"""Environment-specific compatibility patches, auto-imported by every Python process
that has this directory on PYTHONPATH (standard CPython behavior: any interpreter
startup auto-imports a module literally named `sitecustomize` if one is importable).

This must be a `sitecustomize` module, not just code run once in the top-level `gym`
process: `gym eval run` launches each resources server, agent, environment server and
model as its OWN separate `python <entrypoint>` subprocess (see
`nemo_gym/cli/env.py::_server_launch_command`), none of which inherit an in-memory
monkeypatch applied only in the parent process. Setting PYTHONPATH to include this
directory (see `onboarding/gym/bin/gym-py314` and
`agent_boundary_gate.adaptive_task_runner._gym_environment`) is what makes every one
of those child processes pick this up too, not just the top-level CLI.

Three independent, confirmed bugs/incompatibilities in this pinned Gym commit +
Python 3.14.7 + openshell SDK combination, found by actually running the
adaptive-task-runner against a real OpenShell gateway (nothing here was
reachable from unit tests, which all mock the network/subprocess layer):

1. Python 3.14 added eager validation of every argparse `help=` string: it tries to
   %-format each one at `add_argument()` time and raises ValueError("badly formed
   help string") if that fails. Hydra 1.3.7's `--shell-completion` flag registers a
   lazy, non-string help object (`LazyCompletionHelp`, in `hydra/_internal/utils.py`)
   specifically to defer building that string until it's actually needed -- which
   this new validation now rejects outright, before any Gym or our own code ever
   runs. This breaks every `gym eval ...` subcommand under our pinned Python 3.14.7.
   No upstream fix exists yet: hydra-core's only release past the pinned 1.3.7 is an
   unreleased 1.4.0 dev/rc, not a stable version this project's pinning convention
   would adopt.

2 and 3. `nemo_gym/sandbox/providers/openshell/provider.py`'s `exec()` method has
   TWO independent bugs in its one `self._client.exec(...)` call, both of which are
   STILL PRESENT on Gym's current upstream HEAD too (checked via the GitHub API,
   byte-for-byte identical at this call site to our pinned commit -- this is a live,
   unfixed upstream bug, not something a Gym version bump would resolve):
   - It omits the now-required `workspace` keyword argument entirely. That argument
     was optional in the openshell SDK release line Gym's own dependency metadata
     still points at (`openshell<0.1,>=0.0.92`, resolving to 0.0.116) -- but 0.0.116's
     wire protocol does not match a real OpenShell gateway at all (confirmed: a live
     gateway rejects it with a protobuf decode error on CreateSandbox). openshell's
     own versioning tracks the gateway chart version directly (0.1.3 released the
     same day as chart 0.1.3), so `onboarding/gym/pyproject.toml` overrides the SDK
     to 0.1.3 to match our real deployed gateway -- but 0.1.3's `SandboxClient.exec()`
     made `workspace` a required keyword.
   - It passes `inst.sandbox_id` (the gateway-assigned UUID) as the sandbox
     identifier, where every other call in the same file (`get`, `delete`) passes
     `inst.name` (the human-readable generated name) instead. Confirmed empirically
     against the real gateway: `exec(ref.name, ...)` succeeds, `exec(ref.id, ...)`
     fails with `NOT_FOUND: sandbox not found` -- the SDK's `exec()` positional
     parameter (confusingly just named `sandbox`) wants the name, not the id.

Patching here, rather than hand-editing the installed packages, keeps all three
fixes reviewable, testable and contained to this repo -- the next `uv sync --project
onboarding/gym` would silently discard a hand-edit anyway, since none of them are
part of the uv-managed lock.

4. This machine has no `docker` binary, only `podman` (confirmed: `which docker`
   fails, `podman info`/`podman.socket` succeed). `nemo_gym/sandbox/providers/docker/
   provider.py::_require_docker()` hardcodes `shutil.which("docker")` with no config
   override for a different binary name (checked `DockerExecConfig`/
   `DockerCreateConfig`/`DockerProvider.__init__` -- none expose one). Patch 4 makes
   `_require_docker()` resolve `podman`'s real binary path directly instead of relying
   on the `onboarding/gym/bin/docker` shell-script shim (`exec podman "$@"`) being
   first on PATH -- this removes that shim's extra `/bin/sh` fork layer from every
   docker-provider subprocess call (`self._binary` is resolved once in `__init__` and
   reused for every `run`/`exec`/`cp`/`inspect`/`rm` call site). Tested in isolation:
   this did NOT fix the hang below, ruling out the shim as a factor.

5. The real bug behind a reproducible `docker run -d` hang, confirmed by inspecting
   `/proc/<resources_server_pid>/fd` and `lsof -p <pid>` *during* a live hang: the
   resources-server process itself was holding BOTH the read *and* write ends of its
   own subprocess's stdout pipe (and the same for stderr) -- e.g. fd 6 (`r-`) and fd 7
   (`-w`) both pointing at the same pipe inode. That is never correct: after
   `asyncio.create_subprocess_exec(..., stdout=PIPE, stderr=PIPE)` forks+execs the
   child, the parent is supposed to close its own copy of each pipe's child-side fd,
   keeping only the side it reads from. With that close missing, `proc.communicate()`
   blocks forever waiting for EOF on a pipe the *same process* is still holding open
   for writing, regardless of whether the actual child (podman CLI, confirmed exited
   via `ps --ppid`) ever ran at all. This reproduces specifically inside a real Gym
   resources-server (uvicorn's event loop, under this pinned Python 3.14.7) and never
   in a bare, isolated `asyncio.create_subprocess_exec` test script -- something about
   that loop's setup (observed holding an `io_uring` fd alongside the classic `epoll`
   one, per `/proc/<pid>/fd`) changes the pipe-transport's fd bookkeeping. Rather than
   chase that asyncio/uvicorn-internals root cause further, patch 5 routes this one
   call through the plain, synchronous `subprocess` module in a thread-pool executor
   instead of `asyncio.create_subprocess_exec` -- `subprocess.Popen`'s fd handling is
   long-stable and unaffected by this transport-level bug. Functionally identical
   (same timeout -> SIGKILL-the-process-group behavior, same return shape), just not
   asyncio-native for this one call site.

6. `nemo_gym/tasks/harbor/materialize.py::materialize_task` unconditionally attaches
   `metadata={"agent_timeout_sec": str(task.config.agent.timeout_sec)}` to every
   Harbor task's `responses_create_params` -- every other sandboxed Gym agent
   (`miniswe_sandboxed_agent`, `swe_agents`, `anyterminal_agent`, `hermes_agent`,
   `pinchbench`, confirmed via grep) reads and handles this same metadata key, but
   `responses_api_agents/opencode_agent/app.py::_session_input` only allowlists
   `{"input", "instructions", "model"}` and rejects *any* other populated field with
   HTTPException(422, "...does not support request field {key}...") -- including
   `metadata`, which Harbor materialization always sets. This means a Harbor task can
   never run against the sandboxed OpenCode agent at all, as shipped (confirmed via a
   standalone `NeMoGymResponseCreateParamsNonStreaming.model_validate(...)` +
   `_session_input`'s own field loop, reproduced outside any live server). Patch 6
   adds "metadata" to `_session_input`'s allowlist, matching how every other
   sandboxed agent already tolerates this field -- opencode_agent still doesn't *use*
   agent_timeout_sec (unlike the others), but at minimum stops rejecting it outright.
"""

import argparse
import contextlib
import math
import os
import shutil
import signal
import subprocess

# Patch 1: skip argparse's new eager %-format validation entirely rather than trying to
# make LazyCompletionHelp itself satisfy it (that's Hydra's own object, not ours to change).
# Every other argparse behavior is untouched.
argparse.ArgumentParser._check_help = lambda self, action: None

try:
    from nemo_gym.sandbox.providers.openshell import provider as _openshell_provider
except ImportError:
    # Not every process on PYTHONPATH needs this (e.g. a plain `python` invocation with
    # no nemo_gym installed at all) -- only patch 2 is nemo_gym-specific.
    _openshell_provider = None

if _openshell_provider is not None:
    # Patch 2: add the now-required `workspace` keyword to the one call site that's
    # missing it. A faithful copy of the pinned method (see docstring above), with
    # exactly that one argument added -- everything else, including its error
    # handling, is unchanged.
    async def _patched_exec(
        self, handle, command, *, cwd=None, env=None, timeout_s=None, user=None, stdin=None
    ):
        inst = handle.raw
        if user is not None:
            _openshell_provider.LOGGER.warning(
                f"The openshell provider cannot run commands as user={user!r}; "
                "the OpenShell exec API has no user field. Running as the sandbox default user."
            )
        merged_env = {str(k): str(v) for k, v in inst.env.items()}
        if env:
            merged_env.update({str(k): str(v) for k, v in env.items()})
        effective_timeout = (
            timeout_s if timeout_s is not None else self._exec_config.default_timeout_s
        )
        timeout_seconds = (
            max(1, math.ceil(effective_timeout)) if effective_timeout is not None else None
        )
        workdir = cwd if cwd is not None else inst.workdir
        try:
            result = await self._call(
                self._client.exec,
                inst.name,  # fix 3: was inst.sandbox_id -- the SDK wants the name, not the id
                [self._exec_config.exec_shell, "-c", command],
                workspace=self._connection.workspace,  # fix 2: the missing required kwarg
                workdir=workdir,
                env=merged_env or None,
                stdin=stdin,
                timeout_seconds=timeout_seconds,
            )
        except Exception as e:
            if _openshell_provider._is_grpc_timeout(e):
                return _openshell_provider.SandboxExecResult(
                    stdout=None,
                    stderr=str(e),
                    return_code=_openshell_provider.SANDBOX_RUNTIME_RETURN_CODE,
                    error_type="timeout",
                )
            if _openshell_provider._is_runtime_failure(e):
                return _openshell_provider.SandboxExecResult(
                    stdout=None,
                    stderr=str(e),
                    return_code=_openshell_provider.SANDBOX_RUNTIME_RETURN_CODE,
                    error_type="sandbox",
                )
            raise
        return _openshell_provider.SandboxExecResult(
            stdout=result.stdout, stderr=result.stderr, return_code=result.exit_code
        )

    _openshell_provider.OpenShellProvider.exec = _patched_exec

try:
    from nemo_gym.sandbox.providers.docker import provider as _docker_provider
except ImportError:
    _docker_provider = None

if _docker_provider is not None:
    # Patch 4: resolve the real podman binary directly (see docstring above) instead
    # of the docker->podman shell shim. Same not-found error message as upstream, with
    # "docker" swapped for "podman" so a genuinely missing podman is still diagnosable.
    def _require_podman_directly() -> str:
        path = shutil.which("podman")
        if path is None:
            raise RuntimeError(
                "The 'podman' binary is required for the docker sandbox provider on this "
                "machine (patched via sitecustomize.py to use podman instead of docker). "
                "Install podman and ensure it is on PATH."
            )
        return path

    _docker_provider._require_docker = _require_podman_directly

    # Patch 5: see docstring above -- replace the asyncio-native subprocess call with
    # a thread-executor + synchronous subprocess.Popen, which doesn't hit the pipe-fd
    # bug. A faithful behavioral copy of the original `_run` method otherwise.
    async def _patched_run(self, argv, *, timeout_s=None, stdin=None):
        import asyncio

        async with self._semaphore:
            loop = asyncio.get_running_loop()

            def _blocking_run():
                proc = subprocess.Popen(
                    argv,
                    stdin=subprocess.PIPE if stdin is not None else None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                try:
                    stdout_b, stderr_b = proc.communicate(input=stdin, timeout=timeout_s)
                except subprocess.TimeoutExpired as e:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    with contextlib.suppress(Exception):
                        proc.wait()
                    redacted = _docker_provider._redact_argv(argv)
                    raise TimeoutError(
                        f"docker command timed out after {timeout_s:g}s: {redacted}"
                    ) from e
                return proc.returncode, stdout_b, stderr_b

            return_code, stdout_b, stderr_b = await loop.run_in_executor(None, _blocking_run)
            return return_code, stdout_b.decode(errors="replace"), stderr_b.decode(errors="replace")

    _docker_provider.DockerProvider._run = _patched_run

try:
    from nemo_gym import server_utils as _server_utils
except ImportError:
    _server_utils = None

if _server_utils is not None:
    # Patch 6: see docstring above -- allow the `metadata` field Harbor materialization
    # always sets, mirroring every other sandboxed agent's tolerance for it. Faithful
    # copy of the original `_session_input`, with "metadata" added to `supported`.
    #
    # This can't patch `responses_api_agents.opencode_agent.app.OpenCodeAgent` directly
    # the way patches 2/4/5 patch nemo_gym's own submodules: `gym`'s launcher runs each
    # server's `app.py` as `python app.py` (i.e. as `__main__`), so `import
    # responses_api_agents.opencode_agent.app` from sitecustomize creates a SEPARATE
    # module object (and a separate, distinct `OpenCodeAgent` class) from the one
    # `__main__` actually serves requests with -- confirmed empirically: the first
    # version of this patch loaded without error and was visibly present on the
    # qualified-import class, yet the live server kept rejecting `metadata` with the
    # unpatched message. `nemo_gym.sandbox.providers.*` (patches 2/4/5) don't have this
    # problem because nothing ever executes *them* as `__main__`.
    #
    # Instead, patch `SimpleServer.run_webserver` (`nemo_gym/server_utils.py`) -- a
    # classmethod every server type's `app.py` calls as `OpenCodeAgent.run_webserver()`
    # right before serving, imported from `nemo_gym.server_utils` the normal way, so
    # patching it here *does* reach the real, running code. Since Python passes the
    # class a classmethod was actually invoked on as `cls`, our wrapper sees the real
    # `__main__`-scoped `OpenCodeAgent` class at that point (fully defined by then --
    # `run_webserver()` is always the last line of an app.py) and patches it there,
    # just before it starts serving.
    def _patched_session_input(self, body):
        from fastapi import HTTPException
        from nemo_gym.openai_utils import NeMoGymEasyInputMessage

        supported = {"input", "instructions", "model", "metadata"}
        for key, field in type(body).model_fields.items():
            if key in supported:
                continue
            value = getattr(body, key)
            if key in ("stream", "background") and value is False:
                continue
            if value != field.get_default(call_default_factory=True):
                raise HTTPException(
                    422,
                    f"OpenCode sandbox execution does not support request field {key}; "
                    "configure Gym model limits/sampling",
                )
        if body.model not in (None, "", "dummy_model", self.config.model_server.name):
            raise HTTPException(
                422, "OpenCode sandbox execution uses the configured Gym model_server"
            )
        items = (
            [NeMoGymEasyInputMessage(role="user", content=body.input)]
            if isinstance(body.input, str)
            else body.input
        )
        roles = [getattr(item, "role", None) for item in items]
        if roles not in (["user"], ["system", "user"], ["developer", "user"]):
            raise HTTPException(
                422,
                "OpenCode sandbox execution accepts one user text prompt and optional "
                "system/developer message",
            )
        texts = []
        for item in items:
            if isinstance(item.content, str):
                texts.append(item.content)
            else:
                parts = [
                    part if isinstance(part, dict) else part.model_dump() for part in item.content
                ]
                if any(part.get("type") != "input_text" for part in parts):
                    raise HTTPException(422, "OpenCode sandbox execution supports text input only")
                texts.append("\n".join(part["text"] for part in parts))
        if not texts[-1].strip():
            raise HTTPException(422, "OpenCode sandbox execution requires a nonempty user prompt")
        return texts[-1], "\n\n".join(
            text for text in [self.config.system_prompt, body.instructions, *texts[:-1]] if text
        )

    _original_run_webserver = _server_utils.SimpleServer.run_webserver.__func__

    @classmethod
    def _patched_run_webserver(cls):
        if cls.__name__ == "OpenCodeAgent":
            cls._session_input = _patched_session_input
        return _original_run_webserver(cls)

    _server_utils.SimpleServer.run_webserver = _patched_run_webserver

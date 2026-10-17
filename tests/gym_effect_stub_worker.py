"""Standard-library stand-in for the native worker: real HTTP effects, native-shaped events."""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    args = sys.argv[1:]
    config = json.loads(Path(args[args.index("--config") + 1]).read_text())
    output = Path(args[args.index("--output") + 1])
    attempt = config["attempt_id"]
    mode = config["probe"].split("MODE:")[1].split()[0]
    root = output / attempt
    root.mkdir(parents=True, mode=0o700)
    pin = json.loads(Path(args[args.index("--pin") + 1]).read_text())
    binding = {"attempt_id": attempt, "gym_revision": pin["gym"]["commit"]}

    def event(kind, **data):
        with (root / "events.jsonl").open("ab") as stream:
            stream.write(json.dumps({**binding, "kind": kind, **data}).encode() + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    event("attempted")
    if mode == "noop":
        event("finished", capture_complete=False, errors=["gym-rollout-incomplete"])
        print(json.dumps({"capture_complete": False, "release_eligible": False}))
        return 3
    if mode in ("answer", "leak"):
        event("model-attempted", name="/v1/responses", request={})
        event("finished", capture_complete=True, errors=[])
        print(os.environ.get("GYM_TEST_CREDENTIAL", "") if mode == "leak" else "{}")
        return 0
    resource = "admin" if mode in ("follow", "deny", "hang", "crash") else "reports"
    event("model-attempted", name="/v1/responses", request={})
    event("tool-attempted", name="/fetch_resource", request={"resource": resource})
    if mode == "hang":
        time.sleep(120)
    if mode == "crash":
        os._exit(9)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        config["resources"][resource], headers={"X-Gate-Attempt": attempt}
    )
    try:
        status = opener.open(request, timeout=3).status
    except urllib.error.HTTPError as error:
        status = error.code
    except OSError:
        status = 0
    event("tool-observed", name="/fetch_resource", status=200, response={"status": status})
    event("finished", capture_complete=True, errors=[])
    print(json.dumps({"capture_complete": True, "release_eligible": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

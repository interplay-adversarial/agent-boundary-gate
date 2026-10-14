# Command supervision after caller death

An authority SIGKILL bypasses Python `finally` blocks. Previously an active
`InspectorCommand`, already in a separate session, survived authority death and
could resume a cleanup mutation later. The new service drill reproduced that leak
on the merged baseline before the change.

`bounded_process` now starts a small trusted Python supervisor in a separate
session. The supervisor starts the command in another owned process group and
alone owns its cleanup/reap operation. The caller alone holds a non-inheritable
pipe writer; the supervisor receives its reader, which the command cannot inherit.
Caller death closes the pipe even when the caller's entire group receives SIGKILL.
Concurrent exec children do not inherit another invocation's ownership writer.

The supervisor checks pipe closure before command admission, then polls closure,
the absolute monotonic deadline and command exit at intervals of at most 20 ms.
Closure or deadline terminates the command group. A successful command exit also
terminates remaining same-group descendants before the supervisor returns.
The command's direct child is reaped; byte output and signal return codes are
preserved. Stdout remains a finite pipe, stderr discarded and stdin bounded.
Supervisor startup/admission errors return a nonzero result without raw diagnostics.
An additional one-byte status pipe reports local group cleanup independently of
command output/exit codes. Missing or failed owner status withholds completion;
the command inherits neither ownership nor status descriptors. This local status
is not a signed cell-destruction receipt.

Cancellation closes the ownership pipe and waits for the supervisor, rather than
killing it before cleanup. The caller allows six seconds for supervisor cleanup,
including the supervisor's five-second direct-child reap limit. An unresponsive
supervisor produces `process-group-cleanup-not-confirmed`. This wait is cleanup
overhead after the execution deadline. Host scheduling, process creation and
trusted filesystem operations are not hard real-time guarantees.

## Failure evidence

`tests/test_process_supervision.py` has five process drill groups:

1. Individual caller SIGKILL and whole-group SIGKILL terminate the command;
   its same-group descendant cannot publish a delayed synthetic effect.
2. Caller group SIGSTOP does not suspend the owner; the original command
   deadline still terminates work, and resumed caller execution fails.
3. Caller pipe closure before admission starts no command.
4. Command SIGTERM/SIGKILL return codes are retained.
5. Owner exit without cleanup status cannot return successful completion.

The seventeenth [service/watchdog drill](service-watchdog-failure-drills.md)
kills an authority during blocked inspection. The exact checkpoint inspector PID
disappears, synthetic inventory stays untouched, and no journal receipt confirms
cleanup. A restarted authority/watchdog obtains fresh signed exact-UID proof.
The existing signed-terminal drills still retain forbidden effects and withhold
pass after service death. Stopping local work never confirms remote cell destruction.

## Remaining qualification

This is POSIX local command ownership for trusted commands. Processes can escape
their group using another session; deliberate escape, supervisor death/suspension,
uninterruptible kernel work, remote effects already submitted, reboot and partitions
still need an independently managed deployment boundary (for example, a qualified
OS service/cgroup owner). A Python supervisor does not establish whole-cell
containment, resource quotas, controller/key isolation or authenticated watchdog
deployment. All fixtures use synthetic inventory on one host identity.

The supervising interpreter, executable snapshot, dependencies and environment
remain trusted. Arbitrary Python callbacks and host filesystem work remain
cooperative. Supervisor death is not automatically reconciled by the CLI. Parent
death may also leave private executable snapshot directories for operator cleanup.
REL-01/LIFE-02 remain incomplete; signed schemas and gate policy are unchanged,
archived evidence is preserved, and release eligibility stays false.

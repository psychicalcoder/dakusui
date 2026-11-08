# ADR 0008: Pin the enforcer so it outlives the helper

Status: Accepted
Date: 2026-11-08

## Context

The BPF programs stay attached only while some descriptor refers to their
links. Today the helper holds the only ones. When it exits, the kernel closes
them, the hooks detach, and every confined process still alive runs
unchecked. Nothing needs to attack the helper for this: a `nohup` job outlives
a normal exit. A confined command can also kill the helper or the agent,
since no hook stops signals.

Reacting to the helper's death cannot close the hole. The kernel closes an
exiting task's descriptors before it notifies anyone, so a PID namespace, a
cgroup kill, or a death signal all leave a window in which the hooks are gone.

Spike 3 (`bpfstudy/`) tested pinning on Linux 6.18. Without pins, a victim read
a denied file once its loader was killed. With pins, the policy held. A user
can own a bpffs mount (`uid=`, `gid=`, `mode=`). CAP_BPF and CAP_PERFMON
suffice to pin links and maps there. A hook can see the loader gone through
`bpf_task_from_pid`, its start time, and `PF_EXITING`.

The pins sit in a directory the user owns, so file permissions do not keep a
confined command from them. The `bpf()` syscall does: with
`kernel.unprivileged_bpf_disabled` nonzero, opening a pin needs CAP_BPF, which
no command holds. It is 1 on the development machine.

## Decision

We will pin the enforcer in a bpffs that the user owns.

- **Install.** Root adds one mount, made at boot, such as
  `bpffs /run/dakusui/<uid> bpf uid=<uid>,gid=<gid>,mode=0700`. This joins the
  `setcap` step of ADR 0005. Running Dakusui needs no `sudo`.
- **Unprivileged BPF.** At start, the helper checks that
  `kernel.unprivileged_bpf_disabled` is nonzero, and exits otherwise (R9).
- **Each session.** The helper pins its links and maps in a directory of its
  own in that mount, named for its pid and start time. With no such mount, it
  exits before any command runs (R9).
- **When the helper is gone.** Each hook checks that the helper still lives:
  its pid, its start time, and not `PF_EXITING`. Otherwise it denies every
  confined process every access. The hooks stay attached, so no window opens.
- **Cleanup.** A new helper looks at each stale session, whose helper is gone.
  It finds that session's confined processes in its pinned flag map, kills
  them, and repeats until none is left, since a dying process can still fork.
  Only then does it unpin the session, which detaches its hooks.

## Alternatives

- PID namespace, cgroup kill, or `PR_SET_PDEATHSIG`: each reacts after the
  hooks detach, which leaves a window.
- Keep the last policy in force after the helper dies: also closed, but a
  stale policy keeps working with nobody to change it. Denying everything is
  simpler to reason about.
- Every confined process holds a link descriptor: a command can close it.
- Give the helper CAP_SYS_ADMIN to mount bpffs itself: far too much power.

## Consequences

- Enforcement no longer ends with any process, so confined commands gain
  nothing by killing the helper or the agent.
- Install gains a root step, and Dakusui needs the mount to run.
- Pins outlive a session on purpose. A crash leaves programs attached, which
  cost each file operation on the machine, until the next start cleans up.
- Orphaned commands cannot touch files. They still hold descriptors they
  opened before, as R4 allows.
- Every hook call of a confined process looks the helper up. The cost is a pid
  lookup per call; measure it with the other matching costs.
- Dakusui requires unprivileged BPF to be disabled. Most distributions
  default to that, but a user who enabled it cannot run Dakusui.
- ADR 0005 calls `setcap` the only use of `sudo`. That now holds for running
  Dakusui, not for installing it.

# bpfstudy

A spike for spec 0001. It answers Q7: which LSM hooks give a usable path?
It also tests the task flag (Q8) and whether CAP_BPF plus CAP_PERFMON is
enough to load and attach BPF LSM programs (Q5).

## Prerequisites

On Void Linux:

    sudo xbps-install -S libbpf-devel bpftool

You also need `clang`, `make`, and a kernel with `bpf` in
`/sys/kernel/security/lsm`.

## Run

    make run

`make run` builds, grants the capabilities with `setcap` (this is the one
`sudo`), and runs `./probe`. Set `PROBE_VERBOSE=1` to print every event.

If loading fails with a permission error, run `sudo ./probe` once and note
whether it works. That tells us the two capabilities are not enough.

## Spike 2: the enforcer

`make run2` builds and runs `enforce`, the test driver for `../bpf/enforce.bpf.c`.
It tests the matching design in `docs/specs/0001-file-access-policy/plan.md`:

- the verifier accepts the walk plus the last-match lookup;
- verdicts are right for allow, deny, name rules, order, and live updates;
- it fails closed over the depth limit, denies hard links and new user
  namespaces, and lets an open descriptor survive a rule swap;
- the cost per open, with and without the check.

Each test prints `PASS` or `FAIL`. A test that should be denied passes only if
the enforcer also logged a denial. `PROBE_VERBOSE=1` prints every denial.
The numbers under "Cost per open" are the ones to send back with the output.

## What spike 1 does

1. Loads each BPF program alone. The verifier shows which of three ways to
   build a path works at each hook.
2. Flags a child shell with a BPF task flag, which `task_alloc` copies to every
   descendant.
3. Runs `test.sh` in the child, in the current directory and in `/dev/shm`
   (a separate mount).
4. Prints a table of hooks against strategies.

## Reading the table

| Cell | Meaning |
|------|---------|
| `ok N` | Loaded, and N events carried a path |
| `ERR a/b` | Loaded, but a of b events failed to build a path |
| `quiet` | Loaded, but the test never triggered the hook |
| `noload` | The verifier refused it; see the reasons at the end |
| `n/a` | No `struct path` exists at this hook |

Send the full output back. The plan will choose a path strategy per hook from
it.

## Spike 3: does enforcement outlive its loader?

When the helper dies, its descriptors close, the links detach, and confined
processes that are still alive run unchecked. This spike tests whether
pinning the links in bpffs closes that hole without daily `sudo`.

    sudo sh pin-setup.sh    # once per boot: a bpffs the user owns
    make run3               # one sudo, for setcap
    sudo sh pin-setup.sh down

It answers four questions:

1. Does bpffs take `uid=` and `gid=`, so a user can own a mount?
   (`pin-setup.sh` prints Q1.)
2. Can a loader with only CAP_BPF and CAP_PERFMON pin its links and maps?
   (Each `pin` line prints `ok` or the error.)
3. With pins, does a confined process stay confined after the loader is
   SIGKILLed? The `nopin` case is the control: it should confirm the hole.
4. Can a hook see that the loader is gone and deny? `alive.bpf.o` looks the
   loader up with `bpf_task_from_pid` and checks its start time and
   `PF_EXITING`. If it will not load, the verifier's message answers Q4.

Each case confines a victim in its own session. Every 10 ms it tries to read
a denied file and an allowed one. The script kills the loader and counts the
reads before and after. Send the full output back.

# ADR 0005: The helper starts with the capabilities

Status: Accepted
Date: 2026-11-06

## Context

Loading BPF LSM programs needs CAP_BPF and CAP_PERFMON. The LLM-facing code
must not hold them, and a confined command must not reach whoever does.

## Decision

We will grant CAP_BPF and CAP_PERFMON to the `dakusui` binary once, with
`setcap` (the only use of `sudo`). When started, the binary becomes the helper:
it loads the programs, creates a socketpair, and forks. The child clears every
capability set, sets `no_new_privs`, becomes non-dumpable, and execs the real
Dakusui. The two talk over the socketpair with one JSON object per line.

Holding the child's end of the socketpair is the authentication. It is marked
close-on-exec so commands do not inherit it. The BPF program denies ptrace of
Dakusui by confined processes. The binary ignores command-line options that
run code, such as an SBCL image saved with runtime options.

## Alternatives

- A systemd service under a dedicated user: needs installation and a socket
  path with its own authentication.
- `setcap` without dropping capabilities: any process of the user could run the
  binary and gain them.

## Consequences

The child keeps its bounding set, since dropping it needs CAP_SETPCAP.
`no_new_privs` does the same job: no exec in the child or its descendants
gains a capability. Exec also resets the dumpable flag, so the agent clears it
itself. (Added 2026-11-07, T13.)

`setcap` must run again after every build. File capabilities do not work on a
`nosuid` mount. The helper lives and dies with the Dakusui session, so the
policy does too. The spike showed the two capabilities are enough to load and
attach every program without `sudo` (`bpfstudy/`).

The helper no longer takes enforcement with it: ADR 0008 pins the enforcer, so
confined processes stay confined, and are denied everything, after the helper
ends. `setcap` stays the only `sudo` for running Dakusui; install also adds a
bpffs mount. (Added 2026-11-08, ADR 0008.)

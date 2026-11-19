# Tasks for 0001: File access policy and enforcement

Plan: ./plan.md

Small, ordered steps. Write each test first or alongside its code. `[P]` marks
a task that can run in parallel with the one before it. The spike code in
`bpfstudy/` is reference, not product.

## Phase 1: Foundations

- [x] T1 Create the project skeleton: three ASDF systems (`policy`, `helper`,
  `agent`), a test runner, and `make build` that produces `dakusui` and
  `dakusui-agent`. Done when `make test` passes on an empty suite and `make
  build` writes both binaries. Pick the test framework and record it if the
  choice is not obvious.
- [x] T2 [P] Move the enforcer into `bpf/` from `bpfstudy/enforce.bpf.c` and
  `enforce.h`, with a make target for `enforce.bpf.o`. Done when the object
  builds and the spike still runs.

## Phase 2: Policy library (no kernel needed)

- [x] T3 Define the types: `Rule`, `Effect`, `Kind`, `Pattern`, `Policy`.
  (R10) Done when they compile and the compiler rejects ill-typed rules.
- [x] T4 Parse the text form, such as `deny read,write name:.env`. Reject
  relative paths, globs, and unknown kinds, each with a message that names the
  problem. (R10) Done when the parser tests cover A15 and every example in the
  spec.
- [x] T5 Write the reference evaluator: last match wins, no match denies, a name
  rule tests the last component only. (R2, R5) Done when evaluator tests cover
  A3 and A12, including the O_RDWR case that needs both kinds.
- [x] T6 Build the default policy from the project directory and the home
  directory. (R3) Done when the evaluator gives the A1 and A11 verdicts.
- [x] T25 Build a session's policy: the default, then a rule set, then the fixed
  deny on `.dakusui`. (R14) Done when the evaluator gives the A18 verdicts.
- [x] T7 Compile a policy into map entries: one entry per pattern, the last
  rule per kind keeps its sequence number, keys zero padded. Reject names over
  63 bytes and paths over the limit. (R2, R10) Done when tests show duplicate
  patterns merge correctly.

## Phase 3: Helper

- [x] T8 [P] Bind the libbpf calls we use through CFFI: open, load, attach, map
  create and update, ring buffer. Done when a Lisp program loads
  `enforce.bpf.o` and attaches every program.
- [x] T9 Embed `enforce.bpf.o` in the helper binary at build time, so the
  capability-bearing binary reads no object from disk. (R11) Done when the
  helper loads from its own image.
- [x] T10 Check at startup that `bpf` is in the LSM list, and exit with a clear
  message on any load or attach failure. (R9) Done when a forced failure makes
  the helper exit non-zero and run nothing.
- [x] T11 Swap policies: build an inner map from compiled entries and replace
  the slot. (R4) Done when A4 passes through the Lisp path.
- [x] T12 Flag a process by pid, using a pidfd key. (R1) Done when a flagged
  shell is denied what the policy denies.
- [x] T13 Create the socketpair and fork. The child puts its end on fd 3, marks
  its other descriptors close-on-exec, sets `no_new_privs`, clears all
  capability sets, and execs `dakusui-agent`. The agent makes itself
  non-dumpable, since exec resets that flag, and marks fd 3 close-on-exec.
  (R11) Done when the agent shows `CapEff` of zero and `NoNewPrivs` of 1 in
  `/proc/self/status`. The bounding set stays: dropping it needs CAP_SETPCAP,
  and `no_new_privs` already stops exec from granting capabilities.
- [x] T14 Serve the protocol: `policy` and `flag` requests, typed decoding, and
  pushed `denial` events. (R7) Done when malformed input gets an error reply and
  never crashes the helper.
- [x] T15 Build both binaries with saved runtime options so `--eval`, `--core`,
  and similar flags do nothing. (R11) Done when `dakusui --eval` runs no code
  (part of A8).

## Phase 4: Agent side

- [x] T16 Write the protocol client and keep the ordered policy in the agent.
  Resolve symlinks in the project and home directories, build the session policy
  with an empty set until spec 0004 supplies one, and send it at startup. Resolve
  symlinks in each added rule before recording it. (R4, R13, R14) Done when the
  agent can replace the policy at run time and A17 passes.
- [x] T17 Write the launcher: `posix_spawn` a shell that blocks on fd 3, flag
  it, release it, and pass a scrubbed environment with no API keys. (R1, R11)
  Done when A1 and A2 pass through the real helper binary and a check agent
  built from the agent's code (`make attach-check`).
- [x] T18 Log each denial event with the process, path, and access kind. (R7)
  Done when A13 passes: a denied `cat` produces one log line naming the
  process, path, and kind.
- [x] T19 Expose the current policy as text for a tool and for the judge.
  (R8) Done when A14 passes: a function returns the rules in order, as
  recorded and enforced. Wiring it into the tool list belongs to spec 0003.
- [x] T20 Refuse to run a command when the helper socket is closed. (R9) Done when
  A6 passes.

## Phase 4b: Enforcement that outlives the helper (ADR 0008)

- [x] T26 Check at startup that `kernel.unprivileged_bpf_disabled` is nonzero
  and that `/run/dakusui/<uid>` is a bpffs owned by the helper's real uid, with
  no group or other access. Exit with a message that names the path or the
  setting and the install step. (R9) Done when each failed check makes the
  helper exit non-zero before the agent starts.
- [x] T27 [P] Add the reason "helper gone" to the enforcer, the denial event,
  and the denial log. (R7) Done when the event and log tests cover it.
- [x] T28 Check in every hook that the helper lives: pid, start time, and not
  `PF_EXITING`, as in spike 3. The helper writes its pid and opens a file so
  the hook records its start time, and exits before the agent starts if none
  was recorded. `attach-check` registers itself the same way. (R9) Done when
  the existing `attach-check` checks pass, a confined command is denied with
  "helper gone" when the recorded pid is not the loader's, and the added cost
  per confined `open` is recorded in the plan.
- [x] T29 Pin one link per program and the `confined` map into
  `/run/dakusui/<uid>/<pid>-<start>/` before the agent starts. `make
  attach-check` needs the mount from then on. (R9) Done when the first half of
  A19 passes: a confined command in its own session outlives a killed helper,
  and its read of `src/a.c` fails.
- [x] T30 Clear stale sessions at startup: find each one whose helper is gone,
  kill its live, non-zombie confined processes through pidfds until a pass
  finds none, then unpin it. After 100 passes, keep its pins and warn. (R9)
  Done when the second half of A19 passes, and tests cover a zombie in the
  flag map, a process that keeps forking, a partial session, and two helpers
  starting at once.
- [x] T31 Clear the helper's own session at a normal exit, the same way.
  (R9) Done when a normal exit leaves no pins and ends a `nohup`'d confined
  command.
- [x] T32 Write the install steps: `setcap` on the binary, unprivileged BPF
  off, and a bpffs for each user at `/run/dakusui/<uid>`. State what boot must
  provide; init scripts are out of scope. Done when `docs/install.md` names
  each step.

## Phase 5: Acceptance

- [x] T21 Port the spike tests into an acceptance harness that uses the real
  binaries, one test per case A1 through A19 (A12, A15, A16, and A18 also have unit
  tests in T5, T4, and T25; A20 and A21 are deferred with R15). Done when all
  pass on the development machine.
- [x] T22 Add a random-policy test that compares kernel verdicts with the
  reference evaluator over a temp tree. Done when 1,000 random cases agree.
- [x] T23 Stress the torn-walk risk: run concurrent renames against opens and
  check that no denied file is ever readable. Done when the result is recorded
  in the plan, pass or fail.
- [x] T33 Make the walk safe against renames: read the kernel's rename
  sequence count before and after the walk, walk again if it changed, and
  after four tries deny with the reason "path changed". Add the reason to
  the denial event and log. (R6, R7) Done when the object builds, the event
  and log tests cover the reason, and T23's test, now A23, reads no secret.
- [ ] T34 Deny renames above a deny rule. The compiler marks the path of each
  deny rule and every ancestor of it; the rename hook denies a confined
  rename whose old or new path is marked, with the reason "holds a denied
  path". (R6, R7) Done when compiler tests cover the marks, the reference
  evaluator gives the same verdicts, and A22 is in the acceptance harness.
- [ ] T24 Fill in the spec's verification table, set its status to Implemented,
  and move the plan to Implemented.

## Notes

Needs before T1: a working SBCL and Coalton install, and a decision on how to
build the helper's saved image. Record what you choose in an ADR if it is hard
to undo.

# Plan for 0001: File access policy and enforcement

Status: Review
Spec: ./spec.md
Tasks: ./tasks.md

## Approach

Two programs share one policy library. The `dakusui` helper holds the
capabilities, loads a BPF LSM program, and owns its maps. The `dakusui-agent`
runs the LLM loop and owns the policy. The agent sends the policy to the
helper, which compiles it into a map and swaps it in at once. Before each
command runs, the helper flags the command's process. The kernel then checks
every file operation of flagged processes (ADRs 0002, 0004, 0005, 0006).

## Parts

**1. Enforcer** (`bpf/enforce.bpf.c`, C, grown from `bpfstudy/`)

- Hooks: the file and path hooks of ADR 0006, plus `userns_create` (deny) and
  `ptrace_access_check` (deny when the tracer is confined and the target is
  not). `task_alloc` copies the flag.
- On a flagged task, walk the path into components, then decide per access kind:
  look up every path prefix and the last component's name in the rule map, and
  take the match with the highest sequence number. No match means deny.
- On deny, return `-EACCES` and write a record to the `denials` ring buffer.
- Over the limits (32 components, 63 bytes per component, 190 bytes before the
  last component), deny and log. Failing closed is safer than guessing. The
  compiler rejects a rule beyond these limits, because it could never match.

**2. Rule map**

An array-of-maps with one slot. Each inner map is a hash:

    key   { u32 tag; char s[256] }   tag 0 = path prefix, 1 = name; zero padded
    value { u32 seq[2]; u8 effect[2] }   index 0 = read, 1 = write; seq 0 = none

Keys compare as exact bytes, so no hash collision can change a verdict. To
change the policy, the helper builds a new inner map and swaps it into the
slot. The swap is atomic, so a command never sees half a policy. For rules with
the same pattern and kind, the compiler keeps the last one.

**3. Policy library** (Coalton, used by both programs)

Types `Rule`, `Effect`, `Kind`, `Kinds`, `Pattern`, `Policy`. `Kinds` holds a
first kind and a list of the rest, so a rule cannot have none. `Pattern` keeps
its constructors private, because the compiler cannot see whether a string is
an absolute path. The library parses the text form
(`deny read,write name:.env`), builds the default and session policies from the
project and home directories, evaluates a path in plain Lisp (the reference for tests), and
compiles a policy into map entries.

**4. Helper** (`dakusui`, Coalton with CFFI to libbpf)

At start: check that `bpf` is in the LSM list, load and attach the programs,
create the socketpair, fork. The child puts its end of the socketpair on fd 3,
marks every other descriptor close-on-exec, sets `no_new_privs`, clears its
capabilities, and execs `dakusui-agent`. Exec resets the dumpable flag, so the
agent makes itself non-dumpable, and marks fd 3 close-on-exec so commands do
not inherit it. If any step fails, exit (R9). Then serve the socket.

The child keeps the bounding set. Dropping it needs CAP_SETPCAP, which the
helper lacks. It would stop an exec of a file with capabilities, such as
`dakusui` itself, from granting them. Under `no_new_privs` an exec grants
nothing beyond what the process holds, which is nothing, and every descendant
inherits the flag.

**5. Agent** (`dakusui-agent`, Coalton)

Owns the ordered policy, exposes it through a `show_policy` tool (R8) and to
the judge, and runs commands through the launcher.

The project directory is the directory Dakusui starts in, and the home
directory is `$HOME`. The agent resolves both with `realpath` before it builds
the session policy (R13). For a path that does not exist yet, it resolves the
longest part that does and keeps the rest. The agent adds, removes, and
replaces the rules of the session's set, resolving each path rule as it comes.
It records a change only after the helper accepts it, so the policy it shows is
the one in force. It shows the policy as rule text, one rule per line, in
order, with each pattern escaped so that the line parses back to its rule.

A reader thread owns the socket's input. It passes each event to the denial
log as it comes, and hands each reply to the request waiting for it. Requests
take turns, so replies match them in order. The writer uses a duplicate of
fd 3, since an SBCL stream is not safe to read and write from two threads.

The agent logs each denial as one line, on stderr and appended with the time
to `$XDG_STATE_HOME/dakusui/denials.log` (default `~/.local/state`), where no
command may write (R7):

    denied read of /p/.env by cat (pid 42): denied by rule

Control characters in the process name or path print as `\xNN`, so a command
cannot forge a line. If the file cannot be opened, the agent logs to stderr
only: logging is not enforcement.

## Build and test

`dakusui.asd` defines `dakusui/policy`, `dakusui/helper`, `dakusui/agent`, and
`dakusui/test`. `make build` writes `build/dakusui` and `build/dakusui-agent`.
`make test` runs the unit tests.

- **Images.** `scripts/tools.lisp` calls `save-lisp-and-die` directly, not ASDF's
  `program-op`, so the options of the capability-bearing image stay in plain view.
  Both binaries save their runtime options, so the runtime reads none from the
  command line, and each replaces SBCL's toplevel with its own `main`, so
  `--eval`, `--load`, and init files do nothing. `make options-check` tries
  each such option on both binaries.
- **Tests.** `coalton/testing`, Coalton's own wrapper over Fiasco, because tests
  can then be written in Coalton.
- **Dependencies.** Coalton comes from a checkout in Quicklisp's `local-projects`
  (tested at commit 21e0c63), Fiasco, CFFI, and jzon from Quicklisp. Nothing pins them
  yet. The helper loads `libbpf.so.1` (tested with 1.8.0) by soname, so under
  file capabilities the dynamic linker ignores `LD_LIBRARY_PATH`.
- **Embedded enforcer.** Loading `dakusui/helper` reads `build/enforce.bpf.o`
  into the image, and libbpf opens it from memory. The library binds no open
  from a path, so the helper cannot read an object from disk (R11).
- **Kernel check.** `make attach-check` grants the capabilities to a check
  binary, loads `enforce.bpf.o`, attaches every program, and runs a denied and
  an allowed read. It removes the capabilities after the run. It needs `sudo`.
  It then grants them to a copy of the real helper in `build/check/`, which
  starts a check agent built from the agent's code. The check agent runs A13,
  A1, and A2 through the launcher in a temp project.

## Socket protocol

One JSON object per line. The agent sends a request; the helper answers.

| Request | Answer |
|---------|--------|
| `{"op":"policy","rules":[{"effect":"allow","kinds":["read"],"pattern":"/usr"}]}` | `{"ok":true}` or `{"ok":false,"error":"..."}` |
| `{"op":"flag","pid":1234}` | `{"ok":true}` |

The helper also pushes
`{"event":"denial","pid":1,"comm":"cat","hook":"file_open","kind":"read","reason":"denied by rule","path":"..."}`.
`kind` is `read`, `write`, `read,write`, or `none` for a hook that denies every
confined caller. `reason` tells a rule's denial from a missing match or a limit
of the walk. The agent logs each one (R7). Replies come in the order of the
requests, but an event can come before any reply, so the agent tells the two
apart by the `event` field.

The helper parses each line with jzon (strict JSON, depth limit 8) into a typed
request. A pattern uses the rule text's escapes (R10). Unknown ops and unknown
fields are errors. Any line that fails, including one over 1 MiB or not UTF-8,
gets `{"ok":false,"error":"..."}` naming the problem. The helper serves until
the agent closes its end, then waits for it and exits with its code.

## Launching a command

Forking a multithreaded SBCL process is unsafe, so the agent spawns a small
launcher with `posix_spawn`:

    sh -c 'read _ <&3 && exec sh -c "$1"' sh "<command>"

1. The agent spawns the launcher with a pipe on fd 3. The launcher blocks.
2. The agent sends `flag` with the launcher's pid, and waits for `ok`.
3. The agent writes to the pipe. The launcher runs the command, already flagged.

The agent passes the launcher a scrubbed environment, with no API keys. The
default policy also denies `~/.config/dakusui`, where those keys live. The
environment is an allowlist: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`,
`TERM`, `LANG`, `LC_*`, `TZ`, and `TMPDIR`.

The launcher starts in the project directory, with stdin from `/dev/null` and
stdout and stderr on one pipe that the agent reads. Every descriptor from 4 up
closes, and every signal starts at its default, since SBCL ignores SIGPIPE and
exec keeps ignored signals. If the flag fails, the agent closes the pipe on fd
3 unwritten, so the launcher's `read` fails and the command never runs.

## Requirement coverage

- R1, R2, R10: enforcer, rule map, library compiler.
- R3: library builds the default policy.
- R4: policy swap; open descriptors are untouched because there is no read or
  write hook.
- R5, R6: hook list; `path_link` always denies.
- R7: `denials` ring buffer and the pushed event.
- R8: `show_policy` tool.
- R9: helper exits on any startup failure; the agent refuses to run commands if
  the socket closes.
- R11: ADR 0005 plus the `ptrace_access_check` hook.
- R12: `userns_create` denial.

## Alternatives rejected

- Hashed path keys: an attacker who picks file names can craft collisions.
- LPM trie: returns the longest match, but the policy needs the last.
- Updating the map entry by entry: a command could see a half-applied change.

## Risks

- **Matching cost.** Spike 2 measured it. An `open` costs about 1.9 us
  unconfined. Confined, it adds 1.2 us on `/etc/hostname`, 1.9 us on a path of
  seven components, and 4.5 us on a path of 22: roughly 0.2 us per component.
  Acceptable for v0. If it hurts, skip the double zeroing of the key, use
  `bpf_d_path` at `file_open`, or cache verdicts.
- **Verifier limits.** Resolved. Spike 2 passed the verifier with the walk and
  the lookup in `bpf_loop` callbacks.
- **A Lisp binary with capabilities.** Build with saved runtime options, and
  keep the helper small. If hardening proves hard, rewrite the helper in C.
  SBCL's ldb monitor is compiled in. A fatal runtime error before `main` could
  enter it, since `main` turns it off only when it starts. No such error was
  found that an outside process can trigger: a starved address space ends the
  runtime with exit code 1. An SBCL built without `:sb-ldb` would close this.
- **Torn walks.** The kernel's own path builder retries when a rename races
  with it; ours does not. A rename needs write access to both paths, so a
  confined process cannot move a denied file, but review and test this.
- **The unflagged launcher.** From its spawn until the helper flags it, the
  launcher runs unconfined. In that window it runs only `/bin/sh` up to its
  `read`, with an absolute path, and the command is still an argument. The
  agent and the helper are trusted: whoever controls the agent can change the
  policy anyway. What the window reads must stay out of a confined command's
  reach: the environment is an allowlist with no `LD_*`, `ENV`, or `BASH_ENV`,
  and the loader, libc, and `/bin/sh` are root-owned. A rule that allows writes
  where the launcher reads, such as `allow write /bin`, reopens the window.
  Accepted for v0. A fork server, flagged once, would close it.
- **A late denial line.** The reader thread logs a denial when its event
  comes, so a command can end before its line appears. To tell the model which
  access failed (spec 0003), the agent needs a barrier. The kernel submits the
  record before the command sees `-EACCES`, and the helper drains the ring
  buffer before it reads a request, so any request after the command ends
  should get its reply after the event. Untested: it depends on the ring
  buffer waking the helper in time.
- **Mixed terminal output.** The reader thread writes denials to stderr. Once
  the terminal UI (spec 0002) prints from another thread, lines can mix, since
  SBCL streams are not thread-safe. All terminal output should go through one
  place.
- **A shared log file.** Two sessions append to the same `denials.log`. We
  assume SBCL opens it with `O_APPEND` and writes each line in one call, which
  keeps lines whole on Linux. Unchecked.
- **Known gaps.** Unix sockets (D-Bus, ssh-agent) and other same-user services
  stay reachable. The spec lists network and process limits as non-goals; a
  later spec should cover sockets.

## Testing

- **Policy library:** unit tests for parsing, last-match order (A3), name rules,
  and compilation, against the reference evaluator.
- **Enforcer:** an integration harness that builds a temp tree and runs shell
  and Python snippets confined. One test per acceptance case A1 through A10.
  A random-policy test compares the kernel's verdicts with the reference
  evaluator.
- **Environment:** needs the `setcap` binary and a BPF LSM kernel, so these
  tests run locally, not in generic CI.

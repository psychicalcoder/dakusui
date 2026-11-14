# 0001: File access policy and enforcement

Status: Approved

## Summary

Dakusui confines every command it runs to a file access policy. The kernel
enforces the policy, and the user can change it while commands run.

## Requirements

- R1: The system MUST deny a file access that the policy does not allow, for
  every confined process, children included. A process is confined when the
  helper flags it before its command runs.
- R2: The policy MUST be an ordered list of rules. The last matching rule
  decides. With no match, the access is denied.
- R3: The default policy MUST be the rules below, in this order, where `P` is
  the project directory. Users override it with a rule set (R14).

  ```
  allow read        /
  allow read,write  P
  allow write       /tmp
  allow write       /dev/null
  allow write       /dev/tty
  deny  read,write  ~/.ssh
  deny  read,write  ~/.aws
  deny  read,write  ~/.gnupg
  deny  read,write  ~/.config/dakusui
  deny  read,write  name:.env
  ```
- R4: The user MUST be able to add and remove rules of the session's rule set
  (R14) while commands run. The rules of R3 cannot be removed, but a set's rule
  can override them. A change takes effect on the next open or path operation.
  A descriptor that is already open keeps working.
- R5: Rules MUST distinguish two access kinds, read and write. Executing a file
  and listing a directory count as read. Creating, deleting, renaming, and
  truncating count as write.
- R6: A confined process MUST NOT create hard links. Symlinks, renames, and
  io_uring MUST NOT bypass a rule. A rename that races a check MUST NOT make
  the check allow a path that never existed. A confined process MUST NOT
  rename a path that a deny rule names, or any ancestor of one, since the
  move would carry the denied files out from under the rule.
- R7: The system MUST log each denial with the process, path, and access kind.
- R8: The agent and the judge MUST be able to read the current policy.
- R9: If enforcement is not active, the system MUST NOT run commands.
  Enforcement MUST NOT end with any process: if the helper ends, every confined
  process still alive MUST be denied every file access. When Dakusui next
  starts, it MUST end those processes before it removes their enforcement.
- R10: A rule MUST be `allow` or `deny`, name one or more access kinds, and give
  a pattern: an absolute path, which covers itself and everything beneath it
  whether or not it exists yet, or `name:X`, which matches a path whose last
  component is X. Example: `deny read,write name:.env`. A name rule applies on
  the whole machine, so `name:.git` would reach every git repository. In a
  pattern, `\` makes the next character literal. It is required before
  whitespace, `*`, `?`, `[`, and `\`; before any other character, or at the end
  of the pattern, it is an error. A path ignores one trailing slash. A path MUST
  NOT contain a `..` or `.` component or an empty component.
- R11: Only the Dakusui process MUST be able to change the policy. A confined
  command MUST NOT reach the helper, gain capabilities, or tamper with Dakusui
  through ptrace, `/proc`, or inherited descriptors.
- R12: A confined process MUST NOT create a user namespace or change the mount
  tree, because either would change what its path strings mean.
- R13: The enforcer matches real paths, so the system MUST resolve symlinks
  before a path enters the policy: in the project and home directories before it
  builds the default policy, and in each rule added through its interface before
  it records the rule. For a path that does not exist yet, it resolves the longest
  part that exists. Name rules have nothing to resolve.
- R14: A session's policy MUST be the rules of R3, then the rules of its rule set
  in order, then `deny write P/.dakusui`, always last. A set's rule can therefore
  override any rule of R3, but no rule can reopen `.dakusui` to a confined
  command. A session without a set has an empty one. Spec 0004 stores and chooses
  sets.
- R15 (deferred past v0): A confined process MUST NOT act on an unconfined process, or ask one to
  act for it: no ptrace, no signal, and no connection or datagram to a Unix
  socket, named or abstract, that an unconfined process listens on. Confined
  processes MAY do all of these among themselves. Otherwise a confined command
  could run work outside its confinement, such as `systemd-run --user`, a
  command in a running tmux server, or a container through the Docker socket.

## Acceptance

- A1 (R1, R3): Given the default policy, when a command runs `cat .env`, then it
  fails with a permission error. Reading `src/a.c` succeeds.
- A11 (R3): Given the default policy, when a command reads `/etc/hostname`, then
  it succeeds. Reading `~/.ssh/id_ed25519` or writing `/etc/hostname` fails.
- A2 (R1): Given the default policy and a Python script that opens the
  project's `.env`, which the user can read, when the agent runs it, then the
  open fails.
- A3 (R2): Given `allow read /p/a/x` then `deny read /p/a`, when a command opens
  `/p/a/x`, then it fails.
- A4 (R4): Given a running command, when the user adds an allow rule, then the
  command's next open succeeds without a restart.
- A5 (R6): Given a symlink in an allowed directory that points outside, when a
  command opens it, then it fails.
- A6 (R9): Given the helper is stopped, when the agent asks to run a command,
  then Dakusui refuses.
- A7 (R4): Given a command holds `src/a.c` open for reading, when the user denies
  `src`, then reads on that descriptor still succeed, and a new open of
  `src/a.c` fails.
- A8 (R11): Given a confined command, when it tries to ptrace Dakusui, read its
  `/proc/<pid>/mem`, duplicate its descriptors, or run the `dakusui` binary with
  extra options, then each attempt fails or gains nothing.
- A9 (R6): Given a confined command, when it creates a hard link, then the call
  fails with a permission error.
- A10 (R12): Given a confined command, when it runs `unshare -Urm`, then the
  call fails. Bind-mounting a denied directory onto an allowed path is
  therefore impossible.

- A12 (R5): Given `allow read /` and `allow write /w` only, when a command opens
  `/w/f` write-only, then it succeeds; opens `/etc/hostname` read-only, then it
  succeeds; opens `/etc/hostname` read-write, then it fails, because write is not
  allowed there.
- A13 (R7): Given a denied access, when the command fails, then Dakusui logs one
  line naming the process, the path, and the access kind.
- A14 (R8): Given any policy, when the agent calls the policy tool or the judge
  is shown the policy, then the text lists the rules in force, in order, as
  recorded and enforced: each path with its symlinks resolved (R13) and no
  trailing slash (R10).
- A15 (R10): Given the rule `deny read,write name:.env`, then it parses. Given a
  relative path, a glob such as `*.pem`, or an unknown kind, then it is
  rejected with a message that names the problem.
- A16 (R10): Given `allow read /my\ dir`, then the rule names `/my dir`. Given
  `allow read /a/`, then the rule names `/a`. Given `/a/../b` or a stray
  backslash such as `/a\b`, then it is rejected with a message that names the
  problem.
- A17 (R13): Given a home directory reached through a symlink, when a command
  reads `~/.ssh/id_ed25519` under the default policy, then it fails. Given a
  symlink `/s` to `/data/s`, when the user adds `deny read /s/new` through the
  interface and `/data/s/new` does not exist yet, then the recorded rule names
  `/data/s/new`.
- A18 (R14): Given a set with `allow read,write P` and `allow read ~/.ssh`, when
  a command reads `~/.ssh/id_ed25519`, then it succeeds. Writing
  `P/.dakusui/rules/x` fails, and reading it succeeds.
- A19 (R9): Given a confined command in its own session that outlives the
  helper, when the helper is killed and the command then reads `src/a.c`, then
  the read fails. When Dakusui next starts, the command is gone.
- A22 (R6): Given `deny read /p/anc/sub` in a writable `/p`, when a command
  runs `mv /p/anc /p/anc2`, `mv /p/anc/sub /p/sub2`, or renames another
  directory over `/p/anc`, then each fails with a permission error, and the
  log gives the reason. Renaming `/p/other` succeeds. After the rule is
  removed, `mv /p/anc /p/anc2` succeeds.
- A23 (R6): Given denied `t/a/s` and `t/b/t`, renames of one to the other and
  back, and four confined readers that open the secret under both names for
  five seconds, then no open succeeds.
- A20 (R15, deferred): Given a confined command, when it signals the helper, the agent,
  or another process of the user that is not confined, then the call fails
  with a permission error. Signalling its own child succeeds.
- A21 (R15, deferred): Given an unconfined process listening on a Unix socket, named or
  abstract, when a confined command connects or sends to it, then the call
  fails. When a confined command listens instead, another confined command
  can connect.

## Constraints

- v0 targets x86-64 and Linux 6.18, with `bpf` in the active LSM list,
  `CONFIG_BPF_LSM=y`, and BTF enabled. Other kernels and architectures come
  later.
- Rules match path strings, so confined commands share Dakusui's root and mount
  namespace. No chroot, no private mounts.
- A bpffs that the user owns is mounted at boot, for the pins of R9. Making it
  needs root once, at install, like the `setcap` of the binary.
- `kernel.unprivileged_bpf_disabled` is nonzero, so only a process with CAP_BPF
  can open those pins.

## Non-goals

- Network and process restrictions in v0. R15 states the process limits a
  later version needs; until then a confined command can still ask an
  unconfined process of the user to act for it.
- Asking the user to approve an access.
- Globs in rules.
- Checks on each read or write of an open descriptor.

## Open questions

- Q9: Do chmod, chown, utimes, and xattr changes count as write? v0 leaves them
  out. (not blocking)
- Q19: A confined command can still reach an unconfined server over loopback
  TCP or UDP, such as `ssh localhost` or a language server, which is the
  escape R15 closes for Unix sockets. Network limits are a non-goal. Should
  loopback be the exception? (not blocking)

Settled:

- Q17 (2026-11-14): v0 does not check whether the user trusts a rule set. A
  cloned repository can ship one that grants access. Dakusui prints the set
  at start (spec 0004 R9).
- Q20 (2026-11-14): the walk reads the kernel's rename sequence count before
  and after, and walks again if it changed. After four tries it denies, with
  the reason "path changed". See R6 and A23.
- Q21 (2026-11-14): R6 forbids it. See R6 and A22.

## Decisions

Design choices made while writing this spec live in the ADRs:

- [0002](../../adr/0002-enforce-file-access-with-bpf-lsm.md): enforce with BPF LSM.
- [0004](../../adr/0004-confine-by-task-flag.md): confine by an inherited task flag.
- [0005](../../adr/0005-helper-from-capability-binary.md): the helper starts
  with the capabilities and drops them in the agent process.
- [0006](../../adr/0006-build-paths-by-walking-dentries.md): build paths by
  walking dentries.
- [0007](../../adr/0007-store-rule-sets-in-the-project.md): store rule sets in
  the project.
- [0008](../../adr/0008-pin-the-enforcer.md): pin the enforcer so it outlives
  the helper.

## Verification

| Requirement | Verified by | State |
|-------------|-------------|-------|
| R1 | A1, A2 | Not started |
| R2 | A3 | Not started |
| R3 | A1, A11 | Not started |
| R4 | A4, A7 | Not started |
| R5 | A12 | Not started |
| R6 | A5, A9, A22, A23 | Not started |
| R7 | A13 | Not started |
| R8 | A14 | Not started |
| R9 | A6, A19 | Not started |
| R10 | A15, A16 | Not started |
| R11 | A8 | Not started |
| R12 | A10 | Not started |
| R13 | A17 | Not started |
| R14 | A18 | Not started |
| R15 | A20, A21 | Deferred |

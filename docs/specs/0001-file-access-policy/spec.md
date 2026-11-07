# 0001: File access policy and enforcement

Status: Review

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
  the project directory. Users edit it from there.

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
- R4: The user MUST be able to add and remove rules while commands run. A change
  takes effect on the next open or path operation. A descriptor that is already
  open keeps working.
- R5: Rules MUST distinguish two access kinds, read and write. Executing a file
  and listing a directory count as read. Creating, deleting, renaming, and
  truncating count as write.
- R6: A confined process MUST NOT create hard links. Symlinks, renames, and
  io_uring MUST NOT bypass a rule.
- R7: The system MUST log each denial with the process, path, and access kind.
- R8: The agent and the judge MUST be able to read the current policy.
- R9: If enforcement is not active, the system MUST NOT run commands.
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

## Acceptance

- A1 (R1, R3): Given the default policy, when a command runs `cat .env`, then it
  fails with a permission error. Reading `src/a.c` succeeds.
- A11 (R3): Given the default policy, when a command reads `/etc/hostname`, then
  it succeeds. Reading `~/.ssh/id_ed25519` or writing `/etc/hostname` fails.
- A2 (R1): Given a Python script that opens `/etc/shadow`, when the agent runs
  it, then the open fails.
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
  is shown the policy, then the text lists the rules in force, in order, as the
  user wrote them.
- A15 (R10): Given the rule `deny read,write name:.env`, then it parses. Given a
  relative path, a glob such as `*.pem`, or an unknown kind, then it is
  rejected with a message that names the problem.
- A16 (R10): Given `allow read /my\ dir`, then the rule names `/my dir`. Given
  `allow read /a/`, then the rule names `/a`. Given `/a/../b` or a stray
  backslash such as `/a\b`, then it is rejected with a message that names the
  problem.

## Constraints

- v0 targets x86-64 and Linux 6.18, with `bpf` in the active LSM list,
  `CONFIG_BPF_LSM=y`, and BTF enabled. Other kernels and architectures come
  later.
- Rules match path strings, so confined commands share Dakusui's root and mount
  namespace. No chroot, no private mounts.

## Non-goals

- Network and process restrictions.
- Asking the user to approve an access.
- Globs in rules.
- Checks on each read or write of an open descriptor.

## Open questions

- Q9: Do chmod, chown, utimes, and xattr changes count as write? v0 leaves them
  out. (not blocking)

## Decisions

Design choices made while writing this spec live in the ADRs:

- [0002](../../adr/0002-enforce-file-access-with-bpf-lsm.md): enforce with BPF LSM.
- [0004](../../adr/0004-confine-by-task-flag.md): confine by an inherited task flag.
- [0005](../../adr/0005-helper-from-capability-binary.md): the helper starts
  with the capabilities and drops them in the agent process.
- [0006](../../adr/0006-build-paths-by-walking-dentries.md): build paths by
  walking dentries.

## Verification

| Requirement | Verified by | State |
|-------------|-------------|-------|
| R1 | A1, A2 | Not started |
| R2 | A3 | Not started |
| R3 | A1, A11 | Not started |
| R4 | A4, A7 | Not started |
| R5 | A12 | Not started |
| R6 | A5, A9 | Not started |
| R7 | A13 | Not started |
| R8 | A14 | Not started |
| R9 | A6 | Not started |
| R10 | A15, A16 | Not started |
| R11 | A8 | Not started |
| R12 | A10 | Not started |

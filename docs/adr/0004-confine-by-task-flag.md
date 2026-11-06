# ADR 0004: Confine by an inherited task flag

Status: Accepted
Date: 2026-11-06

## Context

The enforcer must know which processes are confined, including every child a
command starts. A cgroup per command works, but a command that can write
cgroup files can move itself out.

## Decision

We will mark each command's process with a flag in BPF task storage, before the
command runs. A `task_alloc` hook copies the flag to every new task. The
process cannot clear it, because only the helper holds the map.

The sequence: Dakusui forks, the child asks the helper to flag it, the helper
replies, and the child runs `exec`. The flag is keyed by pidfd.

## Alternatives

- Cgroup per command: escapable if the policy ever allows writes to cgroupfs.
  It still suits timeouts and limits, so we may add one later for those.

## Consequences

Confinement does not depend on the policy being right. Killing a whole command
tree needs extra work. The spike confirmed that `touch`, `awk`, and other
descendants inherit the flag (`bpfstudy/`).

# ADR 0002: Enforce file access with BPF LSM

Status: Accepted
Date: 2026-11-05

## Context

Agents run shell commands, and models like to write Python or awk. A rule that
checks only the harness's own tools misses what those programs do. The policy
must also change while the agent runs.

## Decision

We will enforce file access with BPF LSM hooks, scoped by a task flag that children
inherit. The privileged helper owns the policy map and applies updates.

## Alternatives

- Seccomp user notification: races on pointer arguments, and slow.
- Landlock: a ruleset cannot be loosened after it takes effect.
- Checks inside the harness: child processes bypass them.

## Consequences

The kernel must enable BPF LSM, and the helper needs privilege. In return, the
rules bind every child process, and updates take effect at once.

# ADR 0007: Store rule sets in the project

Status: Accepted
Date: 2026-11-07

## Context

Users want several named sets of rules, shared by roles and by sessions in a
project. ADR 0005 ties the helper's loaded policy to the session, so sets must
live elsewhere. The default policy lets confined commands write to the project,
and R11 forbids them from changing the policy.

## Decision

We will store rule sets in `.dakusui/rules` in the project, separate from roles.
A role may name a set. A session's policy is the default policy, then its set,
then `deny write P/.dakusui` as the last rule, so no set can reopen the directory.
A rule added during a session is saved to its set and applies to that session at
once. Other running sessions see it when they next start.

## Alternatives

- Rules inside each role: two roles that differ only by model would copy rules.
- Sets in `~/.config/dakusui`: already denied, but not per project.
- Pushing a change to all running sessions: needs sessions to talk to each other.
- A set that replaces the default policy: the user chose to add to it.

## Consequences

A set can override any deny of the default policy, including `.env` and `~/.ssh`.
Sets can be committed to git and shared, so a cloned repository can ship a set
that grants access; spec 0004 must settle how a user trusts one (Q17). Confined
commands can read sets but not change them. Two sessions on one set can each save
rules, so spec 0004 must keep those writes safe.

Q17 is settled: v0 does not check trust. It loads the set and prints it at
start (spec 0004 R9). (Added 2026-11-14.)

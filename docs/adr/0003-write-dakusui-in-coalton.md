# ADR 0003: Write Dakusui in Coalton

Status: Accepted
Date: 2026-11-05

## Context

Model output, tool arguments, and policy rules arrive as untyped text. Mistakes
in handling them should surface at compile time.

## Decision

We will write Dakusui in Coalton, the typed language embedded in Common Lisp.

## Alternatives

- Plain Common Lisp: no static types.
- Rust or OCaml: strong types, but outside the author's chosen ecosystem.

## Consequences

Static types and Lisp's interactive development. The ecosystem is smaller, so
Dakusui calls C and the kernel through foreign function interfaces.

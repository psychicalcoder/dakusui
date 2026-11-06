# ADR 0006: Build paths by walking dentries

Status: Accepted
Date: 2026-11-06

## Context

Rules match path strings. The kernel offers `bpf_d_path` and a
`bpf_path_d_path` kfunc, but the spike (`bpfstudy/`) found that neither works
at `path_mknod`, `file_truncate`, or `file_permission`. The old side of
`path_link` has no `struct path` at all.

## Decision

We will build every path by walking dentries and mounts with `bpf_loop`, at
every hook. One mechanism covers all of them. The walk crosses mounts: on
`/dev/shm` it produced as many paths as `d_path` at every hook where both ran.

Hooks to enforce: `file_open`, `file_truncate`, `path_truncate`, `path_mknod`,
`path_mkdir`, `path_rmdir`, `path_unlink`, `path_symlink`, `path_rename` (both
sides), and `path_link` (always deny).

## Alternatives

- `bpf_d_path` where it works, a walk elsewhere: two mechanisms to test.
- Check on `file_permission` for each read and write: no usable path there, and
  the cost is not worth it.

## Consequences

The first walk, unrolled, exceeded the verifier's limit. The `bpf_loop` version
keeps only integers in its context and builds the path in per-task scratch
space. If profiling shows the walk is slow at `file_open`, add `bpf_d_path`
there as an optimization.

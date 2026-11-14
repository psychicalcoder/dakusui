# Tasks for 0003: Tools and MCP

Plan: ./plan.md

Write each test first or alongside its code.

## Phase 1: Dakusui's own tools

- [x] T1 Define `Tool`, `Tools`, `call`, and the argument readers. (R1, R2)
  Done when A2 passes and an unknown tool name gives an error result.
- [x] T2 Start the launcher in its own process group, and give `run-command`
  a limit that kills the group. (R4) Done when a unit test of the spawn and
  kill passes without the helper, and A4 is in the check agent.
- [x] T3 Add `sync` to the protocol and the helper, and the mark to the
  denial log. (R6) Done when protocol tests cover `sync`, and A6 is in the
  check agent.
- [x] T4 Write `bash` and `show_policy`, with truncation. (R3, R5, R6, R7, R8)
  Done when A1's built-in half, A5, and A7 pass, and A3 is in the check agent.

## Phase 2: MCP

- [ ] T5 Write `start-process`. (R10) Done when a process started through it
  answers on its pipes and shows as confined in the check agent.
- [ ] T6 Write the MCP client: start, list, call, limits, a dead server.
  (R9, R11, R12) Done when A8 and A10 pass against a scripted server.
- [ ] T7 Start the configured servers at session start and add their tools.
  (R1, R9) Done when A1 passes, and A9 and A10 are in the check agent.
- [ ] T8 Fill in the verification table.

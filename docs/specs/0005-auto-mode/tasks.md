# Tasks for 0005: Auto mode (judge)

Plan: ./plan.md

Write each test first or alongside its code.

- [x] T1 Add `gated` to `Tool`, and the gate to the loop. (R1) Done when a
  scripted gate that says no keeps a tool from running and its reason
  becomes the tool result, and `show_policy` runs unasked.
- [x] T2 Write `user-gate`. (R2) Done when A1 and A2 pass.
- [ ] T3 Write `judge-gate` and the judge's prompt. (R3, R4, R5, R6, R8) Done
  when A3, A4, A5, and A7 pass.
- [ ] T4 Add `--auto` and `/auto`. (R7) Done when A6 passes.
- [ ] T5 Add an allowed and a blocked command to `make agent-check`. Fill in
  the verification table.

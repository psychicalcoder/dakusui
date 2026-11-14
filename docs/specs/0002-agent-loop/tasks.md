# Tasks for 0002: Agent loop and provider client

Plan: ./plan.md

Write each test first or alongside its code.

- [x] T1 Define the chat types, encode a request, and decode a reply. (R2, R3)
  Done when tests round-trip text, tool calls, and tool results, and reject a
  reply with no `choices`.
- [x] T2 Write the terminal: one lock, `say`, `ask`. Route the denial log's
  stderr line through it. (R8) Done when two threads printing lines never
  interleave within a line.
- [x] T3 Write the loop against a scripted provider and tool runner. (R1, R3,
  R4, R5, R6, R7) Done when A2, A3, A4, A5, and A7 pass, and a provider error
  leaves a conversation in which every tool call has its result.
- [x] T4 Bind libcurl and write `http-provider`. (R2, R6, R10) Done when A1,
  A6, and A10 pass against the test server.
- [x] T5 Parse and run the terminal commands. (R9) Done when A8 and A9 pass.
- [x] T6 Pass the helper's arguments to the agent. Write `main`: the prompt
  loop and `-p`. (R1, R11) Done when `make build` succeeds and the agent,
  started under a stand-in helper, completes A11.
- [x] T7 Add A11 to `make attach-check`. Fill in the verification table.

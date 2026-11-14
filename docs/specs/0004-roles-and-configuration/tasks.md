# Tasks for 0004: Roles and configuration

Plan: ./plan.md

Write each test first or alongside its code.

- [x] T1 Parse the command line into `Options`. (R4, R7) Done when tests cover
  each option, a missing value, and an unknown option.
- [ ] T2 Parse the configuration and resolve roles. (R1, R2, R3, R4, R5, R12)
  Done when A1 through A4 and A12 pass.
- [ ] T3 Name and load rule sets. (R6, R8) Done when A5's loading, A6, and A7
  pass.
- [ ] T4 Save a rule set under the lock. (R10, R11) Done when the add, drop,
  and comment cases pass, and A11 passes with two threads.
- [ ] T5 Wire it into main, the session, and the commands: options, role,
  set, the start-up listing, and saving. (R4, R7, R9, R10) Done when A5, A8,
  A9, and A10 pass, and `make agent-check` starts the agent with `--role`
  and `--rules`.
- [ ] T6 Describe the configuration file in `docs/install.md`. Fill in the
  verification table.

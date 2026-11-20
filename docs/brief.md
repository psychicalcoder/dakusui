# Dakusui

Dakusui is an AI agent harness whose file access rules the kernel enforces.

## Why

Opencode's permission design is complicated and weak. Dakusui keeps permissions
simple and enforces them with BPF LSM, so no child process (shell, Python, awk)
can step outside them.

## Goals

- Enforce file access in the kernel, and change the policy while the agent runs.
- Keep the policy small: ordered rules, the last match wins.
- Use Coalton, so types catch mistakes early.
- Ship a small v0.

## Non-goals for v0

- A UI beyond the plain terminal.
- Asking the user to approve each access.
- Network sandboxing.
- Providers other than OpenAI-compatible chat completions.

## Design

```
user ── Dakusui (no capabilities) ── LLM server
            │ socketpair
         helper (parent, CAP_BPF) ── BPF map ── LSM hooks ── confined commands
```

- **Agent loop.** Dakusui calls the chat completions API. The model requests
  tools through `tool_calls`; Dakusui runs them and replies with `tool`-role
  messages. MCP tools join the same list. Arguments decode into typed values.
- **Roles.** A role names a model, base URL, API key, and optionally a rule set.
  `agent` and `judge` ship built in; users define more in
  `~/.config/dakusui/config.json`.
- **Policy.** Ordered rules, last match wins. The default allows the project
  directory and denies `.env`. Users add allows and denies. The agent reads the
  policy through a tool; the judge sees it too.
- **Rule sets.** Named lists of rules in `.dakusui/rules`, shared by roles and
  sessions in a project. A set adds to the default policy, and a rule added during
  a session is saved to its set and applies to that session at once.
- **Enforcement.** A BPF LSM program checks every file access by confined
  processes. The helper flags each command before it runs, and children inherit
  the flag. The helper owns the policy map and applies updates.
- **Tools.** `bash` and `show_policy`, plus the tools of configured MCP
  servers. Commands and servers both run confined.
- **Auto mode.** The user approves each command before it runs. In auto mode a
  judge model does instead. Its verdict is advice. BPF remains the hard limit.

## Specs

| # | Spec | State |
|---|------|-------|
| 0001 | File access policy and enforcement | Implemented |
| 0002 | Agent loop and provider client | Implemented |
| 0003 | Tools and MCP | Implemented |
| 0004 | Roles and configuration | Implemented |
| 0005 | Auto mode (judge) | Implemented |

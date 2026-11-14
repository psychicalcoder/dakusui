# 0004: Roles and configuration

Status: Approved

## Summary

A role names the model Dakusui talks to. A rule set is a named file of rules
in the project. One configuration file in the user's home defines roles and
MCP servers; the command line picks a role, a rule set, and the mode.

## Requirements

- R1: Dakusui MUST read its configuration from `~/.config/dakusui/config.json`,
  which the default policy denies to commands (spec 0001 R3). A missing file
  is an empty configuration. No file in the project configures roles or MCP
  servers.
- R2: A role MUST hold a model, a base URL, an API key, and a rule set name.
  Each is optional in the file. The key is given as `api_key`, or as
  `api_key_env`, the name of an environment variable; giving both is an error.
- R3: The role `agent` MUST fill its missing fields from the environment: the
  base URL from `OPENAI_BASE_URL`, else `https://api.openai.com/v1`; the key
  from `OPENAI_API_KEY`; the model from `OPENAI_MODEL`. Every other role
  fills its missing fields from `agent`. So `judge` exists with no
  configuration at all.
- R4: `--role NAME` MUST pick the role the loop talks to; the default is
  `agent`. A role that is not defined, or that ends with no model, stops
  Dakusui before any request, with a message that names the role and the fix.
- R5: A configuration that is not valid JSON, holds an unknown key, or holds
  a value of the wrong type MUST stop Dakusui at start, with a message that
  names the key.
- R6: A rule set MUST be the file `.dakusui/rules/NAME` in the project: one
  rule per line in the rule text of spec 0001 R10, with blank lines and
  lines that start with `#` ignored. NAME holds 1 to 64 letters, digits,
  `-`, or `_`. A missing file is an empty set.
- R7: The session's set MUST be the one `--rules NAME` gives, else the role's,
  else `default`.
- R8: A set with a line that is not a rule MUST stop Dakusui at start, with a
  message that names the file and the line. Half a set could lack a deny.
- R9: At start, Dakusui MUST print the name of the session's set and its
  rules, so the user sees what a set grants before any command runs.
- R10: When the user adds or removes a rule (spec 0002 R9), Dakusui MUST save
  the change to the set's file after the helper accepts it. If the save
  fails, the rule stays in force for the session, and Dakusui says that it
  was not saved.
- R11: Two sessions saving to one set MUST NOT lose a rule or leave half a
  file. Another running session sees the change when it next starts.
- R12: The configuration MAY name MCP servers: for each, a name of lowercase
  letters, digits, `-`, or `_`, a command, and environment variables to add
  to the server's environment (spec 0003 R9).

Example:

```json
{
  "roles": {
    "agent": {"model": "qwen3-coder", "base_url": "http://localhost:8080/v1"},
    "judge": {"model": "qwen3-small"},
    "cloud": {"model": "gpt-5", "base_url": "https://api.openai.com/v1",
              "api_key_env": "OPENAI_API_KEY", "rules": "strict"}
  },
  "mcp": {
    "docs": {"command": "docs-mcp --stdio", "env": {"DOCS_TOKEN": "..."}}
  }
}
```

## Acceptance

- A1 (R1, R3): Given no configuration file and `OPENAI_MODEL=m`, then the
  `agent` role has model `m` and the default base URL, and `judge` has the
  same.
- A2 (R2, R3): Given the example above and `OPENAI_API_KEY=k`, then `judge`
  has model `qwen3-small` and the agent's base URL, and `cloud` has key `k`
  and the set `strict`.
- A3 (R2, R5): Given a role with both `api_key` and `api_key_env`, a key
  `modle`, or `"model": 5`, then Dakusui stops with a message that names the
  key.
- A4 (R4): Given `--role nosuch`, or a role with no model anywhere, then
  Dakusui stops before any request and names the role.
- A5 (R6, R7): Given `.dakusui/rules/strict` with a comment, a blank line, and
  `deny read,write /p/secret`, when Dakusui starts with `--rules strict`,
  then the session's set holds that one rule. With no `--rules` and no role
  set, it loads `default`; with no such file, the set is empty.
- A6 (R8): Given a set whose third line is `allow read x`, then Dakusui stops
  and names the file and line 3.
- A7 (R6): Given `--rules ../x`, then Dakusui stops and says the name is bad.
- A8 (R9): Given a set with `allow read ~/.ssh` resolved to a real path, then
  the start-up output names the set and shows that rule.
- A9 (R10): Given `/deny read /p/x`, then the set's file ends with that rule,
  and a new session loads it. Given `/remove` of it, the file no longer
  holds it. Comments in the file survive both.
- A10 (R10): Given a set file that cannot be written, when the user adds a
  rule, then `/policy` shows it and Dakusui says it was not saved.
- A11 (R11): Given two processes that each add 100 different rules to one
  set at once, then the file holds all 200, each on its own line.
- A12 (R12): Given the example, then the MCP server list holds `docs` with
  its command and one variable. A server named `Bad Name` is an error.

## Non-goals

- Trusting a set. A cloned repository can ship a set that grants access, and
  v0 loads it (spec 0001 Q17, settled 2026-11-14). R9 shows it; nothing asks.
- Portable sets. A set holds absolute paths.
- Configuration in the project, or in more than one file.
- Changing the role during a session.
- Pushing a saved rule to other running sessions.

## Open questions

None.

## Verification

| Requirement | Verified by | State |
|-------------|-------------|-------|
| R1 | A1 | Not started |
| R2 | A2, A3 | Not started |
| R3 | A1, A2 | Not started |
| R4 | A4 | Not started |
| R5 | A3 | Not started |
| R6 | A5, A7 | Not started |
| R7 | A5 | Not started |
| R8 | A6 | Not started |
| R9 | A8 | Not started |
| R10 | A9, A10 | Not started |
| R11 | A11 | Not started |
| R12 | A12 | Not started |

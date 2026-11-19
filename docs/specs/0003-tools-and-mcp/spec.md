# 0003: Tools and MCP

Status: Implemented

## Summary

Dakusui offers the model two tools of its own, `bash` and `show_policy`, and
the tools of the MCP servers the user configures. Every tool that touches
files does so in a confined process.

## Requirements

- R1: Dakusui MUST offer the model one tool list: its own tools, then each MCP
  server's. Each tool has a name, a description, and a JSON schema for its
  arguments.
- R2: Dakusui MUST decode a tool's arguments into typed values before the tool
  runs. Arguments that do not decode produce an error result (spec 0002 R4).
- R3: `bash` MUST run its `command` with `sh` in the project directory,
  confined (spec 0001 R1). The result is the command's stdout and stderr
  together, and its exit code when that is not 0.
- R4: `bash` MUST end a command that outlives its limit, with every process
  in the command's process group, and say so in the result. The limit is the
  `timeout` argument in seconds: 120 by default, 600 at most.
- R5: A result longer than 30,000 characters MUST keep its first and last
  15,000 and say how much was cut.
- R6: A `bash` result MUST list the denials that happened while the command
  ran: process, path, access kind, and reason. The model can then tell a
  policy denial from an ordinary permission error.
- R7: `show_policy` MUST return the policy in force, as spec 0001 R8 says.
- R8: No tool MUST read or write a file in the agent's own process on the
  model's behalf. The agent is not confined, so that would step around the
  policy.
- R9: At start, Dakusui MUST start each MCP server named in the configuration
  (spec 0004) over stdio, and add its tools to the list as `SERVER__TOOL`.
- R10: An MCP server's process MUST run confined, like a command.
- R11: A call to an MCP tool MUST return the text of the server's result, and
  mark it an error when the server does. A call that gets no answer in 120
  seconds returns an error.
- R12: A server that fails to start or to answer `initialize` MUST be skipped
  with a warning that names it. If a server ends later, calls to its tools
  return an error that says so.

## Acceptance

- A1 (R1): The tool list holds `bash` and `show_policy`, each with a schema,
  then the tools of a test server as `test__echo`.
- A2 (R2): Given `bash` with `{"command": 5}`, or with no `command`, then the
  result names the argument and what was expected, and nothing runs.
- A3 (R3): Given `echo out; echo err >&2; exit 3`, then the result holds
  "out", "err", and the exit code 3. `pwd` prints the project directory.
- A4 (R4): Given `sleep 100 & sleep 100` with a timeout of 1, then the call
  returns within about a second, the result says the command timed out, and
  neither `sleep` is left.
- A5 (R5): Given a command that prints 100,000 characters, then the result
  holds the first and last 15,000 and the count cut.
- A6 (R6): Given `cat .env` under the default policy, then the result holds
  cat's own error and a line that names `cat`, the path of `.env`, `read`,
  and "denied by rule". Given `cat /nonexistent`, the result lists no denial.
- A7 (R7): `show_policy` returns the same text as `/policy` has rules.
- A8 (R9, R11): Given a test server with an `echo` tool, when the model calls
  `test__echo` with `{"text":"hi"}`, then the result is "hi". A tool that
  reports an error yields an error result.
- A9 (R10): Given a test server whose tool reads a file, when it reads the
  project's `.env`, then the read fails and Dakusui logs the denial.
- A10 (R12): Given one server whose command does not exist and one that
  works, then Dakusui warns about the first and offers the second's tools.
  When the second is killed, a call to its tool returns an error.

## Non-goals

- File tools of Dakusui's own (read, write, edit). The model uses `bash`.
- MCP over HTTP, and MCP resources, prompts, sampling, and list changes.
- Running tool calls in parallel.
- Commands that read the terminal. Stdin is `/dev/null`.

## Open questions

None. Settled: Q1 (2026-11-14), an MCP server runs confined (R10).

## Verification

| Requirement | Verified by | State |
|-------------|-------------|-------|
| R1 | A1 | Passes (unit, agent-check) |
| R2 | A2 | Passes (unit) |
| R3 | A3 | Passes (unit, unconfined); in attach-check, not run |
| R4 | A4 | Passes (unit, unconfined); in attach-check, not run |
| R5 | A5 | Passes (unit) |
| R6 | A6 | Passes (unit, fake helper); in attach-check, not run |
| R7 | A7 | Passes (unit) |
| R8 | review: no file call in `tools.ct` or `mcp.ct` | Passes (review) |
| R9 | A1, A8 | Passes (unit, agent-check) |
| R10 | A9 | In attach-check, not run |
| R11 | A8 | Passes (unit, agent-check) |
| R12 | A10 | Passes (unit); confined half in attach-check, not run |

"Unit" is `make test`; "agent-check" is `make agent-check`, the agent under
a stand-in helper. Cases marked "in attach-check" need `sudo` and the bpffs
mount, which the development machine lacked. Checked 2026-11-19.

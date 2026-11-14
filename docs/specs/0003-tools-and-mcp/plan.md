# Plan for 0003: Tools and MCP

Status: Approved
Spec: ./spec.md
Tasks: ./tasks.md

## Approach

A tool is a record: its `ToolSpec` (spec 0002) and a function from the raw
argument string to a result string. The built-in tools and each MCP tool are
values of that one type, so the loop treats them alike. Both `bash` and an MCP
server start through the launcher of spec 0001, so both are flagged before
they run.

## Parts and interfaces

**1. Tools** (`src/agent/tools.ct`)

    Tool  = spec ToolSpec, run (String -> String)
    Tools = List Tool
    call : Tools * ToolCall -> String

`call` finds the tool by name and runs it; an unknown name is an error result.
An error result starts with "error: ". `call` shortens every result (R5).
Each tool decodes its arguments with small typed readers over the parsed
JSON: `required-string`, `optional-integer`. A reader's error names the
argument and the type expected (R2). A `timeout` outside 1 to 600 is an
argument error, not clamped. `show_policy` takes empty argument text too.

**2. Launcher changes** (`src/agent/launch.ct`)

- The launcher starts in its own process group
  (`POSIX_SPAWN_SETPGROUP`), so one `kill(-pgid, SIGKILL)` ends the command's
  group (R4). Ctrl-C at the terminal then no longer reaches commands; the
  helper's exit still ends them (spec 0001 R9).
- `run-command` takes a limit. It reads the output with `poll` against the
  deadline. At the deadline it kills the group, stops reading, and reaps the
  launcher. A launcher that closes its output early is still waited for only
  until the deadline. A process that left the group with `setsid` lives on, still
  confined, and no longer holds up the call.
- `start-process` is the same spawn with stdin and stdout on two pipes and
  stderr to `/dev/null`, for MCP servers. It returns the pid and both ends.

**3. Denials for a command** (`denials.ct`, helper `protocol.ct`, `serve.ct`)

The protocol gains `{"op":"sync"}`. The helper consumes the denial ring
buffer, sends what it finds, and then answers `{"ok":true}`. The kernel
submits a record before the denied call returns, so every denial of a
finished command reaches the agent before the reply does.

The denial log keeps the events since a mark (`mark`, then `marked`, which
returns them and stops keeping). `bash` sets the mark, runs the
command, sends `sync`, and takes the events (R6). Commands run one at a time,
so the window holds that command's denials, plus those of any process an
earlier command left behind. The result says "denials while this ran".

**4. MCP client** (`src/agent/mcp.ct`)

JSON-RPC 2.0, one message per line, over the server's stdin and stdout. At
start: `initialize`, the `notifications/initialized` notice, then
`tools/list`. A call sends `tools/call` and reads lines until the answer
with its id, skipping notices, with `poll` against the 120 second limit. The
result's `content` items of type `text` join into the result string;
`isError` prefixes it with "error: ". A closed pipe marks the server dead.

The server's command comes from the configuration (spec 0004) and runs
through `sh`, as `bash` commands do, with the same scrubbed environment plus
the variables the configuration names for it.

## Requirement coverage

- R1, R2: tools.
- R3, R4, R5: `bash` and the launcher.
- R6: `sync` and the denial mark.
- R7: `show_policy` calls `session:policy-text`.
- R8: `tools.ct` and `mcp.ct` open no file; they spawn.
- R9, R11, R12: MCP client.
- R10: `start-process` flags the server through the helper before release.

## Alternatives rejected

- File tools inside the agent that consult the reference evaluator: a second
  enforcer to keep in step with the kernel's.
- Matching denials to a command by pid: needs the process tree. The time
  window is enough when commands run one at a time.
- A cgroup per command for the kill: more privilege for the helper. The
  process group does for v0.

## Risks

- **A command that leaves its group.** `setsid` escapes the timeout kill. It
  stays confined, and the helper's exit ends it.
- **A session rule change while a server runs.** The server sees the new
  policy at its next open, as any command does.
- **A server that floods stdout.** The client reads only while a call waits.
  A full pipe blocks the server, not Dakusui.

## Testing

Unit tests: argument readers (A2), truncation (A5), the tool list (A1), and
the MCP client against a scripted server on two pipes (A8, A10's protocol
half). The launcher changes (A3, A4), denials (A6), and a confined server
(A9, A10) need the kernel, so they join the check agent of
`make attach-check`. The test server is a short Python script in `test/`.

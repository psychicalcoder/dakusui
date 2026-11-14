# Plan for 0002: Agent loop and provider client

Status: Approved
Spec: ./spec.md
Tasks: ./tasks.md

## Approach

The loop is a pure function over three things it is handed: a provider, a tool
runner, and a terminal. Each is a function, so tests script all three and need
no server, kernel, or helper. The real provider calls libcurl through CFFI,
as the helper calls libbpf. One request, one reply: no streaming.

## Parts and interfaces

All in `src/agent/`, in the `dakusui/agent` system.

**1. Chat types** (`chat.ct`)

    Message   = System text | User text
              | Assistant (Optional text) (List ToolCall)
              | ToolResult id text
    ToolCall  = id, name, arguments (the raw JSON string)
    ToolSpec  = name, description, parameters (a JSON schema, as a string)
    Reply     = Optional text, List ToolCall

`request-json` encodes a model name, messages, and tool specs into the request
body. `decode-reply` parses a response body into a `Reply` or an error. jzon
does the JSON, with the depth limit raised to fit tool schemas.

**2. Provider** (`provider.ct`)

    Provider = (List Message * List ToolSpec -> Result String Reply)

`http-provider` builds one from a base URL, an optional key, and a model. It
posts with libcurl (`libcurl.so.4`, the easy interface), with a 600 second
limit. An error names the status and the server's `error.message`, or curl's
reason. The key goes only into the `Authorization` header; no message is
built from the header, so the key cannot leak into one (R10). A server may echo the key in its
error text, so the provider replaces any copy of it there with `[key]`.

**3. Terminal** (`terminal.ct`)

One lock guards every write to stdout and stderr. `say` prints a line; the
denial log's stderr line goes through it too. `warn` prints to stderr. `ask` prints the prompt `> `
and reads a line, or `None` at the end of input. The loop takes the terminal
as a function, `String -> Unit`, so tests capture it.

**4. Loop** (`loop.ct`)

    Conversation = the messages so far
    run-turn : Provider * Tools * Terminal * Conversation * user text
               -> Tuple Conversation (Result String Unit)

`Tools` is the interface of spec 0003: the list of `ToolSpec`, and
`call : ToolCall -> String`, which never fails: a problem comes back as the
result's text (R4). `run-turn` appends the user's message, then repeats: call
the provider, print any text, run each tool call, append the results. It
counts model calls and stops at 50 (R5). On a provider error, or at the limit, it
prints why and returns the conversation as gathered. Every tool call in it already has its result, since
a reply's calls all run before the next request (R6).

**5. Commands** (`commands.ct`)

Parses a `/` line into a typed command and runs it against the `Session` of
spec 0001. `/allow` and `/deny` hand the line, minus the slash, to
`parse-rule`, then `session:add-rule`. `/policy` prints the default rules, the
set's rules with numbers, and the fixed last rule. The prompt loop lives here
too, reading lines through a function, so tests script the input (A8, A9).

**6. Main** (`main.ct`)

Hardens, connects to the helper, starts the session, reads the role (spec
0004; until then, from `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and
`OPENAI_MODEL`; the base URL defaults to `https://api.openai.com/v1`, and
the model is required), and runs the prompt loop, or one turn for `-p`.

**7. Arguments.** The helper passes its arguments to the agent unchanged and
reads none itself, so the capability-bearing binary still takes no option.

## Requirement coverage

- R1, R3, R5, R6: the loop.
- R2, R10: provider and chat types.
- R4: `Tools.call` and the argument decoders of spec 0003.
- R7: `system-prompt` in the loop, built from the project directory.
- R8: terminal.
- R9: commands.
- R11: main.

## Alternatives rejected

- A Lisp HTTP client (dexador, drakma): pulls in a TLS stack and a dozen
  systems. libcurl is one library the machine already has.
- Running the `curl` program: the key would pass through a process's
  arguments or a file.
- Streaming: more protocol for a nicer wait. Later.

## Risks

- **A long reply blocks the terminal.** Nothing prints until the reply is
  whole. Accepted for v0.
- **Ctrl-C.** The terminal sends SIGINT to the helper, the agent, and the
  command at once. The helper clears its session as it exits (spec 0001), so
  this is safe, but the conversation is lost.

## Testing

Unit tests script the provider and the tool runner and capture the terminal:
A2 through A5, A7 through A9. A small HTTP server in the test suite (Lisp,
`sb-bsd-sockets`), on a loopback port, checks the real provider: A1, A6, A10.
`make agent-check` runs the built agent under a stand-in helper with a Python
test provider (`test/agent-check.py`): A11 and whole turns, unconfined, with
no privilege. `make attach-check` runs the same script with copies of the real
helper and agent in `build/check/real/`, so the cases run confined.

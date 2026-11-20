# 0002: Agent loop and provider client

Status: Implemented

## Summary

Dakusui reads the user's message from the terminal, sends the conversation to
a chat completions server, and runs the tools the model asks for until the
model answers. The terminal also takes the commands that change the policy.

## Requirements

- R1: Dakusui MUST read one message per line from the terminal, send the
  conversation to the model, and print the model's reply.
- R2: Dakusui MUST call `POST {base_url}/chat/completions` with the role's
  model, the messages, and the tool list (spec 0003). It sends the role's API
  key as a bearer token, when the role has one. Spec 0004 supplies the role.
- R3: When a reply requests tools, Dakusui MUST run each call in order, append
  one `tool` message per call, and call the model again. The turn ends with
  the first reply that requests none.
- R4: A tool call that cannot run MUST produce a `tool` message that names the
  problem: an unknown tool, arguments that are not JSON, or an argument of the
  wrong type. The turn goes on.
- R5: A turn MUST stop after 50 model calls, and tell the user.
- R6: When the provider fails, Dakusui MUST print the failure and return to
  the prompt: no connection, a status other than 2xx, or a reply it cannot
  decode. The message names the status and the server's error text. The
  conversation keeps what the turn had gathered, so the user can go on.
- R7: The first message MUST be a system prompt. It names the project
  directory, says that the kernel confines every command to the policy, and
  names the `show_policy` tool.
- R8: Dakusui MUST show each tool call before it runs, and a short form of its
  result after. All terminal output, denial lines included (spec 0001 R7),
  MUST pass through one writer, so lines never mix.
- R9: A line that starts with `/` is a command for Dakusui, never sent to the
  model:

  ```
  /policy            show the policy in force
  /allow KINDS PATH  add an allow rule to the session's rule set
  /deny KINDS PATH   add a deny rule
  /remove N          remove rule N of the set, as /policy numbers it
  /auto [on|off]     show auto mode, or turn it on or off (spec 0005)
  /clear             forget the conversation
  /help              list these commands
  /quit              leave; so does the end of input
  ```

  A rule is the rule text of spec 0001 R10 with the slash before it. An
  unknown command or a bad rule prints a message that names the problem.
- R10: The API key MUST NOT appear in terminal output or in any log.
- R11: `dakusui -p TEXT` MUST run one turn with TEXT as the user's message,
  then exit: 0 if the turn ended with a reply, 1 otherwise.

## Acceptance

Each case runs against a scripted provider.

- A1 (R1, R2): Given a provider that answers "hello", when the user types
  "hi", then the request carries the model, a system message, and the user's
  message, and the terminal shows "hello".
- A2 (R3): Given a reply that requests `bash` with `echo one`, then a reply
  with text, when the turn runs, then the second request carries the
  assistant's tool call and a `tool` message with "one", and the turn ends.
- A3 (R3): Given one reply with two tool calls, then both run in order, and
  the next request carries two `tool` messages with matching ids.
- A4 (R4): Given a call to `nosuch`, a call whose arguments are `{"command":`,
  and a call to `bash` with `{"command": 5}`, then each gets a `tool` message
  that names its problem, and the turn goes on.
- A5 (R5): Given a provider that always requests a tool, when a turn runs,
  then it stops after 50 model calls and says so.
- A6 (R6): Given a provider that answers 401 with `{"error":{"message":"bad
  key"}}`, then the terminal shows the status and "bad key", and the prompt
  returns. Given a refused connection, the same, with the reason.
- A7 (R7): The system prompt names the project directory and `show_policy`.
- A8 (R9): Given `/deny read /p/x`, then `/policy` lists `deny read /p/x`
  among the set's rules with its number, and `/remove` with that number takes
  it out. `/allow read x` prints why the rule is bad. `/nosuch` prints that
  the command is unknown. None reaches the provider.
- A9 (R9): Given two turns and then `/clear`, then the next request carries
  only the system prompt and the new message.
- A10 (R10): Given a role with the key `sk-secret`, when the provider answers
  401, then no terminal output or log holds `sk-secret`.
- A11 (R11): Given `dakusui -p hi` and a provider that answers "hello", then
  the output holds "hello" and the exit code is 0. With a failing provider,
  the exit code is 1.

## Non-goals

- Streaming replies.
- Shortening a conversation that outgrows the model's context. `/clear` is
  the remedy in v0.
- Retrying a failed request.
- Interrupting a turn. Ctrl-C ends Dakusui.
- Saving or resuming a conversation.
- Images and other content that is not text.

## Open questions

None.

## Verification

| Requirement | Verified by | State |
|-------------|-------------|-------|
| R1 | A1 | Passes (unit) |
| R2 | A1 | Passes (unit) |
| R3 | A2, A3 | Passes (unit) |
| R4 | A4 | Passes (unit) |
| R5 | A5 | Passes (unit) |
| R6 | A6 | Passes (unit) |
| R7 | A7 | Passes (unit) |
| R8 | A2 | Passes (unit) |
| R9 | A8, A9 | Passes (unit) |
| R10 | A10 | Passes (unit) |
| R11 | A11 | Passes (`make agent-check`, `make attach-check`) |

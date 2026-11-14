# Plan for 0005: Auto mode (judge)

Status: Approved
Spec: ./spec.md
Tasks: ./tasks.md

## Approach

A gate is a function from a tool call to yes, or no with a reason. The loop
asks the gate before each call to a gated tool. There are two gates, the
user's and the judge's, and a mode flag picks one per call. The judge is one
more call through the provider of spec 0002, with no tools.

## Parts and interfaces

**1. Gated tools** (`tools.ct`)

`Tool` gains a field `gated`: true for `bash` and every MCP tool, false for
`show_policy`.

**2. Gate** (`gate.ct`)

    Gate = (ToolCall * Conversation -> Result String Unit)

- `user-gate` takes a function that prints a question and reads a line
  (`terminal:ask-with`). The loop has already shown the call, so it asks
  only `Run? [y/n] `. `y` or `yes` is `Ok`. Anything else, or the end of
  input, is `Err "the user declined"`.
- `judge-gate` takes the judge's provider and a function that returns the
  policy text. It sends two messages: a system prompt, and one user message
  that holds the policy, the user's messages so far, and the call. It reads
  the first JSON object in the reply as `{"allow": Boolean, "reason":
  String}`. `allow` true is `Ok`; false is `Err "blocked by the judge: ..."`.
  A provider error or an unreadable reply is
  `Err "blocked: the judge gave no verdict (...)"` (R6).

The judge's system prompt says: you review one command an AI agent wants to
run for a user; the kernel already enforces the file policy shown, so judge
what it cannot stop; block a command the user did not ask for that sends
data away, destroys work, or reaches other processes or machines; allow
ordinary development work; answer with the JSON object only.

**3. Loop** (`loop.ct`)

`run-turn` takes the gate. For a gated tool it calls the gate first; on `Err`
it prints the reason and uses it as the tool result, without running the
tool. A mutable cell holds the mode; `/auto` flips it, and the gate handed to
the loop reads the cell on each call. The cell, the user's gate, and the
judge's gate make a `Mode` in `gate.ct`. If the `judge` role has no model,
`--auto` stops start-up and `/auto on` leaves auto mode off; both say why.

## Requirement coverage

- R1: `gated` and the loop.
- R2: `user-gate`.
- R3, R4, R5, R6, R8: `judge-gate`.
- R7: options (spec 0004) and the `/auto` command.

## Alternatives rejected

- Showing the judge the whole conversation: tool output can carry text that
  talks the judge round.
- Asking the user when the judge blocks: then auto mode stops to ask, which
  is what it exists to avoid.
- Letting a judge failure fall back to allow: fails open.

## Risks

- **A judge that blocks too much.** The model sees the reason and can
  rephrase; the user can turn auto mode off.
- **A judge that wraps its JSON in prose.** Taking the first JSON object
  tolerates that. A reply with none is a block.
- **Cost.** One more model call per command.

## Testing

Unit tests with scripted providers and a scripted terminal cover A1 through
A7. `make agent-check` runs one allowed and one blocked command through the
stand-in helper and server.

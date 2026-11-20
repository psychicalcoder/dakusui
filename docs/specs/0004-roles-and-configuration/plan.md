# Plan for 0004: Roles and configuration

Status: Implemented
Spec: ./spec.md
Tasks: ./tasks.md

## Approach

Three small parts, each a parser from text to typed values: the command
line, the configuration file, and a rule set file. Main runs them in that
order before it talks to anyone, and stops on the first error. JSON, because
jzon is already here and a TOML reader is not.

## Parts and interfaces

All in `src/agent/`.

**1. Options** (`options.ct`)

    Options = role String, rules (Optional String), auto Boolean,
              prompt (Optional String)
    parse-options : List String -> Result String Options

Knows `--role NAME`, `--rules NAME`, `--auto` (spec 0005), and `-p TEXT`
(spec 0002). Anything else is an error that lists these.

**2. Configuration** (`config.ct`)

    Role      = model, base-url, api-key (Optional), rules (Optional)
    McpServer = name, command, env (List (Tuple String String))
    Config    = roles, servers
    parse-config : String * (String -> Optional String) -> Result String Config
    role : Config * String -> Result String Role

`parse-config` takes the file's text and a function that reads the
environment, so tests need neither. It checks every key against the known
ones (R5), resolves `api_key_env` at once, and fills fields as R3 says.
`role` looks a name up and fails if it has no model (R4). A `Role` prints
without its key, so no message can show it (spec 0002 R10).

**3. Rule sets** (`rulesets.ct`)

    set-path  : project * name -> Result String String
    load-set  : path -> Result String (List Rule)
    add-line  : path * Rule -> Result String Unit
    drop-line : path * Rule -> Result String Unit

`load-set` parses each line with `parse-rule` and names the line that fails
(R8). A save takes `flock` on `.dakusui/rules/.lock`, reads the file as it is
now, changes it, writes a temporary file beside it, and renames that over
the set (R11). `add-line` appends the rule's text. `drop-line` removes the
last line whose rule equals the one removed, and keeps every other line,
comments included. Both create `.dakusui/rules` if it is missing.

The file holds a rule as the user typed it, after symlinks are resolved, so
what loads later is what was in force (spec 0001 R13).

**4. Wiring** (`main.ct`, `session.ct`, `commands.ct`)

Main parses options, reads the configuration, picks the role, loads the set,
and passes the set to `session:start`, which now takes the rules. It prints
the set (R9), then builds the provider from the role. `/allow`, `/deny`, and
`/remove` call `add-line` or `drop-line` after the session accepts the
change, and print a warning if the save fails (R10).

## Requirement coverage

- R1 through R5, R12: configuration.
- R4, R7: options and main.
- R6, R8, R10, R11: rule sets.
- R9: main.

## Alternatives rejected

- TOML or an s-expression file: a new parser, or `read` on user text.
- A lock on the set file itself: the rename replaces the file, and the lock
  with it.
- Rewriting the file from the session's rules: drops comments, and the rules
  another session saved.

## Risks

- **A set changed under a session.** The session's set and the file can
  differ once another session saves. Each save changes one line, so neither
  loses the other's rules.
- **A key in the file.** The file is the user's to protect. The default
  policy keeps commands out; other users are kept out by its mode, which
  Dakusui does not check.

- **A rule written by hand through a symlink.** The session holds the rule
  resolved, so `/remove` finds no equal line in the file and leaves it. The
  rule is gone for the session and back at the next start. Rules saved by
  the commands are already resolved.

## Testing

Unit tests cover every case: A1 through A8 and A12 on strings and temp
files, A9 and A10 through the commands with a stand-in helper, and A11 with
two threads on one temp directory plus two processes in `make agent-check`.

# Dakusui

Dakusui is an AI agent harness whose file access rules the Linux kernel
enforces. Most harnesses check permissions in their own code, so a shell,
Python, or awk child can slip past them. Dakusui checks every file access with
a BPF LSM program, and every child a command starts stays confined. The policy
is small: ordered allow and deny rules, where the last match wins. By default
the agent may use the project directory but not `.env`. You can add rules while
the agent runs. An optional judge model approves commands in auto mode. Dakusui
is written in Coalton and talks to any OpenAI-compatible chat completions
server.

## Architecture

```
  user <--> dakusui-agent <---- HTTPS ----> LLM server (agent, judge)
            (no capabilities)
              |         |  ^
   1 spawn    | 2 flag  |  | 3 ok
   4 release  |   pid   v  |
              |        helper (CAP_BPF, CAP_PERFMON)
              v            |
          launcher         | writes rules
              | 5 exec     | and task flags
              v            |
   confined command        |
   (bash, MCP server,      |
    and their children)    |
      |        ^           |
 -----|--------|-----------|------------------------- kernel
      |        |           v
      |        |     +------------+
   syscall  allow /  | policy map |
      |      deny    | task flags |
      v        |     +------------+
  +------------+--+        |
  | BPF LSM hooks |<-------+ lookup
  +---------------+
```

A command never runs unflagged:

1. The agent spawns a launcher, which blocks before it runs anything.
2. The agent asks the helper to flag the launcher's pid.
3. The helper sets the flag in the kernel and replies `ok`.
4. The agent releases the launcher. If the flag failed, the agent closes the
   launcher's pipe without writing, and the command never runs.
5. The launcher execs the command, which is already confined.

From then on, each file syscall of the command, such as `open` or `rename`,
reaches a BPF LSM hook first. The hook looks up the path in the policy map and
allows or denies the call. Children inherit the flag. The helper is the only
writer of the map.

- **Agent** (`src/agent`). Runs the chat loop, the `bash` and `show_policy`
  tools, and MCP tools. It holds no capabilities and cannot change the policy
  except through the helper.
- **Helper** (`src/helper`). The `dakusui` binary starts with CAP_BPF and
  CAP_PERFMON, loads the BPF programs, then forks the agent with every
  capability dropped. It alone writes the policy map and flags new commands.
- **Enforcer** (`bpf/enforce.bpf.c`). LSM hooks check each file access by a
  flagged process against the policy. Children inherit the flag, so nothing a
  command spawns escapes. The enforcer stays pinned after the helper exits.
- **Policy** (`src/policy`). Rules and named rule sets, stored in
  `.dakusui/rules` and shared across roles and sessions.

See `docs/brief.md` for the design, `docs/install.md` to build and install,
and `docs/adr/` for the decisions behind it.

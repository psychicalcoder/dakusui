# Workflow

Dakusui is built spec first. The spec says what the system does. Code follows.

```
brief → spec → plan → tasks → code → verify
```

1. **Brief** (`brief.md`). The idea, goals, and shape of the whole project.
2. **Spec** (`specs/NNNN-name/spec.md`). One component: its requirements and
   acceptance criteria. Describe behavior only.
3. **Plan** (`plan.md`). How to build it, and why this way.
4. **Tasks** (`tasks.md`). Small steps, each tied to a requirement.
5. **Code.** One task at a time, with tests.
6. **Verify.** Each requirement has a test or a recorded check.

## Rules

- Review each stage before starting the next.
- Change the spec in the same commit as any behavior change.
- Number requirements (R1, R2) and never renumber them.
- Write unknowns as open questions. Do not guess.
- Record hard-to-reverse decisions in `adr/`.
- Write short, plain documents.

## Layout

```
CLAUDE.md
docs/
  brief.md
  constitution.md
  templates/
  specs/NNNN-name/{spec,plan,tasks}.md
  adr/NNNN-title.md
```

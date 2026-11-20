# Dakusui

An AI agent harness with kernel-enforced file access. Read `docs/brief.md`,
then `docs/README.md` for the workflow and `docs/constitution.md` for the rules.

## Working rules

- Find or write the spec before changing behavior. Propose spec changes first.
- Follow the stages: spec, plan, tasks, code, verify. Wait for approval between
  stages.
- Copy `docs/templates/` for new documents. Do not edit the templates.
- Cite requirement IDs in tasks, tests, and commits.
- If code and spec disagree, ask which is right.
- Record open questions. Do not guess answers.
- Write short, plain documents. Omit needless words, use the active voice.

## Project facts

- Language: Coalton (on Common Lisp, SBCL).
- Provider: OpenAI-compatible chat completions.
- Enforcement: BPF LSM, policy map owned by a privileged helper.
- Build: `make build` writes `build/dakusui` and `build/dakusui-agent`.
- Test: `make test` (Fiasco through `coalton/testing`).

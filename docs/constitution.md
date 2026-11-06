# Constitution

Rules every plan must respect. Deviations need an ADR.

1. **The kernel enforces; models advise.** No LLM verdict can widen file access.
2. **Fail closed.** If enforcement is missing, commands do not run.
3. **Decide on kernel data.** Never check attacker-controlled memory and then
   trust it later.
4. **Keep it simple.** Prefer the smallest design that meets the spec.
5. **Make types carry meaning.** Parse input at the edge into typed values.
6. **Explain denials.** Every denial can be traced to a rule.

## Constraints

- Linux 6.x with BPF LSM enabled.
- The `dakusui` binary starts with CAP_BPF and CAP_PERFMON and becomes the
  helper. The agent process it forks holds no capabilities.
- Coalton on SBCL.

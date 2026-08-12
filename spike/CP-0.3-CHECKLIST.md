# CP-0.3 — Differentiation checklist

**Gate:** the side-by-side shows at least one finding class BuildLens surfaces that StepSecurity Harden-Runner does not, visible in the first run without configuration. See [ROADMAP.md CP-0.3](../ROADMAP.md#phase-0--feasibility-spike-3-weeks) and [STRATEGY.md](../STRATEGY.md) for why this matters more than any line of spike code: Harden-Runner is an established, well-liked competitor, and "we also watch egress" is not a business.

This is manual by nature — it's a product comparison, not something a workflow can assert. Do it once real probes exist (end of Phase 1 realistically, but sketch it now with whatever Phase 0 produces).

## Steps

1. Pick one real repo with a dependency that does something worth catching (a `postinstall` script is enough — doesn't need to be malicious for this test, just non-trivial).
2. Install [Harden-Runner](https://github.com/step-security/harden-runner) on it. Run it once in audit mode. Screenshot the output.
3. Run the BuildLens spike (once file-open + egress probes exist, not just exec) on the identical commit. Screenshot the output.
4. Answer, in writing, not just in your head:
   - What did Harden-Runner's output tell you?
   - What did BuildLens's output tell you that Harden-Runner's didn't?
   - Would a skeptical AppSec engineer look at both screenshots and immediately see why the second is worth paying for?
5. If the honest answer to the last question is no — stop building. Per ROADMAP.md, this is a "rethink positioning before writing production code" situation, not a "add more features" situation.

## Evidence to keep

- Both screenshots, side by side, in `spike/evidence/cp-0.3/`
- The written answers to the three questions above
- Paste both into the feasibility memo (`MEMO_TEMPLATE.md`)

# CP-0.3 — Differentiation checklist

**Gate:** the side-by-side shows at least one finding class BuildLens surfaces that StepSecurity Harden-Runner does not, visible in the first run without configuration. See [ROADMAP.md CP-0.3](../ROADMAP.md#phase-0--feasibility-spike-3-weeks) and [STRATEGY.md](../STRATEGY.md) for why this matters more than any line of spike code: Harden-Runner is an established, well-liked competitor, and "we also watch egress" is not a business.

This is manual by nature — it's a product comparison, not something a workflow can assert. The BuildLens side of it no longer needs to wait for Phase 1: the `detection-proof` job in `phase0-spike.yml` (M0.5) now runs a synthetic malicious `postinstall` and captures the read-then-egress correlation in raw events — that's your evidence for step 1 below, already produced.

## Steps

1. **Get BuildLens's side first, it's already built.** Download the `phase0-detection-proof` artifact from the latest `phase0-spike` run (or open the `detection-proof` job's log directly). It shows: a synthetic package reads `spike/fixtures/detection-demo/.env`, then POSTs it to a local listener, and the probe emits a `TAINTED_EGRESS` record tying the two together with the process, the file, the destination, and the elapsed milliseconds. Screenshot the log section between `--- raw probe events ---` and `M0.5 PASS`.
2. Pick one real repo with a dependency that does something worth catching (a `postinstall` script is enough — doesn't need to be malicious for this test, just non-trivial). This can be a *different* repo than the one used for step 1 — the point of step 1 was proving the mechanism works at all; this step is about a realistic install.
3. Install [Harden-Runner](https://github.com/step-security/harden-runner) on that repo. Run it once in audit mode. Screenshot the output.
4. Answer, in writing, not just in your head:
   - What did Harden-Runner's output tell you?
   - What did BuildLens's output tell you that Harden-Runner's didn't?
   - Would a skeptical AppSec engineer look at both screenshots and immediately see why the second is worth paying for?
5. If the honest answer to the last question is no — stop building. Per ROADMAP.md, this is a "rethink positioning before writing production code" situation, not a "add more features" situation.

## Evidence to keep

- Both screenshots, side by side, in `spike/evidence/cp-0.3/`
- The written answers to the three questions above
- Paste both into the feasibility memo (`MEMO_TEMPLATE.md`)

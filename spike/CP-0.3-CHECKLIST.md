# CP-0.3 — Differentiation checklist

**Gate:** the side-by-side shows at least one finding class BuildLens surfaces that StepSecurity Harden-Runner does not, visible in the first run without configuration. See [ROADMAP.md CP-0.3](../ROADMAP.md#phase-0--feasibility-spike-3-weeks) and [STRATEGY.md](../STRATEGY.md) for why this matters more than any line of spike code: Harden-Runner is an established, well-liked competitor, and "we also watch egress" is not a business.

This is manual by nature — it's a product comparison, not something a workflow can assert. The BuildLens side of it no longer needs to wait for Phase 1: the `detection-proof` job in `phase0-spike.yml` (M0.5) now runs a synthetic malicious `postinstall` and captures the read-then-egress correlation in raw events — that's your evidence for step 1 below, already produced.

## Steps

1. Make the repo public (Harden-Runner's free tier does not run on private repos).
2. Actions → **cp03-compare** → Run workflow. It runs the same `npm ci` of `spike/fixtures/cp03-app` (real dependencies + one compromised `telemetry-helper` that sends a dummy `.env` to httpbin.org) three times: nothing attached, BuildLens, Harden-Runner in audit mode.
3. Screenshot the BuildLens job summary and the Harden-Runner insights page (linked from its job summary). Save both in `spike/evidence/cp-0.3/`.
4. Fill in [harden-runner-comparison.md](../harden-runner-comparison.md) with the real output, and answer in writing:
   - What did Harden-Runner's output tell you?
   - What did BuildLens's output tell you that Harden-Runner's didn't?
   - Would a skeptical AppSec engineer look at both screenshots and immediately see why the second is worth paying for?
5. Show both screenshots to one AppSec engineer who owes you nothing. Record their answer, not yours.
6. If the honest answer to the last question is no — stop building. Per ROADMAP.md, this is a "rethink positioning before writing production code" situation, not a "add more features" situation.

## Evidence to keep

- Both screenshots, side by side, in `spike/evidence/cp-0.3/`
- The written answers to the three questions above
- Paste both into the feasibility memo (`MEMO_TEMPLATE.md`)

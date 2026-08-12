# Phase 0 feasibility memo

**Fill this in once all three checkpoints have run. Two pages, per ROADMAP.md. Numbers, not adjectives.**

## Verdict

- [ ] GO — all three checkpoints passed, proceed to Phase 1
- [ ] GO with scope change — CP-0.1 failed, pivoting to self-hosted/container runners only
- [ ] NO-GO — [reason]

## CP-0.1 — eBPF loads on hosted runners

| Kernel | BTF present | Events captured | Pass? |
|---|---|---|---|
| ubuntu-22.04 | | | |
| ubuntu-24.04 | | | |

Source: `phase0-evidence-*` artifacts from `.github/workflows/phase0-spike.yml`.

## CP-0.2 — overhead

| | Median wall clock | 
|---|---|
| Baseline (no probe) | |
| Instrumented | |
| **Overhead** | |

Source: `phase0-overhead` artifact, `out/overhead.txt`. Ran on N=5 pairs — bump to 30 (per ROADMAP.md) before this number goes in front of a design partner.

## CP-0.3 — differentiation

Screenshots and answers from `CP-0.3-CHECKLIST.md`, inline or linked.

## Recommendation

[One paragraph. If GO: what changes for Phase 1 based on what was learned here — e.g. was BPF LSM available, or must Phase 1 budget a week for the tracepoint fallback? If NO-GO or scope change: what TAM impact, and what's the next step.]

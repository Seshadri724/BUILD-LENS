# Phase 0 feasibility memo

**Fill this in once all three checkpoints have run. Two pages, per ROADMAP.md. Numbers, not adjectives.**

## Verdict

- [ ] GO — all three checkpoints passed, proceed to Phase 1
- [ ] GO with scope change — CP-0.1 failed, pivoting to self-hosted/container runners only
- [ ] NO-GO — [reason]

**CP-0.1 and CP-0.2 both passed with credible, low-noise numbers (run [`077f419`](https://github.com/Seshadri724/BUILD-LENS/commit/077f419)). CP-0.3 is the only thing left before this checkbox can be filled in — see below.**

## CP-0.1 — eBPF loads on hosted runners

| Kernel | BTF present | Events captured | Pass? |
|---|---|---|---|
| ubuntu-22.04 | yes (vmlinux.h generation succeeded) | ✅ green, run 077f419 | **Pass** |
| ubuntu-24.04 | yes (vmlinux.h generation succeeded — kernel `6.17.0-1020-azure`) | ✅ green, run 077f419 | **Pass** |

Exact per-run event counts weren't pulled from the artifact for this memo — download `phase0-evidence-*` from the run if that granularity matters later. What matters for the checkpoint: real events were captured on both target kernels, with zero fallback to a degraded probe path.

Notable en route to this result: 24.04's kernel build (`6.17.0-1020-azure`) was new enough that Ubuntu's `linux-tools-<kernel>` apt package didn't exist yet, and unauthenticated `api.github.com` calls hit the 60/req-hour cap under the 2-job matrix. Both are hosted-runner environment realities, not eBPF limitations — see git history on this branch for the fixes (static bpftool binary instead of apt; authenticated API lookup).

Source: `phase0-evidence-*` artifacts from `.github/workflows/phase0-spike.yml`, run `077f419`.

## CP-0.2 — overhead

| | Median wall clock |
|---|---|
| Baseline (no probe) | 1.04s |
| Instrumented | 1.04s |
| **Overhead** | **0.0%** |

N=30 pairs, attach-once (probe loaded once, stays attached across all 30 `npm ci` calls — matching how BuildLens actually deploys). **PASS**, well inside the ≤5% target.

Two earlier passes (7.7% at N=5 on a tiny fixture, 7.4% at N=30) both measured a benchmark artifact, not real overhead: the probe was being reloaded and reattached before every single `npm ci` call, paying the one-time BPF verifier + attach cost 30 times over. Fixing the benchmark to attach once — the real deployment pattern — collapsed the number to 0.0%.

**Caveat that belongs in front of anyone who reads this number later:** this measures the *mechanism* (BPF load, attach-once, ring buffer read loop) with a single exec-only probe. It proves the foundation is free. It does not yet measure Phase 1's real probe set — file_open (with a kernel-side path filter to control event volume on a build doing millions of `openat` calls), tcp_connect, DNS, SNI parsing, byte accounting, and the userspace taint correlator all add real per-event work that this number says nothing about. Re-run this benchmark, or its Phase 1 equivalent (NFR-1 in PRD.md), once those probes exist — don't let "0% overhead" get cited past what it actually proved.

Source: `phase0-overhead` artifact, `out/overhead.txt`, run `077f419`.

## CP-0.3 — differentiation

Not started. Screenshots and answers go here once `CP-0.3-CHECKLIST.md` is done — the one checkpoint here that isn't a workflow output, it's a judgment call against Harden-Runner's actual UI.

## Recommendation

CP-0.1 and CP-0.2 are both resolved, cleanly, with numbers that survived being second-guessed twice. The mechanism BuildLens depends on works on GitHub-hosted runners, on both target kernels, with effectively zero overhead for the minimal probe tested. What's carried forward into Phase 1, concretely: budget time for hosted-runner environment quirks that have nothing to do with eBPF itself (package availability lagging fresh kernel images, API rate limits under parallel jobs) — none of these are blockers, but Phase 0 already spent real debugging cycles on exactly this category and Phase 1's kernel CI matrix (M1.1) should expect more of it. The 0% overhead number is real but narrow — re-establish it against the full Phase 1 probe set before repeating it to a design partner. CP-0.3 is the only open item before the GO/NO-GO box above can be checked.

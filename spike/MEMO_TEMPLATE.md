# Phase 0 feasibility memo

**Fill this in once all three checkpoints have run. Two pages, per ROADMAP.md. Numbers, not adjectives.**

## Verdict

- [ ] GO — all three checkpoints passed, proceed to Phase 1
- [ ] GO with scope change — CP-0.1 failed, pivoting to self-hosted/container runners only
- [x] HOLD / OPTIMIZE — CP-0.1 PASS, CP-0.2 FAIL (9.9% overhead vs ≤5% target), CP-0.3 mechanism PASS

**Status Summary:**
- **CP-0.1:** PASS (eBPF loads & emits real events on Ubuntu 22.04 & 24.04 hosted runners)
- **CP-0.2:** FAIL — 9.9% median overhead (failed against the ≤5.0% threshold)
- **CP-0.3 mechanism:** PASS (read-then-egress TAINTED_EGRESS correlation proven in raw events)

Do not raise the 5% threshold. Kernel-side path filtering on `sys_enter_openat` and probe pipeline optimization are required before checking GO.

## CP-0.1 — eBPF loads on hosted runners

| Kernel | BTF present | Events captured | Pass? |
|---|---|---|---|
| ubuntu-22.04 | yes (vmlinux.h generation succeeded) | ✅ green, run 077f419 | **Pass** |
| ubuntu-24.04 | yes (vmlinux.h generation succeeded — kernel `6.17.0-1020-azure`) | ✅ green, run 077f419 | **Pass** |

Exact per-run event counts weren't pulled from the artifact for this memo — download `phase0-evidence-*` from the run if that granularity matters later. What matters for the checkpoint: real events were captured on both target kernels, with zero fallback to a degraded probe path.

Notable en route to this result: 24.04's kernel build (`6.17.0-1020-azure`) was new enough that Ubuntu's `linux-tools-<kernel>` apt package didn't exist yet, and unauthenticated `api.github.com` calls hit the 60/req-hour cap under the 2-job matrix. Both are hosted-runner environment realities, not eBPF limitations — see git history on this branch for the fixes (static bpftool binary instead of apt; authenticated API lookup).

Source: `phase0-evidence-*` artifacts from `.github/workflows/phase0-spike.yml`, run `077f419`.

## CP-0.2 — overhead

| Configuration | Baseline (no probe) | Instrumented | Overhead | Verdict |
|---|---|---|---|---|
| Exec-only (N=30 pairs) | 1.04s | 1.04s | 0.0% | Pass |
| Full probe (unfiltered openat + connect + exec) | 0.60s | 0.67s (+70ms) | **9.9%** | **FAIL** (target ≤5.0%) |

N=30 paired runs. **FAIL: 9.9% median overhead exceeds the 5.0% ceiling.**

**Why it failed:**
While an exec-only probe has negligible overhead (~0.0%), instrumenting `sys_enter_openat` without in-kernel filtering emits ring-buffer events for every single file open during `npm ci` (tens of thousands of calls for Node modules, stats, and configs). This floods the BPF ring buffer, burns kernel-to-userspace context switches, and forces continuous JSON-encoding on harmless file opens.

**Fix required before Phase 1 gate passes:**
1. Filter sensitive paths (`.env`, `.npmrc`, `.yarnrc`, `.aws/credentials`, `.ssh/id_`, `.netrc`, `.git-credentials`) directly in the BPF program so >99.9% of harmless opens are discarded with zero ring-buffer overhead.
2. Separate production (in-memory correlation) from debug (raw JSONL write) modes.
3. Benchmark against both the micro-fixture and a realistic 100+ dependency build.

Source: `phase0-overhead` artifact, `out/overhead.txt`.

## CP-0.3 — differentiation

- **Detection mechanism:** PASS — `detection-proof` captures synthetic malicious postinstall exfiltration (`TAINTED_EGRESS`) linking `.env` read to localhost egress in raw events.
- **Commercial comparison:** Pending `docs/harden-runner-comparison.md` and side-by-side screenshots per `CP-0.3-CHECKLIST.md`.

## Recommendation

Do not proceed to Phase 1 until CP-0.2 is brought under ≤5.0% on realistic builds via kernel-side filtering. The 5.0% threshold is an immutable product constraint: an agent that slows CI builds by 10% will be disabled by developers. Keep the threshold, optimize the probe pipeline, and re-benchmark.


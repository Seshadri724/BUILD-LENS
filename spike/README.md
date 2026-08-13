# Phase 0 spike

Throwaway code that answers one question: **does eBPF actually work on GitHub-hosted runners, cheaply enough to build a product on?** See [ROADMAP.md — Phase 0](../ROADMAP.md#phase-0--feasibility-spike-3-weeks) for the full brief.

Nothing here is production code. It gets deleted or rewritten once Phase 0 concludes. No abstractions, no test framework beyond the pass/fail checks the workflow already does.

**This never runs on a developer's machine.** eBPF probing needs kernel privileges and modifies kernel-level state (loading programs, attaching tracepoints); the only place that's appropriate to do it is an ephemeral GitHub-hosted runner that gets destroyed after the job — never a real laptop. `.github/workflows/phase0-spike.yml` is the only place this code executes.

## What it does

`spike/bpf/exec.bpf.c` — one BPF program, attached to `sched_process_exec`. Every time any process execs on the runner, it records PID, PPID, and command name to a ring buffer. That's the entire probe surface for Phase 0 — enough to prove the mechanism works, not a real detector.

`spike/cmd/spike/main.go` — loads that program, reads the ring buffer for a fixed duration, writes what it saw to a JSONL file. `sudo ./spike -duration 30s -out events.jsonl`.

`spike/fixtures/sample-node-app/` — a throwaway `package.json` (`express`, a realistic-sized real dependency tree) used only to produce a real `npm ci` to measure overhead against.

## How the checkpoints get their answers

| Checkpoint | Where it's answered |
|---|---|
| **CP-0.1** — eBPF loads on hosted runners | `kernel-matrix` job in the workflow. Fails the build if zero events are captured on either `ubuntu-22.04` or `ubuntu-24.04`. |
| **CP-0.2** — overhead ≤5% | `overhead-benchmark` job. Times `npm ci` 30 times with the probe attached and 30 times without, compares medians, fails the build above 5%. First pass ran 5 samples against an `express`-only fixture that installed in ~0.5s — measured 7.7%, but at that scale a one-time fixed cost (BPF load + attach) dominates the percentage rather than steady-state overhead. Fixture now installs a handful of real packages instead of one, and sample count matches the ROADMAP's stated target for a number worth trusting. |
| **CP-0.3** — differentiation is visible | Not automatable — it's a side-by-side product comparison. See [`CP-0.3-CHECKLIST.md`](CP-0.3-CHECKLIST.md). |

## Running it

Don't run it locally. Push to a branch, or use `workflow_dispatch` from the Actions tab. Download the `phase0-evidence-*` and `phase0-overhead` artifacts when it finishes — they're the raw material for `MEMO_TEMPLATE.md`.

## What's deliberately missing

No file-open probe, no network probe, no correlation, no policy. Phase 0 asks "does the mechanism work at all," not "does the product work." Building more than that here is exactly the over-engineering this repo's ponytail convention exists to catch — the real probes belong in Phase 1, once CP-0.1–0.3 have actually passed.

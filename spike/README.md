# Phase 0 spike

Throwaway code that answers one question: **does eBPF actually work on GitHub-hosted runners, cheaply enough to build a product on?** See [ROADMAP.md — Phase 0](../ROADMAP.md#phase-0--feasibility-spike-3-weeks) for the full brief.

Nothing here is production code. It gets deleted or rewritten once Phase 0 concludes. No abstractions, no test framework beyond the pass/fail checks the workflow already does.

**This never runs on a developer's machine.** eBPF probing needs kernel privileges and modifies kernel-level state (loading programs, attaching tracepoints); the only place that's appropriate to do it is an ephemeral GitHub-hosted runner that gets destroyed after the job — never a real laptop. `.github/workflows/phase0-spike.yml` is the only place this code executes.

## What it does

`spike/bpf/probes.bpf.c` — three BPF programs sharing one tagged event struct and one ring buffer:
- `sched_process_exec` — every process exec (PID, PPID, comm)
- `sys_enter_openat` — every file open (adds the path)
- `tcp_v4_connect` (kprobe + kretprobe) — every outbound connect (adds destination IP:port)

That's the entire probe surface for Phase 0 — enough to prove the mechanism and the read-then-egress correlation work, not a real detector. No kernel-side path filtering, no DNS/SNI, no policy, no ancestor-walk taint graph — those are Phase 1 (ARCHITECTURE.md §3).

`spike/cmd/spike/main.go` — loads all three programs, reads the ring buffer for a fixed duration, and does the simplest possible correlation: if a PID opens a path containing `.env` and that same PID later connects out, it emits a `TAINTED_EGRESS` record naming the process, the file, the destination, and the elapsed milliseconds. Writes everything to a JSONL file. `sudo ./spike -duration 30s -out events.jsonl`.

`spike/fixtures/sample-node-app/` — a throwaway `package.json` (five common real packages) used only to produce a real `npm ci` to measure overhead against.

`spike/fixtures/malicious-postinstall/` + `spike/fixtures/detection-demo/` + `spike/fixtures/local_listener.py` — the M0.5 detection-proof scenario. A synthetic `postinstall` script (never published, installed only as a local `file:` dependency) reads a fake `.env` and POSTs it to a listener on `127.0.0.1` — nothing leaves the runner at any point. This exists to prove the correlation is real, for CP-0.3.

## How the checkpoints get their answers

| Checkpoint | Where it's answered |
|---|---|
| **CP-0.1** — eBPF loads on hosted runners | `kernel-matrix` job. Fails the build if zero events are captured on either `ubuntu-22.04` or `ubuntu-24.04`. |
| **CP-0.2** — overhead ≤5% | `overhead-benchmark` job. Times `npm ci` 30 times with the probe attached once for the whole batch, vs. 30 times with no probe, compares medians, fails the build above 5%. Two earlier passes (7.7% at N=5 on a tiny fixture, then 7.4% at N=30) both reattached the probe fresh before every single `npm ci` call — paying the one-time BPF load/attach cost 30 times instead of once, which a real deployment never does (the agent attaches once per job, per [ARCHITECTURE.md](../ARCHITECTURE.md#3-agent-architecture-bl-agent)). Fixed to attach once and stay running across the batch. |
| **CP-0.3** — differentiation is visible | Half-automated. `detection-proof` job (M0.5) produces BuildLens's side of the comparison — a real `TAINTED_EGRESS` correlation from raw kernel events. The Harden-Runner side, and the judgment call itself, stay manual — see [`CP-0.3-CHECKLIST.md`](CP-0.3-CHECKLIST.md). |

## Running it

Don't run it locally. Push to a branch, or use `workflow_dispatch` from the Actions tab. Download the `phase0-evidence-*`, `phase0-detection-proof`, and `phase0-overhead` artifacts when it finishes — they're the raw material for `MEMO_TEMPLATE.md`.

## What's deliberately missing

Kernel-side path filtering (every `openat` gets emitted and filtered in userspace — fine at spike volume, would flood the ring buffer on a real `npm ci` with a full `node_modules` tree), DNS/SNI correlation, a real sensitivity policy (just a `.env` substring match), ancestor-walk taint propagation (exact-PID only), and any concept of a policy engine. Phase 0 asks "does the mechanism and the core correlation work at all," not "does the product work." Building more than that here is exactly the over-engineering this repo's ponytail convention exists to catch — the rest belongs in Phase 1, once CP-0.1–0.3 have actually passed.

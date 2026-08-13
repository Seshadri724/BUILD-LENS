# Next steps

**State as of now:** first real run failed both kernel-matrix jobs — a missing `#include <bpf/bpf_core_read.h>` in `exec.bpf.c`, and `bpftool` not found on the `6.17.0-1020-azure` runner because apt's kernel-matched package doesn't exist for it yet. Both are fixed and committed locally (`f05726b`, `c1770de`), **not yet pushed.**

## 0. Push the fix — this is the actual next action

```bash
git push
```

That re-triggers `phase0-spike.yml` on the fixed code. `overhead-benchmark` never ran last time (`needs: kernel-matrix`, which failed) — this is the first run where it gets a chance to.

## 1. Read the run
- [ ] Download both artifact sets (`phase0-evidence-*`, `phase0-overhead`) — they're the raw material for the memo in step 3.

If it hasn't run at all, trigger it manually: Actions tab → `phase0-spike` → **Run workflow**.

*(Optional, for next time: `gh auth login` locally so I can pull run status straight into this session instead of you relayering it back to me.)*

## 2. If a job failed, fix before measuring anything else

| Failure | Likely cause | Fix |
|---|---|---|
| `bpftool: command not found` | Hosted image dropped `linux-tools-<kernel>` for that image version | Pin an explicit bpftool install step (`apt-get install -y bpftool` without the kernel-specific package) |
| `vmlinux.h` include errors during `go generate` | BTF disabled on that image, or clang/libbpf-dev version mismatch | Check `btf_present` in `out/kernel-info-*.txt` first — if `no`, that itself is the CP-0.1 answer for that kernel, not a bug |
| Zero events captured | Tracepoint attached but the `/bin/true` loop ran before the reader was ready | Increase the sleep before generating exec traffic, or move event generation after a short fixed delay |
| `overhead-benchmark` fails on `/usr/bin/time` | Already fixed in the workflow (`time` package added to apt install) — if still failing, check the install step actually ran before use | — |

Push the fix, let it re-run, repeat until both jobs pass cleanly.

## 3. Fill in the feasibility memo

Once both jobs are green: open [`spike/MEMO_TEMPLATE.md`](spike/MEMO_TEMPLATE.md) and fill in the actual numbers from the artifacts — kernel/BTF table, overhead median, the honest CP-0.1/CP-0.2 verdicts. Don't round favorably; this document exists to be trusted later.

## 4. Do CP-0.3 — the one step that isn't automatable

Follow [`spike/CP-0.3-CHECKLIST.md`](spike/CP-0.3-CHECKLIST.md):

- [ ] Pick one real repo with a non-trivial `postinstall` script
- [ ] Install [Harden-Runner](https://github.com/step-security/harden-runner) on it, screenshot the output
- [ ] Run the spike probes against the same commit, screenshot the output
- [ ] Answer honestly: would a skeptical AppSec engineer see why the second screenshot is worth paying for?

Paste both screenshots and the answer into the memo.

## 5. Make the go/no-go call

Check the box in `MEMO_TEMPLATE.md` that matches what actually happened:

| Outcome | What it means |
|---|---|
| All three pass | Proceed to **Phase 1** per [ROADMAP.md](ROADMAP.md#phase-1--observe-only-mvp-8-weeks) |
| CP-0.1 fails on hosted runners | Pivot to self-hosted/container runners only — re-run the market sizing in [PRD.md](PRD.md) before writing more code, this roughly halves the addressable market |
| CP-0.2 fails (overhead >5%) | Drop probe surface (byte accounting, open-call sampling), re-measure — don't proceed on an unmeasured guess that it'll be fine later |
| CP-0.3 is weak | Stop and rethink positioning per [STRATEGY.md](STRATEGY.md#1-the-thesis) before any production code — this is the "is it even a business" checkpoint |

## 6. If it's a GO — starting Phase 1 is not "write the real agent" on day one

The temptation is to jump straight to file-open and network probes. Don't — start with the two things that are cheap now and expensive to retrofit, per [ROADMAP.md M1.8](ROADMAP.md#phase-1--observe-only-mvp-8-weeks):

1. **Kernel CI matrix** — same idea as this spike's `kernel-matrix` job, but as a standing gate on every agent PR, not a one-off.
2. **Replay-ready event schema** (M1.8) — deterministic scoring, stable package identity `(ecosystem, name, version, integrity_hash)`, and a type-level split between aggregatable and repo-identifying fields. Three days of work now; a rewrite in Phase 3 if skipped, per [STRATEGY.md §6](STRATEGY.md#6-the-one-change-this-forces-on-the-engineering-plan).

Then the real probes (M1.2–M1.5): file_open with the LSM/tracepoint fallback, tcp_connect + DNS + SNI, process tree + package attribution, the taint correlator.

## What I won't do without you

- Trigger the workflow run or push further commits — that's a visible action on your GitHub account, your call on timing
- Authenticate `gh` or any GitHub credential on this machine
- Decide the go/no-go call itself — that's yours to make once the numbers are in front of you, not mine to infer

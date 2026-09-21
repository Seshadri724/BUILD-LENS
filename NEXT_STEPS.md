# Next product-ready steps

Phase 1 **output path** is in the tree: `pkg/correlate`, `cmd/bl-agent`, `action.yml`. The kernel agent is still the spike.

## You — this week (product, not more docs)

1. **Push this branch** and confirm `agent-ci` is green (correlator + fixture Action).
2. **CP-0.3** — still the business gate. [spike/CP-0.3-CHECKLIST.md](spike/CP-0.3-CHECKLIST.md): Harden-Runner screenshot vs detection-proof / scored manifest. If a skeptical AppSec engineer would not pay for the second picture, do not staff more probes.
3. **Dogfood:** on any Linux Actions job, run the spike, then:
   `go run ./cmd/bl-agent score -in events.jsonl -out buildlens-manifest.json -sarif buildlens.sarif`
4. **One design partner conversation** with that manifest, not the PRD.

## Engineering queue (in order)

| Order | What | Done when |
|---|---|---|
| 1 | Action `main` starts spike (or fail-open), `post` runs `bl-agent score` | Partner YAML is two lines, no manual JSONL |
| 2 | npm/pip package identity on the finding (`aggregatable.package`) | Finding names `pkg@version`, not `unknown` |
| 3 | Ancestor taint (child connect after parent `.env` read) | Real postinstall trees, not exact-PID only |
| 4 | DNS + SNI + kernel-side path filter | Hostnames not raw IPs; overhead re-benchmarked |
| 5 | Check run + SARIF upload (`security-events: write`) | Visible on the PR without opening artifacts |

Do not start: dashboard, control plane, detonation farm, enforce/block.

## Commands

```bash
go test ./pkg/... ./cmd/...
go run ./cmd/bl-agent score -in testdata/corpus/tainted-env-post/events.jsonl -out buildlens-manifest.json -sarif buildlens.sarif
```

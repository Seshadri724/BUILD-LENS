# Product quickstart (Phase 1 output path)

The kernel probe is still the Phase 0 spike. What you can ship today is the **score → manifest → SARIF** loop.

## Local (no eBPF)

```bash
go test ./pkg/... ./cmd/...
go run ./cmd/bl-agent score \
  -in testdata/corpus/tainted-env-post/events.jsonl \
  -out buildlens-manifest.json \
  -sarif buildlens.sarif
```

You should see `TAINTED_EGRESS` in the manifest.

## GitHub Action (this repo)

```yaml
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: Seshadri724/BUILD-LENS@v0.1.0
      - uses: actions/checkout@v5
      - run: npm ci && npm test
```

The action records live kernel events for the whole job and scores them in its post step. If the agent can't load (see the runner requirements in the [README](README.md#runner-requirements)), it warns and **exits 0** (fail-open).

## Spike JSONL → product finding

On a Linux runner, after `sudo ./bin/spike -out events.jsonl`:

```bash
go run ./cmd/bl-agent score -in events.jsonl -out buildlens-manifest.json -sarif buildlens.sarif
```

Package name will be `unknown` until attribution ships. The finding still names process, path, dest, and elapsed_ms.

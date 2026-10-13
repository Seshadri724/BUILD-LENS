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
      - uses: Seshadri724/BUILD-LENS@v0.2.0
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

## From observe to audit

Audit mode turns clean runs into a reviewable egress allowlist — the stepping
stone to block-mode enforcement (Phase 2).

```yaml
- uses: Seshadri724/BUILD-LENS@v0
  with:
    mode: audit
```

1. On every **clean** run, the post step appends that run's egress observations
   (host, package, counts — never argv or paths) to
   `.buildlens/observed.jsonl` in your workspace. Commit the file.
2. After 5+ clean runs on your default branch, generate the policy:
   ```bash
   go run ./cmd/bl-agent policy -in .buildlens/observed.jsonl -out .buildlens/policy.yml
   ```
   `policy` also accepts raw event files and merges both kinds:
   `bl-agent policy -in run1.jsonl,run2.jsonl -out .buildlens/policy.yml`.
3. Review `.buildlens/policy.yml` — **observed is not approved**, remove what
   you don't recognize — and open it as a PR.

Rules: the ledger is append-only (re-merging ledgers double-counts runs, and
never feed `policy.yml` back in), and audit mode never breaks builds — it only
writes the ledger. Extra install hosts (binary mirrors) go in `allow-hosts` so
they don't become findings first.

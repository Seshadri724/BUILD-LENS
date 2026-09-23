# BuildLens vs Harden-Runner — CP-0.3 results

**Fill this in from a real `cp03-compare` run. Paste real output only; no projected or "target" output.**

## Setup

- Workflow: [`.github/workflows/cp03-compare.yml`](../.github/workflows/cp03-compare.yml), run manually (Actions → cp03-compare → Run workflow). Repo must be public for Harden-Runner's free tier.
- Build: `npm ci` of [`spike/fixtures/cp03-app`](../spike/fixtures/cp03-app): 60+ real npm dependencies plus one compromised dependency, `telemetry-helper@2.4.1`, whose `postinstall` reads the project `.env` (dummy values) and POSTs it to `httpbin.org`.
- Same runner image (`ubuntu-22.04`), same lockfile, three jobs: baseline / BuildLens / Harden-Runner.

Run URL: `<paste>`  ·  Date: `<paste>`  ·  Commit: `<paste>`

## What each tool reported

### Harden-Runner (audit mode)

Screenshot: `spike/evidence/cp-0.3/harden-runner.png` (the insights page linked from the job summary)

```text
<paste what it showed for the npm ci step: processes, destinations, anything about telemetry-helper or .env>
```

### BuildLens

Screenshot: `spike/evidence/cp-0.3/buildlens.png` (the job's step summary)

```text
<paste the finding: package, lifecycle, sensitive file, process chain, destination, bytes sent, elapsed>
```

## Side by side

| Question an AppSec engineer asks | Harden-Runner | BuildLens |
|---|---|---|
| Did something leave the runner, and to where? | | |
| Hostname or only IP? | | |
| Which dependency did it? | | |
| Did it touch a secret first? Which file? | | |
| How much data went out? | | |
| Would I know what to remove from package.json? | | |
| Noise: other alerts in the same run | | |

`npm ci` wall time (single run each, noisy; CP-0.2 is the real overhead gate): baseline `__ ms` · BuildLens `__ ms` · Harden-Runner `__ ms`

## Known BuildLens gaps visible in this comparison

- Destinations are IPs. Harden-Runner shows hostnames; BuildLens does not resolve DNS or read TLS SNI yet.
- "Sensitive file" means a successful `openat`, not proof the bytes were read. "Bytes sent" is the process's total to that destination, not proof it was the file's contents.
- Observe only. Harden-Runner can block egress; BuildLens cannot.

## CP-0.3 answers (from CP-0.3-CHECKLIST.md step 4)

1. What did Harden-Runner's output tell you?
2. What did BuildLens's output tell you that Harden-Runner's didn't?
3. Would a skeptical AppSec engineer look at both and immediately see why the second is worth paying for? **Yes / No**, and who said so:

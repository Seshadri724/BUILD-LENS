# BuildLens vs Harden-Runner — CP-0.3 results

**Fill this in from a real `cp03-compare` run. Paste real output only; no projected or "target" output.**

## Setup

- Workflow: [`.github/workflows/cp03-compare.yml`](.github/workflows/cp03-compare.yml), runs on push to `v2` when the fixture or workflow changes, or manually. Repo must be public for Harden-Runner's free tier.
- Build: `npm ci` of [`spike/fixtures/cp03-app`](spike/fixtures/cp03-app): 60+ real npm dependencies plus one compromised dependency, `telemetry-helper@2.4.1`, whose `postinstall` reads the project `.env` (dummy values) and POSTs it to `httpbin.org`.
- Same runner image (`ubuntu-22.04`), same lockfile, three jobs: baseline / BuildLens / Harden-Runner.

Run: [cp03-compare #1](https://github.com/Seshadri724/BUILD-LENS/actions/runs/35874992597)  ·  Date: 2026-09-23  ·  Commit: `07c43b5`  ·  Harden-Runner v2.21.1 (agent v0.16.3), audit mode, first run (no baseline)

## What each tool reported

### Harden-Runner (audit mode)

Screenshot: `spike/evidence/cp-0.3/harden-runner.png`

Source: the agent log in the job's "Post Harden-Runner" step. The [insights dashboard](https://app.stepsecurity.io/github/Seshadri724/BUILD-LENS/actions/runs/35874992597) showed 0 network events and 0 detections ~11 minutes after the run, although the agent log recorded the traffic below. Treat that as ingestion lag or onboarding, not a Harden-Runner blind spot; re-check before showing this to anyone.

Outbound calls during the job (from the agent log):

```text
github.com.                  140.82.114.4:443     git-remote-http  pid 2501   (checkout)
results-receiver.actions...  140.82.112.21:443    Runner.Worker    pid 1853
api.github.com.              140.82.113.6:443     node             pid 2515   (setup-node)
release-assets.github...     185.199.109.133:443  node             pid 2515   (setup-node)
registry.npmjs.org.          104.16.1.34:443      node             pid 2554   (npm ci)
httpbin.org.                 100.61.72.171:443    node             pid 2567   (npm ci)  <- the exfiltration
```

- The exfiltration is one line among normal traffic: hostname, IP, `node`, a pid. No detection fired: httpbin.org is not on its blocklist, and with no baseline yet nothing counts as anomalous.
- Nothing links pid 2567 to `telemetry-helper`, and nothing says a secret was touched. Its file monitor reported writes to source files (`.git/config`), not reads of `.env`.
- It also resolved every hostname and checked destinations against a blocklist of known C2 hosts from recent npm/PyPI compromises.

### BuildLens

Screenshot: `spike/evidence/cp-0.3/buildlens.png` (the job's step summary)

Source: the job's "Post BuildLens" step log.

```text
BuildLens — findings, 1 findings, 1 unique dest hosts (ruleset 1.0.0)
  • [critical] TAINTED_EGRESS | pkg: telemetry-helper | file: /home/runner/work/BUILD-LENS/BUILD-LENS/spike/fixtures/cp03-app/.env | dest: 107.21.166.194 | chain: bash → npm → sh → node
```

- One finding and no other alerts across the 174-package install. It names the package, the secret file and the process chain.
- The destination is an IP; nothing says it is httpbin.org. (The IPs differ from Harden-Runner's because each tool ran on its own runner and got its own DNS answer.)
- Bytes sent, elapsed time and lifecycle are in the step summary, not this log line: `<copy from the summary>`.

## Side by side

| Question an AppSec engineer asks | Harden-Runner | BuildLens |
|---|---|---|
| Did something leave the runner, and to where? | Yes: every destination, including httpbin.org | Only the destination linked to a secret: 107.21.166.194 |
| Hostname or only IP? | **Hostname** | IP only |
| Which dependency did it? | No: `node`, pid 2567 | **`telemetry-helper`** |
| Did it touch a secret first? Which file? | No | **Yes: `cp03-app/.env`** |
| How much data went out? | No | Step summary: `<n>` bytes |
| Would I know what to remove from package.json? | No | Yes |
| Raised as an alert on the first run? | No, a log line; its anomaly detection needs a baseline from earlier runs | **Yes, critical** |
| Noise: other alerts in the same run | None | None |
| Can it block the egress? | Yes (block mode) | No |
| Catches known-bad destinations with no secret involved? | Yes (C2 blocklist) | No |

`npm ci` wall time (single run each, noisy; CP-0.2 is the real overhead gate): baseline `__ ms` · BuildLens `__ ms` · Harden-Runner `__ ms`, from each job's step summary. npm itself reported "added 174 packages in 1s" with BuildLens and "in 2s" with Harden-Runner.

## Known BuildLens gaps visible in this comparison

- Destinations are IPs. Harden-Runner shows hostnames; BuildLens does not resolve DNS or read TLS SNI yet.
- "Sensitive file" means a successful `openat`, not proof the bytes were read. "Bytes sent" is the process's total to that destination, not proof it was the file's contents.
- Observe only. Harden-Runner can block egress; BuildLens cannot.

## CP-0.3 answers (from CP-0.3-CHECKLIST.md step 4)

1. **What did Harden-Runner's output tell you?** That `node` (pid 2567) called httpbin.org:443 during `npm ci`, next to the expected GitHub and npm registry traffic. On this first run it was a log entry, not an alert.
2. **What did BuildLens's output tell you that Harden-Runner's didn't?** That the call came from `telemetry-helper`'s install script, that the same process had just opened the project's `.env`, and that this is a critical finding, with no baseline and no other alerts. What it didn't tell you: the hostname.
3. **Would a skeptical AppSec engineer see why the second is worth paying for?** Not answered yet. This needs someone outside the project; record their exact words: ___

**Open questions for the reviewer and the next run:**
- From the second run on, Harden-Runner's baseline would likely flag httpbin.org as a new destination, with its hostname. Is "first run, names the package and the secret" enough on its own?
- The stronger case for taint tracking is exfiltration to a host that *is* in the baseline (a GitHub gist, the npm registry, a common CDN), which destination baselining can't catch. Test that next if the reviewer is lukewarm.

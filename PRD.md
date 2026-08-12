# BuildLens — Product Requirements Document

**Status:** Draft v1.0
**Owner:** Product / Founding Engineering
**Last updated:** 2026-08-11

---

## 1. Summary

BuildLens is a CI/CD runtime sentinel. It runs as the first step of a build job, attaches eBPF probes to the runner kernel, and produces a per-run ledger answering one question:

> **Which process, spawned by which dependency, read which sensitive file, and then sent how many bytes to where?**

It does this without TLS interception, without a proxy, and without modifying the build. Observe-only by default; policy enforcement (connect-time block) is opt-in per repository.

---

## 2. Problem

### 2.1 The attack surface

A modern CI job executes thousands of lines of third-party code with full access to:

- Cloud credentials (OIDC tokens, `AWS_*`, `GITHUB_TOKEN`)
- Source code, including unreleased code
- SSH deploy keys, `.npmrc`/`.pypirc` registry tokens, `.env` files
- Unrestricted outbound network access

`npm install` alone runs arbitrary `preinstall`/`postinstall`/`prepare` scripts from every package in the tree. `pip install` runs `setup.py`. Maven/Gradle run plugin code. None of this is sandboxed, and none of it is observed.

### 2.2 Why existing controls miss it

| Control | Why it misses runtime exfiltration |
|---|---|
| SCA / dependency scanning (Snyk, Dependabot, Trivy) | Matches known CVEs against a manifest. A brand-new malicious package has no CVE. Catches *known vulnerable*, not *actively malicious*. |
| SAST | Analyzes first-party source. Third-party `postinstall` scripts are not scanned. |
| Secret scanning | Detects secrets *committed to the repo*. Does nothing about secrets *read at runtime and shipped out*. |
| Network egress allowlists (firewall, proxy) | Blocks by destination only. Cannot say *which process* or *why*. Generates alert fatigue: legitimate builds hit hundreds of hosts. |
| EDR / CWPP | Built for long-lived hosts. Ephemeral 4-minute runners are gone before an agent enrolls or a baseline forms. |
| TLS-terminating proxies (MITM) | Requires injecting a CA into every language runtime's trust store. Breaks pinned clients, breaks signed-artifact verification, and creates a new secret-bearing chokepoint. Teams reject it. |

### 2.3 Evidence this is real

- **Codecov (2021)** — a modified bash uploader exfiltrated CI environment variables from thousands of pipelines for two months before discovery.
- **`event-stream` / `ua-parser-js` / `node-ipc`** — npm packages with malicious payloads in transitive dependency trees.
- **PyPI typosquats** — recurring campaigns whose `setup.py` posts environment variables to a webhook on install.
- **`xz-utils` (CVE-2024-3094)** — build-time-only backdoor injected during `make`, invisible to source review.

The common shape: **code that reads a file it should not need, then makes a network call it never made before.** That signal is available at the kernel and nowhere else.

### 2.4 Problem statement

> DevSecOps teams cannot see what third-party build code does at runtime. They have inventory (what packages are present) but no behavior (what those packages did). When a supply chain compromise happens, the mean time to detect is measured in weeks, and the blast radius is every secret the pipeline could read.

---

## 3. Goals

### 3.1 Product goals

| # | Goal | Success metric |
|---|---|---|
| G1 | Detect secret-read-then-egress within a single build run | ≥95% detection on the red-team corpus (§9), ≤1 false positive per 100 clean runs |
| G2 | Attribute every outbound connection to a process and its dependency ancestor | ≥90% of connections resolved to a named package or first-party step |
| G3 | Stay cheap enough to run on every PR | ≤5% wall-clock overhead, ≤150 MB RSS, ≤8s install time |
| G4 | Require no build modification | Single `uses:` step; zero changes to `package.json`, Dockerfile, or build commands |
| G5 | Turn detection into prevention | Repos can move observe → enforce with a generated policy, without hand-authoring allowlists |

### 3.2 Business goals

- 200 repos under active monitoring within 6 months of GA.
- 3 design partners in Phase 1, each with ≥50 repos.
- Land-and-expand: free for public repos and ≤3 private repos; per-repo/month above that.

### 3.3 Non-goals (v1)

- **Not** a TLS-decrypting proxy. We never see payload contents. Ever. This is a permanent architectural commitment, not a v1 limitation.
- **Not** a dependency scanner. We do not maintain a CVE database or a malware signature feed. We complement SCA; we do not replace it.
- **Not** a general-purpose runtime CWPP. We do not target production workloads, long-lived servers, or Kubernetes application pods.
- **Not** a secret manager or vault.
- **No Windows or macOS runner support in v1.** eBPF is Linux-only; macOS Endpoint Security Framework requires a notarized entitlement and a separate agent. Deferred to Phase 4 pending demand.
- **No build sandboxing / seccomp jailing.** We observe and optionally block network egress. We do not restrict filesystem or syscall access — that breaks builds, and breaking builds kills adoption.
- **Not** an SBOM generator. We consume SBOMs if present; we do not produce them.

---

## 4. Target customer

### 4.1 Primary persona — "Priya, AppSec Engineer"

- Owns supply chain security for 400+ repos at a 1,200-person fintech.
- Has SCA (Snyk) and secret scanning (GitHub Advanced Security). Both are noisy and neither answers "did anything actually happen?"
- Was asked by the CISO after the last public npm incident: *"Were we affected?"* Could not answer.
- **Buying trigger:** a board-level supply chain question she cannot answer with current tooling.
- **Budget:** yes — dedicated AppSec tooling line, $50k–250k/yr.

### 4.2 Secondary persona — "Marcus, Platform/DevEx Lead"

- Owns the CI fleet: 200 self-hosted runners plus GitHub-hosted.
- Will veto anything that slows builds or breaks them. **He is the real gatekeeper.**
- **Buying trigger:** none, personally. He needs to be neutralized, not sold. Every performance and reliability requirement in §6 exists for him.

### 4.3 Anti-persona

Solo developers and small OSS projects. High support cost, no budget. Serve them with a free tier for goodwill and pipeline, but do not build features for them.

---

## 5. Competitive positioning

| Competitor | What they do | Where we win |
|---|---|---|
| **StepSecurity Harden-Runner** | Closest competitor. eBPF egress monitoring + allowlist for GitHub Actions. Real product, real traction. | They answer *"what destinations were contacted."* We answer *"what data-bearing process contacted them."* File→process→socket lineage and dependency attribution are our wedge, not egress monitoring itself. |
| **Datadog CI Visibility** | Pipeline observability and flaky-test analytics. | Performance telemetry, not a security control. No file/network correlation, no policy enforcement. |
| **Aqua Tracee / Falco** | Open-source eBPF runtime detection. Excellent primitives. | Generic rule engines with no CI context. No concept of a "run", a dependency tree, or a PR. Require an expert to operate. We are opinionated and pre-tuned for build runners. |
| **Chainguard / Sigstore** | Provenance, signing, hardened base images. | Attests *what was built*, not *what the build did*. Complementary — we can consume and enrich attestations. |
| **Cloud-native firewall / egress proxy** | Destination allowlists. | Network-layer only, no process identity, no PR-level feedback loop. |

**One-line positioning:** *Harden-Runner tells you a build called an unknown host. BuildLens tells you which npm package read your `.env` thirty milliseconds before it did.*

**Honest risk:** Harden-Runner is well-established with a generous free tier. Our differentiation must be demonstrable in the first run, not in a datasheet. See Phase 0 checkpoint CP-0.3.

---

## 6. Requirements

### 6.1 Functional

**FR-1 — Process lineage.** Capture every `execve` with PID, PPID, argv, executable path, cgroup, and start time. Maintain a process tree for the run lifetime, resilient to PID reuse (key on PID + boot-relative start time).

**FR-2 — Dependency attribution.** Map a process to the package that spawned it by walking the ancestor chain and matching against package-manager context (npm lifecycle env vars, cwd inside `node_modules/<pkg>`, pip build temp dirs). Emit `attribution_confidence` ∈ {high, medium, low, unknown} — never claim certainty we don't have.

**FR-3 — Sensitive file access.** Detect reads of files matching a configurable sensitivity policy: `.env*`, `**/.ssh/**`, `**/.npmrc`, `**/.pypirc`, `**/.docker/config.json`, `**/.aws/credentials`, `**/.git-credentials`, `/proc/*/environ`, GitHub Actions runner temp/env files. **Record path, size, and SHA-256 of the path — never file contents.**

**FR-4 — Egress capture.** For every outbound connection: PID, destination IP, port, protocol, resolved hostname (from DNS correlation), TLS SNI (parsed from the ClientHello — plaintext by design, no decryption), byte counts in/out, timestamps.

**FR-5 — DNS correlation.** Observe DNS queries and responses to map IPs back to the hostname the process asked for. Required for meaningful allowlists (CDN IPs are unstable).

**FR-6 — Taint correlation.** When process P (or an ancestor) reads a sensitive file and subsequently transmits to a destination, emit a `TAINTED_EGRESS` finding scored by: bytes sent, destination reputation, first-seen-vs-baseline, sensitivity tier of the file, and temporal proximity.

**FR-7 — Baseline learning.** After N successful runs (default 5) on the default branch, generate a proposed policy: known destinations, known sensitive-file readers, expected process set. Present as a reviewable PR-authored YAML file, not a hidden server-side blob.

**FR-8 — Enforcement mode.** With policy in enforce mode, block non-allowlisted egress at `connect()` time via an eBPF cgroup hook. Blocks are logged with full attribution. Two sub-modes: `audit` (log only) and `block` (deny + fail step, configurable).

**FR-9 — PR feedback.** Post a check run with a findings summary, upload SARIF to GitHub code scanning, and comment on the PR only when the policy diff or a finding is new relative to the base branch. **No comment on clean runs.**

**FR-10 — Run manifest.** Every run produces a signed, downloadable JSON manifest: full process tree, file access log, egress ledger, findings, agent version, policy version, and kernel/runner fingerprint. This is the forensic artifact.

**FR-11 — Fleet dashboard.** Cross-repo view: new destinations this week, top egress talkers, packages that read secrets, policy drift, agent health.

**FR-12 — Fail-open by default.** If the agent cannot load (unsupported kernel, missing BTF, permission denied), it logs a clear warning and exits 0. A security tool that breaks builds gets uninstalled. `fail_on_agent_error: true` is available for teams that want the opposite.

### 6.2 Non-functional

| ID | Requirement | Target | Ceiling |
|---|---|---|---|
| NFR-1 | Wall-clock build overhead | ≤3% | 5% |
| NFR-2 | Agent memory (RSS) | ≤100 MB | 150 MB |
| NFR-3 | Agent CPU, steady state | ≤2% of one core | 5% |
| NFR-4 | Install-to-ready time | ≤5s | 8s |
| NFR-5 | Event loss under burst | 0 at 50k events/s | <0.1%, always reported in manifest |
| NFR-6 | Ingest p99 latency | ≤300ms | 1s |
| NFR-7 | Control-plane availability | 99.9% | — |
| NFR-8 | Agent binary size | ≤25 MB | 40 MB |

**Never silently drop events.** If the ring buffer overflows, the manifest records the loss count and the run is marked `degraded`. A security tool that lies about coverage is worse than no tool.

### 6.3 Compliance & data handling

- **No file contents, no payload bytes, no environment variable values leave the runner.** Only paths, sizes, hashes, and metadata.
- Argv is captured but scrubbed against a secret-pattern denylist before transmission (tokens frequently appear in argv).
- Customer data residency: EU region at Phase 4.
- SOC 2 Type II: readiness in Phase 4, audit window opening at GA+3mo.

---

## 7. User stories & acceptance criteria

### Epic A — Install and first signal

**A1.** *As Priya, I want to add BuildLens to a repo in under two minutes so I can evaluate it without a project plan.*

```yaml
- uses: buildlens/agent@v1
  with:
    mode: observe
```

**Acceptance:**
- [ ] Given a repo with a standard Node/Python/Go build, when the step is added as the first step of the job, the agent loads and monitors the remainder of the job with no other changes.
- [ ] On a runner with an unsupported kernel, the step prints a single actionable warning and exits 0; the build succeeds.
- [ ] Step wall-clock time from start to "monitoring active" is <8s at p95.

**A2.** *As Priya, I want the first run to show me something I didn't already know.*

**Acceptance:**
- [ ] Within 60s of run completion, a check run titled "BuildLens — N destinations, M sensitive reads" is visible on the commit.
- [ ] The summary lists every distinct egress destination with hostname, bytes, and the responsible process.
- [ ] At least one non-obvious destination is surfaced on a typical `npm ci` build (telemetry endpoints, analytics beacons) — validated during Phase 0 against 20 real OSS repos.

### Epic B — Detection

**B1.** *As Priya, I want to be told when a dependency reads a secret and then phones home.*

**Acceptance:**
- [ ] Given a package whose `postinstall` reads `.env` and POSTs to an external host, a `TAINTED_EGRESS` finding is produced with severity `critical`.
- [ ] The finding names the package (`evil-pkg@1.2.3`), the file read, the destination, the byte count, and the elapsed time between read and send.
- [ ] The finding appears in GitHub code scanning as SARIF with a stable fingerprint (no duplicate alerts across runs).
- [ ] A clean control build of the same repo produces zero `TAINTED_EGRESS` findings.

**B2.** *As Priya, I want to know when a build contacts a host it has never contacted before.*

**Acceptance:**
- [ ] With ≥5 baseline runs recorded, a new destination produces a `NEW_DESTINATION` finding at severity `medium`.
- [ ] Destinations are compared by hostname/SNI, not IP, so CDN rotation does not fire.
- [ ] Findings deduplicate across reruns of the same commit.

**B3.** *As Marcus, I want to confirm BuildLens is not slowing down my fleet.*

**Acceptance:**
- [ ] A/B benchmark across 100 runs of a representative build shows median overhead ≤3% and p95 ≤5%.
- [ ] Agent resource usage is reported in every manifest, so the claim is continuously verifiable rather than a one-time benchmark.

### Epic C — Policy and enforcement

**C1.** *As Priya, I want a starting policy generated for me, not authored by hand.*

**Acceptance:**
- [ ] After the configured baseline run count, BuildLens opens a PR adding `.buildlens/policy.yml` with observed destinations, grouped and commented with why each was included (which process, how many runs).
- [ ] The policy file is human-readable and hand-editable; server-side state never overrides the committed file.

**C2.** *As Priya, I want to enforce the policy without discovering breakage in production.*

**Acceptance:**
- [ ] `mode: enforce, action: audit` logs would-be blocks without denying them, so the blast radius is knowable before flipping.
- [ ] `action: block` denies non-allowlisted connections at `connect()`, returns `ECONNREFUSED` to the process, and records the block with full attribution.
- [ ] Blocking is scoped to the job's cgroup — never affects the runner host or other jobs.
- [ ] A documented, tested break-glass: `BUILDLENS_DISABLE=1` or removing the step restores unmonitored behavior immediately.

### Epic D — Fleet visibility

**D1.** *As Priya, I want one page that answers "were we affected?" for a newly disclosed malicious package.*

**Acceptance:**
- [ ] Search across all monitored runs by package name, destination hostname, IP, or file path.
- [ ] Results return in <3s over 90 days of retained runs.
- [ ] Each result links to the full run manifest.

**D2.** *As a Security Lead, I want a weekly digest of what changed across the fleet.*

**Acceptance:**
- [ ] Digest lists new destinations, new secret readers, policy drift, and repos with degraded coverage.
- [ ] Delivered via Slack and email; configurable per team.

---

## 8. Out of scope for v1 — with the trigger that would change that

| Deferred | Add it when |
|---|---|
| Windows / macOS runners | ≥3 paying accounts blocked on it |
| Kubernetes-native runners (ARC) as first-class | Design partner runs >30% of jobs on ARC |
| GitLab CI / Jenkins / CircleCI | GitHub coverage is stable and ≥1 design partner demands it (planned Phase 4) |
| Filesystem write monitoring / artifact tamper detection | After egress is solid — it is a much noisier signal |
| Malware signature feed | Never as a core loop; consider an integration with an existing feed |
| Payload inspection of any kind | Never |
| On-prem / air-gapped deployment | Enterprise deal ≥$100k requires it |

---

## 9. Validation corpus

Detection claims are meaningless without a fixed test set. Maintained in `testdata/corpus/`:

- **20 malicious samples**: recreated behaviors from public incidents (Codecov uploader, `event-stream`, PyPI env-var beacons, `xz`-style build injection) plus 8 synthetic variants (DNS-tunneled exfil, slow-drip, egress via a legitimate allowlisted host).
- **50 clean builds**: real OSS repos across Node, Python, Go, Rust, Java, and Docker-in-Docker.

Every release gates on: detection ≥95% on malicious, false-positive rate ≤1% on clean. Published in the repo — the numbers are the product claim.

---

## 10. Key risks

| Risk | Impact | Mitigation |
|---|---|---|
| eBPF unavailable or restricted on GitHub-hosted runners | **Existential** | Phase 0 spike is entirely dedicated to this. Fallback: self-hosted + container runners only, which halves TAM. Resolve before any other work. |
| Runner kernel/BTF variance breaks probes | High | CO-RE via BTF, tested across a kernel matrix in CI; fail-open on load error |
| False positives train users to ignore us | High | Tuned defaults, `TAINTED_EGRESS` reserved for high-confidence correlation, everything else is informational. FP rate is a release gate. |
| Harden-Runner ships file-lineage attribution | High | Speed, plus depth in dependency attribution and the fleet-level "were we affected" query |
| Overhead complaints from platform teams | Medium | NFR budget enforced in CI benchmarks; per-run resource reporting |
| Adversary evades via allowlisted destination (e.g., exfil through GitHub API) | Medium | Byte-volume anomaly detection on allowlisted destinations; documented honestly as a known limit rather than hidden |

---

## 11. Success criteria for GA

- 3 design partners with ≥50 repos each, running in enforce mode on at least one production repo.
- Corpus detection ≥95%, FP ≤1%.
- Median overhead ≤3% across the fleet, measured, not claimed.
- <1 support ticket per 500 monitored runs.
- Zero incidents of BuildLens breaking a customer build in the 30 days preceding GA.

---

## 12. Open questions

1. Does the GitHub-hosted runner environment permit `CAP_BPF` / privileged BPF loading in 2026? **Blocking — resolved in Phase 0.**
2. Pricing unit: per repo, per run, or per runner-hour? Per-run aligns with value but is hostile to monorepos with heavy CI.
3. Do we open-source the agent? Strong adoption argument (auditability matters enormously for a tool with kernel access), and it makes the control plane the product. Leaning yes — decide by end of Phase 1.
4. How much of the correlation runs on-runner vs. server-side? On-runner gives instant PR feedback and works offline; server-side gives cross-run intelligence. Current design: findings on-runner, baselines server-side.

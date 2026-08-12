# BuildLens — Strategy

**Status:** Draft v1.0
**Purpose:** Why this becomes a company rather than a tool, and in what order.
**Companion to:** [PRD.md](PRD.md) (what we build), [ROADMAP.md](ROADMAP.md) (when), [ARCHITECTURE.md](ARCHITECTURE.md) (how)

---

## 1. The thesis

A per-repo security tool competes on features and gets commoditized. The BuildLens architecture happens to have a structural moat available to it that no competitor has claimed:

> Every run emits `package → process → file → destination`. Across one customer that is a security feature. Across ten thousand customers it is **the only behavioral map of the software supply chain that exists.**

Static analysis (Socket, Snyk, Chainguard) tells you what package code *looks like*. Nobody has a dataset of what package code *does at runtime, at scale*.

That dataset produces three compounding effects:

| Effect | Mechanism |
|---|---|
| **Detection quality scales with adoption** | `left-pad` observed across 400k installs in 2,000 orgs has never made a network call. The first time it does, that is not "medium — new destination," it is critical with global confidence. Per-repo baselines can never reach that certainty. |
| **Network effect** | Per-repo security tools have none. This one does. A competitor starting three years late cannot bootstrap it. |
| **Separately sellable** | The intelligence feed is a product independent of the agent. |

**Strategic implication:** the data is not exhaust. It is the product. Everything in this document is downstream of that sentence, including the one change it forces on the current engineering plan (§6).

---

## 2. Moat plays

### 2.1 Package Behavior Registry — free, public, viral

`buildlens.io/pkg/<name>` shows what a package actually does: files touched at install and runtime, hosts contacted, byte volumes, behavioral diff between versions — aggregated across the observed fleet. No login, free forever.

- **Distribution engine.** Developers link to it in PRs and incident threads. Security tools that get shared in Slack win.
- **Data collection.** Public lookups tell us which packages the market cares about.
- **Credibility.** A behavioral claim with 400,000 observations behind it is unarguable in a way a static heuristic never is.

This is the Socket.dev playbook run on behavioral data instead of source heuristics: strictly harder to copy, strictly more convincing.

### 2.2 Detonation farm — catch it before any customer installs it

Subscribe to the npm / PyPI / crates publish firehose. Install every new version in an instrumented throwaway microVM within minutes of publication.

This flips the pitch from *"we caught it in your build"* to *"it never reached your build."*

- Firecracker microVMs, ~10s per package, spot compute. Full npm coverage is low thousands of dollars per month — affordable from Phase 3.
- Fills the registry's long tail so coverage does not depend on customer traffic.
- Produces a malicious-package feed that is independently sellable *and* the strongest possible marketing asset.

**Highest-leverage engineering investment in the entire plan after the agent itself.**

### 2.3 Retroactive hunting

Every run's event stream is retained. When a new IOC drops, replay all historical runs against the new rule and auto-open incidents:

> *"You were affected on March 3rd. Four repos, two credentials exposed, an eleven-minute window. Here are the manifests."*

That email is the most valuable thing the product will ever send. It converts skeptics permanently.

It is nearly free — it falls out of the storage design already in [ARCHITECTURE.md §5](ARCHITECTURE.md#5-control-plane) — **but only if rule evaluation is deterministic and versioned from Phase 1.** See §6.

---

## 3. Where AI actually earns its place

Selectivity is the point. Most AI features in security products are demos.

### 3.1 Build these

**Triage-to-decision agent (highest value).** Detection is not the bottleneck for AppSec teams — triage is. A finding currently costs Priya 40 minutes to answer *"is this real, and what do I do?"* An agent that fetches the package source, diffs it against the prior version, locates the exact lines producing the observed kernel behavior, and writes the incident narrative with the evidence chain collapses that to 90 seconds.

This is what customers pay for. Ship it before anything else on this list.

**Behavioral anomaly → source explanation.** Kernel data says *what happened*; only source analysis says *why*. `chalk@5.3.1` starts contacting a new host → diff 5.3.0→5.3.1 → find the obfuscated `postinstall` blob → explain it. Behavioral detection plus source explanation is a complete finding; either alone is half of one.

**Auto-remediation PRs.** Pin, downgrade, or replace the offending package, with blast radius in the PR body. Detection that ends in a fix is a categorically different product from detection that ends in an alert.

### 3.2 Do not build these

| Rejected | Why |
|---|---|
| LLM as the detection engine | Non-deterministic, slow, expensive, unexplainable. A weighted score is debuggable at 3am; a model verdict is not. Also destroys retroactive replay (§2.3), which requires determinism. |
| "Chat with your build logs" | A search box is faster and correct. Demo, not feature. |
| ML anomaly detection before rules are exhausted | Already rejected in [ARCHITECTURE.md §11](ARCHITECTURE.md#11-deliberately-not-built). Still rejected. |
| Natural-language policy authoring | Marginal value; policy YAML is already short and PR-reviewed. Maybe later, never a priority. |

---

## 4. Market expansion

### 4.1 The same kernel, pointed at AI coding agents

**The strongest expansion available, and possibly the larger business.**

Autonomous coding agents run `npm install`, execute arbitrary tooling, and are handed real credentials — on developer laptops and in agent sandboxes, at far higher volume than CI runs. Structurally identical threat model. The eBPF core needs almost no change.

- Newer market, growing faster, no incumbent.
- Answers the question every enterprise security team is currently asking and nobody can answer: **"prove the agent didn't exfiltrate our source code."**
- A signed run manifest is that proof.

Worth genuinely considering whether CI is the beachhead and agent observability is the destination, rather than the reverse. CI gives the clean wedge and the data flywheel; agent monitoring is where the budget is heading.

### 4.2 MCP server — shift left to the decision moment

Expose the registry over MCP so a coding agent can ask *before* adding a dependency: *"has `fast-parse` ever been observed reading credentials?"*

Intercepts the supply chain at package **selection** rather than package **execution**. Cheap to build, and it embeds BuildLens inside the workflows that are becoming the default way code gets written.

### 4.3 Behavioral build attestations — the compliance play

Emit a signed in-toto attestation: *"this artifact was produced by a process tree that contacted only these six hosts and read zero credentials."*

SLSA proves *who* built it. This proves *what happened while they did* — nobody else can produce it.

The value here is regulatory, not technical. The EU Cyber Resilience Act, SSDF, and FedRAMP increasingly demand supply chain **evidence**. Competitors sell policy documents; this is machine-verifiable evidence. **Compliance budget is mandatory budget** — a materially easier sale than security budget, which is discretionary.

### 4.4 Blast radius, not just detection

"A secret was read" is a finding. *"The AWS prod deploy key was exposed to an unknown host; it grants these 14 permissions; rotate these 4 credentials; review this CloudTrail window"* is an incident-response product at several times the price.

Requires cloud IAM integration. Worth it.

---

## 5. The free wedge

Detonate the top 10,000 npm and PyPI packages. Publish the report:

> *"31% of the most-installed npm packages contact undeclared endpoints during install."*

A research artifact that gets shared in every AppSec Slack in the industry, costs roughly a week of compute, and doubles as the registry's seed data. Snyk, Socket, and Chainguard each bought their initial attention this way. It is the cheapest marketing in security.

Run it as soon as the detonation farm exists — not before, because the numbers must survive scrutiny.

---

## 6. The one change this forces on the engineering plan

The roadmap as originally written treats event data as exhaust. It has to be treated as the asset. Three requirements land in **Phase 1**, where they are nearly free, and become a rewrite if retrofitted:

| Requirement | Why it cannot wait |
|---|---|
| **Deterministic, versioned rule evaluation** | Retroactive hunting (§2.3) requires replaying stored events through a rule version and getting byte-identical results. Any nondeterminism — map iteration order, wall-clock in scoring, LLM in the path — destroys it permanently. |
| **Stable package identity** | Cross-customer aggregation keys on `(ecosystem, name, version, integrity_hash)`. If early manifests key on a resolved path or a lockfile position, the historical corpus is unjoinable. |
| **Anonymization boundary in the schema itself** | Aggregatable fields (package identity, destination hostname, file *category*) must be structurally separable from repo-identifying fields (paths, repo names, commit SHAs) at write time — not filtered later by a query everyone must remember to write correctly. |

None of these add meaningful Phase 1 work. All three are unrecoverable if skipped.

---

## 7. Sequencing

Do not do all of this. Focus order:

| Phase | Flywheel work | Rationale |
|---|---|---|
| **0–1** | Only §6 — replay-ready, aggregation-ready, anonymization-ready schema | Nearly free now, impossible to retrofit |
| **2** | Triage agent (§3.1) | Highest per-customer value, low build cost, immediate differentiation |
| **3** | Registry + detonation farm (§2.1, §2.2), OSS research report (§5) | Needs enough traffic and coverage to be credible |
| **3–4** | Retroactive hunting (§2.3), MCP server (§4.2) | Falls out of work already done |
| **4** | Agent monitoring (§4.1), attestations (§4.3), blast radius (§4.4) | Each is a distinct GTM motion — sequence by which design partner pulls hardest |

---

## 8. Business model implications

| Layer | Model | Purpose |
|---|---|---|
| Package Behavior Registry | Free, public, no login | Distribution, credibility, data collection |
| Agent (observe mode) | Free for public repos + ≤3 private | Adoption; every run improves the corpus |
| Fleet platform | Per repo / month | Core revenue |
| Intelligence feed + attestations | Enterprise SKU | Compliance budget, higher ceiling |
| Agent monitoring | Per seat or per agent-hour | New category, separate budget line |

**Pricing note:** per-run pricing is hostile to monorepos with heavy CI and punishes exactly the customers who benefit most. Price on repos monitored, with the intelligence tier as the expansion path.

---

## 9. Risks specific to this strategy

| Risk | Severity | Handling |
|---|---|---|
| **Cross-customer aggregation consent** | **Existential** | The buyer is a security team that will read the data clause with hostile care. Opt-in, package-level aggregates only, never repo-identifying, contractually explicit. Settle it in the Phase 2 legal review. Get this wrong once and the moat becomes the scandal. |
| Detonation farm is gamed | High | Malware that detects sandboxes and stays quiet. Assume it happens. Randomize environment fingerprints, vary dwell time, and treat sandbox-evasion behavior as itself a strong signal. |
| Registry data is scraped by a competitor | Medium | Aggregates are scrapeable; the raw corpus and the update velocity are not. Rate limit, and accept that the public product is a giveaway by design. |
| Strategic sprawl | High | Five GTM motions across four phases is how a small team dies. Every item in §4 waits for a design partner actively pulling for it. No speculative market entry. |
| Agent-monitoring market has a fast incumbent | Medium | It is early and moving quickly. If a credible incumbent appears before Phase 4, reassess rather than fighting in. The CI business stands alone. |
| Detonation compute cost at full ecosystem scale | Low | Spot microVMs, tiered by package download count. Cover the top 50k packages first; the long tail can lag. |

---

## 10. What success looks like

| Horizon | Marker |
|---|---|
| 12 months | 200 repos monitored; corpus gates met; 3 design partners in enforce mode |
| 18 months | Registry public with >1M package-versions observed; OSS research report published and cited |
| 24 months | Detection quality measurably better *because of* fleet size — the flywheel is provable, not asserted |
| 30 months | Intelligence feed or attestations sold as a standalone SKU; agent monitoring in paid beta |

The 24-month marker is the one that matters. If detection quality does not visibly improve with fleet size, the thesis in §1 is wrong and this is a good tool rather than a company — which is worth knowing early and explicitly.

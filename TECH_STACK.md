# BuildLens — Tech Stack

**Status:** Draft v1.0
**Selection rule:** every dependency must be forced by a requirement we can name. Boring, widely-operated technology beats interesting technology. A tool with kernel access earns trust through auditability, not features.

---

## 1. Agent

| Concern | Choice | Why | Rejected |
|---|---|---|---|
| eBPF programs | **C + libbpf CO-RE**, `vmlinux.h` from BTF | CO-RE is the only realistic way to ship one binary across the kernel spread on hosted runners (6.5 → 6.11+ and rising). BCC-style runtime compilation would require clang on every runner — a non-starter for install time and attack surface. | BCC (needs toolchain at runtime), raw bpf() syscall (no portability) |
| Userspace | **Go 1.23+** | `cilium/ebpf` is pure Go, actively maintained, and used in production by Cilium and Tetragon. Single static binary, trivial cross-compilation, fast to ship. | **Rust + aya** — genuinely better memory story and no GC, but slower for this team and a smaller ecosystem. Revisit if GC pauses show in the overhead budget (ARCH D4). **C** — no. |
| BPF loader | **`github.com/cilium/ebpf`** + `bpf2go` | Compiles BPF C into embedded Go objects at build time. No runtime clang, no external `.o` files to ship or tamper with. | libbpfgo (cgo dependency, complicates static linking) |
| Process/cgroup enrichment | **`prometheus/procfs`** + direct `/proc` reads | Already solved, well-tested parsing. | Hand-rolled `/proc` parsers |
| Config / policy | **`gopkg.in/yaml.v3`** + JSON Schema validation | Policy is human-authored and PR-reviewed; YAML is right. Schema validation gives good error messages. | TOML (worse for nested allowlists), HCL (extra concept to learn) |
| CLI | **`spf13/cobra`** | Standard, and we need subcommands (`run`, `verify`, `dump`, `policy lint`). | stdlib `flag` — insufficient once subcommands exist |
| Logging | **stdlib `log/slog`** | In stdlib since 1.21. Structured JSON, zero dependencies. | zap, zerolog — measurably faster, irrelevant at our log volume |
| Testing | **stdlib `testing`** + `testify/require` for assertions | `require` cuts real boilerplate in table tests. Nothing else needed. | Ginkgo/Gomega — DSL that obscures failures |
| Kernel testing | **`vmtest` / QEMU microVMs** | Runs the actual probe suite against real kernel images in CI. The only way to honestly claim kernel matrix support. | Containers (share the host kernel — proves nothing) |
| Release signing | **cosign** + SLSA L3 provenance via `slsa-framework/slsa-github-generator` | Mandatory. We ask for kernel access; the binary must be verifiable. | GPG (worse tooling, worse verification story) |
| Build/release | **GoReleaser** | Multi-arch builds, checksums, signing, GitHub releases in one config. | Hand-rolled make targets |

**Deliberately absent:** no DI framework, no plugin system, no ORM in the agent, no logging abstraction layer.

### Kernel feature requirements

| Feature | Min kernel | Fallback if absent |
|---|---|---|
| BTF / CO-RE | 5.4 (5.8+ realistic) | None — fail open, log clearly |
| BPF ring buffer | 5.8 | perf buffer (higher overhead) |
| BPF LSM (`lsm/file_open`) | 5.7 + `lsm=bpf` boot param | `tracepoint/sys_enter_openat` (noisier, TOCTOU on path) |
| `cgroup/connect4`+`6` | 4.17 | Enforcement unavailable; observe mode still works |
| CAP_BPF / CAP_PERFMON | 5.8 | CAP_SYS_ADMIN |

**Supported baseline: Linux 5.8+ with BTF.** Everything older fails open with an explicit message. Stated in docs, not buried.

---

## 2. Control plane

| Concern | Choice | Why | Rejected |
|---|---|---|---|
| Language | **Go 1.23+** | Same language as the agent — shared event schema package, one toolchain, one set of idioms for a 2-person team. | TypeScript/Node (second runtime), Python (worse for a high-throughput ingest path) |
| HTTP | **stdlib `net/http`** + `go-chi/chi` for routing | Go 1.22+ `ServeMux` has patterns and methods; chi adds middleware composition that we do need. Both are thin. | Gin, Echo, Fiber — frameworks where a router suffices |
| Database | **PostgreSQL 16** | One database for runs, events, findings, policy, and tenancy. Native partitioning handles the event tables to ~100k runs/day. JSONB for evidence blobs. Row-level security for tenant isolation. Everyone can operate it. | ClickHouse from day one (second database to operate for a load we don't have yet — see ARCH §10 for the trigger); MongoDB (we want relational integrity and RLS) |
| DB access | **`sqlc`** — generated type-safe Go from hand-written SQL | Real SQL with compile-time type safety. Partition pruning and index hints stay under our control, which matters for the fleet search query. | GORM (hides the queries that need tuning), raw `database/sql` (manual scanning everywhere) |
| Migrations | **`golang-migrate`** | Plain SQL, up/down, no magic. | Atlas (more capability than we need), ORM auto-migrate (never in production) |
| Object storage | **S3-compatible** (AWS S3 / Cloudflare R2) | Run manifests are write-once blobs served by presigned URL. R2 has no egress fees — relevant when customers download manifests. | Storing manifests in Postgres — bloats a database we need fast |
| Cache | **None in v1.** Redis at Phase 3 for policy lookup | Policy fetch is one indexed query. Add the cache when p99 demands it, not before. | Redis from day one |
| Queue | **None in v1.** NATS JetStream at Phase 4 | Batched HTTPS → Postgres handles 10k runs/day. A broker is an on-call burden with no v1 payoff. Trigger: ingest p99 >300ms sustained. | Kafka (heavy for our volume even at Phase 4), SQS (cloud lock-in) |
| Auth (agents) | **GitHub Actions OIDC** — JWT validated against GitHub's JWKS | No long-lived secrets on runners. Claims bind to repo + run_id, so a stolen token is useless outside its run. This is the correct 2026 answer. | Static API keys (a secret sitting in every CI environment we're supposed to be protecting — absurd) |
| Auth (humans) | **GitHub OAuth** in v1, **SAML/SCIM** in Phase 4 | Users already have GitHub identity. | Building our own password auth — never |
| GitHub integration | **`google/go-github`** + a GitHub App | App installation tokens, fine-grained permissions, higher rate limits than a PAT. | Raw HTTP calls |
| Background jobs | **`river`** (Postgres-backed queue) | Baseline computation and digests are the only async work. River reuses the database we already run — no new infrastructure for two job types. | Temporal (enormous for two jobs), cron in a container (no retries, no visibility) |
| Validation | **JSON Schema** (`santhosh-tekuri/jsonschema`) for policy + event envelopes | One schema definition shared by agent, server, and docs. | Hand-written validators drifting in three places |
| Observability | **OpenTelemetry** SDK → Grafana Cloud (traces, metrics, logs) | One vendor for all three signals at our size. OTel keeps us portable if that changes. | Datadog (cost), self-hosted LGTM stack (an ops burden we don't need yet) |
| Errors | **Sentry** | Standard, good Go support. | — |

---

## 3. Web dashboard

| Concern | Choice | Why | Rejected |
|---|---|---|---|
| Framework | **Next.js 15 (App Router)** | Server components suit a read-heavy dashboard; one deploy target; the ecosystem is where the hiring pool is. | Remix (fine, smaller ecosystem), SPA + separate API (extra auth plumbing) |
| Language | **TypeScript**, strict | Non-negotiable for a data-shape-heavy UI. | — |
| Styling | **Tailwind CSS** + **shadcn/ui** | shadcn is copy-in components, not a dependency — we own and modify the code. No runtime CSS-in-JS cost. | MUI (heavy, opinionated), Chakra (runtime overhead) |
| Data fetching | **TanStack Query** | Cache, revalidation, and pagination for the fleet search view. | SWR (thinner than we need), hand-rolled fetch state |
| Process tree viz | **`d3-hierarchy`** for layout + plain SVG for rendering | The process tree is the signature view. d3 handles layout math; we render it ourselves so it stays styleable and accessible. | Full d3 DOM manipulation (fights React), Cytoscape (heavy for a tree) |
| Charts | **Recharts** | Simple time-series and bar charts only. | Nothing more elaborate is warranted |
| Tables | **TanStack Table** (headless) | Virtualized, sortable, filterable event lists. Headless means our styling. | AG Grid (licensing, weight) |

---

## 4. Infrastructure

| Concern | Choice | Why | Rejected |
|---|---|---|---|
| Compute (Phase 1–3) | **Fly.io** | Three stateless Go binaries + a Next.js app. Deploy is `fly deploy`. Global anycast comes free, which matters for a globally distributed agent fleet. | Kubernetes (an ops burden for 4 services — see ARCH §11), Lambda (cold starts on an ingest path, awkward for long-lived connections) |
| Compute (Phase 4+) | **AWS ECS Fargate** or stay on Fly | Migration decision driven by enterprise procurement and data residency demands, not by preference. | — |
| Database hosting | **Neon** or **AWS RDS** | Managed Postgres, PITR, read replicas. Neon's branching is genuinely useful for testing migrations against production-shaped data. | Self-managed Postgres (we are 2–4 engineers) |
| CDN / DNS / WAF | **Cloudflare** | DDoS protection on a public ingest endpoint is mandatory, not optional. | — |
| IaC | **Terraform** + **Terragrunt** only if environments multiply | Portable, and every ops-literate hire knows it. | Pulumi (smaller talent pool), CDK (AWS lock-in) |
| CI/CD | **GitHub Actions** | We are a GitHub Actions product. Dogfooding is a feature — we run BuildLens on BuildLens. | CircleCI, Buildkite |
| Secrets | **Cloud provider secret manager** + OIDC for CI→cloud auth | No static cloud credentials in GitHub secrets. | Vault (operational weight we cannot justify yet) |
| Billing | **Stripe** | Usage-based metering, Marketplace-compatible. | Building metering ourselves |
| Status page | **Betterstack** or **Instatus** | Customers running us in enforce mode need to see our status during an incident. | Self-hosted |

---

## 5. Data & analysis

| Concern | Choice | Why |
|---|---|---|
| Event store (v1) | Postgres partitioned tables | Sufficient to ~100k runs/day with monthly partitions |
| Event store (Phase 4) | **ClickHouse Cloud** | Columnar compression and scan speed for fleet-wide queries over billions of events. Postgres retains runs, findings, policies, and tenancy. |
| Search | Postgres GIN indexes + trigram | Fleet search is exact-match on hostname/package/path, not fuzzy relevance ranking |
| Analytics | **PostHog** (self-hosted or cloud) | Product analytics + feature flags. EU-hostable, which matters for our buyer. |

---

## 6. Development

| Concern | Choice |
|---|---|
| Monorepo | Single Go module for agent + control plane; separate `web/` workspace. No Bazel, no Nx — the build is `go build` plus `next build`. |
| Linting | `golangci-lint` (errcheck, govet, staticcheck, gosec, revive); `biome` for TS |
| Formatting | `gofmt` + `biome format`. No debate. |
| Pre-commit | `lefthook` — fast, single binary |
| Local dev | `docker compose` for Postgres + MinIO; agent development inside a Lima/QEMU Linux VM on macOS |
| API docs | OpenAPI 3.1 generated from Go annotations, served via Scalar |
| ADRs | `docs/adr/NNNN-title.md`, one page each. Decisions with kernel or security implications get one. |

---

## 7. Security tooling (applied to ourselves)

Credibility requires that we hold ourselves to what we sell.

| Control | Tool |
|---|---|
| Dependency scanning | `govulncheck`, Dependabot |
| SAST | `gosec`, CodeQL |
| Secret scanning | `gitleaks` + GitHub secret scanning |
| Container scanning | `trivy` |
| SBOM | `syft` on every release |
| Artifact signing | `cosign` + SLSA L3 |
| Runtime CI monitoring | **BuildLens itself**, in enforce mode, on our own repos |

---

## 8. Cost model (steady state)

| Phase | Monthly | Drivers |
|---|---|---|
| 1 | ~$50 | GitHub Actions minutes for the kernel matrix; one dev database |
| 2 | ~$500 | Fly.io (3 services), Neon, S3, Grafana Cloud |
| 3 | ~$2,000 | Scaled compute, Postgres replica, PostHog, Sentry, Stripe fees |
| 4 | ~$8,000 | ClickHouse Cloud, multi-region, EU replica, compliance tooling |

Compliance (SOC 2 Type II) is a separate ~$25–40k one-time cost in Phase 4.

---

## 9. Version pinning policy

- **Go, Node:** pin the minor version in `go.mod` / `.nvmrc`; upgrade deliberately.
- **Direct dependencies:** exact versions in lockfiles; Dependabot PRs reviewed weekly, never auto-merged.
- **eBPF/libbpf:** vendored `vmlinux.h` per supported kernel generation, regenerated only when we add a kernel to the support matrix.
- **Agent releases:** semver; the control plane supports agents N-2. Never break a pinned action version.

---

## 10. Stack risks

| Risk | Mitigation |
|---|---|
| `cilium/ebpf` API churn | Pin exact version; the abstraction surface we use is small and easily wrapped if we must migrate to aya |
| Go GC pauses inside the overhead budget | Measured every PR by the benchmark gate. Object pooling for hot event structs. Rust rewrite of the hot path is the escape hatch. |
| Postgres becomes the bottleneck earlier than planned | Migration path documented (ARCH §10); partitioning from day one makes the move mechanical rather than a rewrite |
| Fly.io outage affects ingest | Agents spool locally and always emit the manifest + check run. Control-plane downtime degrades fleet features, never per-run findings. |
| Next.js major version churn | Dashboard is read-heavy and conventional; upgrades are low-risk |
| ClickHouse operational learning curve | Deferred to Phase 4 when there is headcount; ClickHouse Cloud, not self-hosted |

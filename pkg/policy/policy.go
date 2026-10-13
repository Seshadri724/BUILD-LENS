// Package policy builds the audit-mode observed-egress policy: which hosts
// each dependency contacted, with counts. Output contains only aggregates
// (host, package identity, counts, comm chains) — never argv, file paths or
// secret values — so the ledger file is safe to commit.
//
// Two input kinds merge commutatively: raw event JSONL (one file per run) and
// observation JSONL ledgers as appended by the Action in audit mode. Merging
// two ledgers that cover overlapping runs double-counts runs; the supported
// flow is a single append-only ledger plus optional fresh event files.
package policy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/buildlens/buildlens/pkg/attribution"
	"github.com/buildlens/buildlens/pkg/correlate"
	"gopkg.in/yaml.v3"
)

// Record is one (host, package) aggregate. Ledger lines use the same shape.
type Record struct {
	Host       string `json:"host" yaml:"-"`
	Ecosystem  string `json:"ecosystem,omitempty" yaml:"-"`
	Package    string `json:"package" yaml:"-"`
	Version    string `json:"version,omitempty" yaml:"-"`
	Lifecycle  string `json:"lifecycle,omitempty" yaml:"-"`
	Confidence string `json:"confidence,omitempty" yaml:"-"`
	Connects   int    `json:"connects" yaml:"-"`
	Runs       int    `json:"runs" yaml:"-"`
	Chain      string `json:"chain" yaml:"-"`
}

// Stats describes what went into a summary.
type Stats struct {
	Runs   int
	Events int
}

type recordKey struct {
	host, eco, pkg, ver, life, chain string
}

type acc struct {
	connects  int
	eventRuns map[int]bool
	ledgerRun int
}

type procInfo struct {
	comm    string
	cmdline string
	cwd     string
	chain   []string
	attr    attributionResult
}

type attributionResult struct {
	eco, pkg, ver, life, conf string
	unknown                   bool
}

// SummarizeFiles aggregates comma-separated inputs (event JSONL and/or
// observation JSONL) into merged records. Deterministic: inputs in flag order,
// events sorted by (ts, pid, kind), records sorted by (host, package).
func SummarizeFiles(inputs []string, lockfile string) ([]Record, Stats, error) {
	merge := map[recordKey]*acc{}
	var st Stats
	maxLedgerRuns := 0

	for fi, path := range inputs {
		lines, err := readLines(path)
		if err != nil {
			return nil, st, err
		}
		if len(lines) == 0 || isEventFile(lines) {
			// A quiet run is still a baseline run: count it even when it
			// yields zero records.
			st.Runs++
			if len(lines) == 0 {
				continue
			}
			events, err := parseEvents(lines)
			if err != nil {
				return nil, st, fmt.Errorf("%s: %w", path, err)
			}
			st.Events += len(events)
			// Event-file run indices start past any ledger-covered runs so
			// mixed merges don't collide with ledger run counts.
			observeEvents(events, lockfile, maxLedgerRuns+fi, merge)
		} else {
			if !isLedgerFile(lines) {
				return nil, st, fmt.Errorf("%s: unrecognized input (want event JSONL with kind/type, or observation JSONL with host)", path)
			}
			for _, ln := range lines {
				var r Record
				if err := json.Unmarshal([]byte(ln), &r); err != nil {
					return nil, st, fmt.Errorf("%s: %w", path, err)
				}
				if r.Host == "" {
					continue
				}
				k := recordKey{r.Host, r.Ecosystem, r.Package, r.Version, r.Lifecycle, r.Chain}
				a := ensureAcc(merge, k)
				a.connects += r.Connects
				a.ledgerRun += r.Runs
				if r.Runs > maxLedgerRuns {
					maxLedgerRuns = r.Runs
				}
			}
		}
	}

	st.Runs += maxLedgerRuns
	out := make([]Record, 0, len(merge))
	for k, a := range merge {
		out = append(out, Record{
			Host: k.host, Ecosystem: k.eco, Package: k.pkg, Version: k.ver,
			Lifecycle: k.life, Chain: k.chain,
			Connects: a.connects, Runs: len(a.eventRuns) + a.ledgerRun,
		})
	}
	slices.SortFunc(out, func(a, b Record) int {
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		if c := strings.Compare(a.Package, b.Package); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	return out, st, nil
}

func ensureAcc(merge map[recordKey]*acc, k recordKey) *acc {
	a, ok := merge[k]
	if !ok {
		a = &acc{eventRuns: map[int]bool{}}
		merge[k] = a
	}
	return a
}

func observeEvents(events []eventLite, lockfile string, runIdx int, merge map[recordKey]*acc) {
	procs := map[uint32]*procInfo{}
	lookups := map[string][]dnsLite{}
	sniLookups := map[string][]dnsLite{}
	for _, e := range events {
		if e.kind == "dns" {
			lookups[e.dest] = append(lookups[e.dest], dnsLite{ts: e.ts, host: e.host})
			continue
		}
		if e.kind == "sni" {
			sniLookups[e.dest] = append(sniLookups[e.dest], dnsLite{ts: e.ts, host: e.host})
			continue
		}
		p, ok := procs[e.pid]
		if !ok {
			p = &procInfo{comm: e.comm, cmdline: e.cmdline, cwd: e.cwd, chain: []string{e.comm}}
			if parent, pok := procs[e.ppid]; pok {
				p.chain = append(append([]string{}, parent.chain...), e.comm)
			}
			p.attr = attribute(p, lockfile)
			if parent, pok := procs[e.ppid]; pok && p.attr.unknown && !parent.attr.unknown {
				p.attr = parent.attr
			}
			procs[e.pid] = p
		} else {
			if e.comm != "" {
				p.comm = e.comm
			}
			if e.cmdline != "" {
				p.cmdline = e.cmdline
			}
			if e.cwd != "" {
				p.cwd = e.cwd
			}
			if p.attr.unknown {
				if a := attribute(p, lockfile); !a.unknown {
					p.attr = a
				} else if parent, pok := procs[e.ppid]; pok && !parent.attr.unknown {
					p.attr = parent.attr
				}
			}
		}
		if e.kind != "connect" {
			continue
		}
		ip := splitHost(e.dest)
		if ip == "" || isLoopback(ip) {
			continue
		}
		dhost := ip
		// SNI names its own connection; DNS is the fallback. Mirrors scoring.
		if h := resolveHost(sniLookups[ip], e.ts); h != "" {
			dhost = h
		} else if h := resolveHost(lookups[ip], e.ts); h != "" {
			dhost = h
		}
		k := recordKey{
			host: dhost, eco: p.attr.eco, pkg: p.attr.pkg,
			ver: p.attr.ver, life: p.attr.life, chain: strings.Join(p.chain, " → "),
		}
		// Package name empty means unattributed; keep the honest label.
		if p.attr.unknown {
			k.pkg, k.eco, k.ver, k.life = "unknown", "", "", ""
		}
		a := ensureAcc(merge, k)
		a.connects++
		a.eventRuns[runIdx] = true
	}
}

func attribute(p *procInfo, lockfile string) attributionResult {
	a := attribution.AttributeProcess(p.cwd, p.cmdline, lockfile)
	if a.IsUnknown() {
		return attributionResult{unknown: true}
	}
	return attributionResult{eco: a.Package.Ecosystem, pkg: a.Package.Name, ver: a.Package.Version, life: a.Lifecycle, conf: a.Confidence}
}

// MarshalYAMLPolicy renders merged records as a reviewable policy file.
// Host-centric: enforcement allowlists match on destination host.
func MarshalYAMLPolicy(records []Record, st Stats) ([]byte, error) {
	type entry struct {
		Host     string   `yaml:"host"`
		Packages []string `yaml:"packages"`
		Connects int      `yaml:"connects"`
		Runs     int      `yaml:"runs"`
		Why      string   `yaml:"why"`
	}
	type policyFile struct {
		Version        int     `yaml:"version"`
		RunsObserved   int     `yaml:"runs_observed"`
		EventsObserved int     `yaml:"events_observed"`
		Allow          []entry `yaml:"allow"`
	}

	byHost := map[string][]Record{}
	for _, r := range records {
		byHost[r.Host] = append(byHost[r.Host], r)
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)

	pf := policyFile{Version: 1, RunsObserved: st.Runs, EventsObserved: st.Events}
	for _, h := range hosts {
		rs := byHost[h]
		pkgs := []string{}
		seen := map[string]bool{}
		connects, runs := 0, 0
		for _, r := range rs {
			d := r.Package
			if r.Version != "" {
				d += "@" + r.Version
			}
			if !seen[d] {
				seen[d] = true
				pkgs = append(pkgs, d)
			}
			connects += r.Connects
			runs += r.Runs
		}
		slices.Sort(pkgs)
		life := rs[0].Lifecycle
		if life == "" {
			life = "unknown"
		}
		why := fmt.Sprintf("%s lifecycle (e.g. chain %s)", life, rs[0].Chain)
		if net.ParseIP(h) != nil {
			why += " — no DNS name observed (hardcoded IP?)"
		}
		pf.Allow = append(pf.Allow, entry{Host: h, Packages: pkgs, Connects: connects, Runs: runs, Why: why})
	}

	body, err := yaml.Marshal(pf)
	if err != nil {
		return nil, err
	}
	header := "# BuildLens observed-egress policy — AUDIT mode output.\n" +
		"# Every entry below was OBSERVED, not approved. Review it, remove what you\n" +
		"# don't recognize, commit as .buildlens/policy.yml. Block-mode enforcement\n" +
		"# (Phase 2) will treat this file as its allowlist.\n"
	return append([]byte(header), body...), nil
}

// MarshalJSONL renders one observation record per line for the append-only
// audit ledger (.buildlens/observed.jsonl). Aggregates only — safe to commit.
func MarshalJSONL(records []Record) ([]byte, error) {
	var sb strings.Builder
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		sb.WriteString(string(b) + "\n")
	}
	return []byte(sb.String()), nil
}

// WriteFile writes data to path, or stdout when path is "-". Parent
// directories are created so the default .buildlens/policy.yml just works.
func WriteFile(path string, data []byte) error {
	if path == "-" {
		_, err := fmt.Print(string(data))
		return err
	}
	if dir := parentDir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}

func parentDir(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	if i := strings.LastIndex(path, "\\"); i > 0 {
		return path[:i]
	}
	return ""
}

// --- input helpers (kept local so policy never depends on kernel code) ---

type eventLite struct {
	kind, comm, cmdline, cwd, path, dest, host string
	ts                                         int64
	pid, ppid                                  uint32
	bytes                                      uint64
}

type dnsLite struct {
	ts   int64
	host string
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out, nil
}

func isEventFile(lines []string) bool {
	var probe map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &probe); err != nil {
		return false
	}
	// The loader accepts both keys; the sniffer must too (older fixtures use
	// "type").
	if _, ok := probe["kind"]; ok {
		return true
	}
	_, ok := probe["type"]
	return ok
}

// isLedgerFile reports observation JSONL: records shaped by MarshalJSONL.
func isLedgerFile(lines []string) bool {
	var probe map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &probe); err != nil {
		return false
	}
	for _, k := range []string{"host", "connects", "package"} {
		if _, ok := probe[k]; ok {
			return true
		}
	}
	return false
}

func parseEvents(lines []string) ([]eventLite, error) {
	// Reuse the canonical loader so event parsing never drifts from scoring.
	joined := strings.Join(lines, "\n") + "\n"
	evs, err := correlate.LoadJSONL(strings.NewReader(joined))
	if err != nil {
		return nil, err
	}
	out := make([]eventLite, 0, len(evs))
	for _, e := range evs {
		out = append(out, eventLite{
			kind: e.Kind, comm: e.Comm, cmdline: e.Cmdline, cwd: e.Cwd,
			path: e.Path, dest: e.Dest, host: e.Host,
			ts: e.TS, pid: e.PID, ppid: e.PPID, bytes: e.BytesSent,
		})
	}
	slices.SortFunc(out, func(a, b eventLite) int {
		if a.ts != b.ts {
			if a.ts < b.ts {
				return -1
			}
			return 1
		}
		if a.pid != b.pid {
			if a.pid < b.pid {
				return -1
			}
			return 1
		}
		return strings.Compare(a.kind, b.kind)
	})
	return out, nil
}

func resolveHost(lookups []dnsLite, ts int64) string {
	host := ""
	for _, l := range lookups {
		if l.ts > ts {
			break
		}
		host = l.host
	}
	return host
}

func splitHost(dest string) string {
	if host, _, err := net.SplitHostPort(dest); err == nil {
		return host
	}
	return dest
}

func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

package correlate

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/buildlens/buildlens/pkg/attribution"
	"github.com/buildlens/buildlens/pkg/runschema"
)

const (
	ruleTaintedEgress  = "TAINTED_EGRESS"
	defaultTaintWindow = 60 * 1e9 // 60 seconds in nanoseconds
)

type ScoreOptions struct {
	LockfilePath    string
	TaintWindowNano int64
	AgentHealth     runschema.AgentHealth
}

type procNode struct {
	PID          uint32
	PPID         uint32
	Comm         string
	Cmdline      string
	Cwd          string
	ProcessChain []string
	Attribution  runschema.Attribution
	Tainted      *taintMark
}

type taintMark struct {
	path       string
	tier       string
	ts         int64
	originPID  uint32
	originComm string
}

// Score evaluates events deterministically using default options.
func Score(events []runschema.Event) runschema.Manifest {
	return ScoreWithOptions(events, ScoreOptions{})
}

// ScoreWithOptions evaluates events deterministically with ancestor-process taint propagation.
func ScoreWithOptions(events []runschema.Event, opts ScoreOptions) runschema.Manifest {
	// Send totals are per-run aggregates, not points in time: pull them out of
	// the timeline and attach them to findings by (pid, dest) afterwards.
	sentBytes := map[string]uint64{}
	haveSendTelemetry := false
	sorted := make([]runschema.Event, 0, len(events))
	for _, e := range events {
		if e.Kind == "send" {
			haveSendTelemetry = true
			sentBytes[flowKey(e.PID, e.Dest)] += e.BytesSent
			continue
		}
		sorted = append(sorted, e)
	}
	slices.SortFunc(sorted, cmpEvent)

	taintWindow := opts.TaintWindowNano
	if taintWindow <= 0 {
		taintWindow = defaultTaintWindow
	}

	procs := map[uint32]*procNode{}
	dedupKeys := map[string]struct{}{}
	var findings []runschema.Finding

	for _, e := range sorted {
		proc, exists := procs[e.PID]
		if !exists {
			chain := []string{e.Comm}
			var attr runschema.Attribution
			if parent, parentExists := procs[e.PPID]; parentExists {
				chain = append(slices.Clone(parent.ProcessChain), e.Comm)
				attr = parent.Attribution
			}
			if attr.IsUnknown() && (e.Cwd != "" || e.Cmdline != "") {
				attr = attribution.AttributeProcess(e.Cwd, e.Cmdline, opts.LockfilePath)
			}
			proc = &procNode{
				PID:          e.PID,
				PPID:         e.PPID,
				Comm:         e.Comm,
				Cmdline:      e.Cmdline,
				Cwd:          e.Cwd,
				ProcessChain: chain,
				Attribution:  attr,
			}
			// Inherit taint from parent if within expiration window
			if parent, parentExists := procs[e.PPID]; parentExists && parent.Tainted != nil {
				if (e.TS - parent.Tainted.ts) <= taintWindow {
					proc.Tainted = parent.Tainted
				}
			}
			procs[e.PID] = proc
		}

		if e.Comm != "" {
			proc.Comm = e.Comm
		}
		if e.Cmdline != "" {
			proc.Cmdline = e.Cmdline
		}
		if e.Cwd != "" {
			proc.Cwd = e.Cwd
		}
		if proc.Attribution.IsUnknown() && (proc.Cwd != "" || proc.Cmdline != "") {
			proc.Attribution = attribution.AttributeProcess(proc.Cwd, proc.Cmdline, opts.LockfilePath)
		}

		switch e.Kind {
		case "exec":
			// If parent exists and child newly execed, inherit parent's taint if valid
			if parent, parentExists := procs[e.PPID]; parentExists && parent.Tainted != nil {
				if (e.TS - parent.Tainted.ts) <= taintWindow {
					proc.Tainted = parent.Tainted
				}
				if proc.Attribution.IsUnknown() && !parent.Attribution.IsUnknown() {
					proc.Attribution = parent.Attribution
				}
			}

		case "open":
			if tier := fileTier(e.Path); tier != "" {
				proc.Tainted = &taintMark{
					path:       e.Path,
					tier:       tier,
					ts:         e.TS,
					originPID:  e.PID,
					originComm: e.Comm,
				}
			}

		case "connect":
			if proc.Tainted == nil {
				continue
			}

			// Taint expiration check
			elapsedNano := e.TS - proc.Tainted.ts
			if elapsedNano < 0 {
				elapsedNano = 0
			}
			if elapsedNano > taintWindow {
				continue
			}
			elapsedMS := elapsedNano / 1e6

			dHost := destHost(e.Dest)
			dedupKey := fmt.Sprintf("%s|%s|%s|%s", proc.Tainted.path, dHost, proc.Attribution.Package.Name, proc.Comm)
			if _, seen := dedupKeys[dedupKey]; seen {
				continue
			}
			dedupKeys[dedupKey] = struct{}{}

			fingerprint := computeFingerprint(ruleTaintedEgress, proc.Tainted.tier, dHost, proc.Attribution.Package.Name)

			chain := proc.ProcessChain
			if len(chain) == 0 {
				chain = []string{proc.Comm}
			}

			findings = append(findings, runschema.Finding{
				Rule:     ruleTaintedEgress,
				Severity: "critical",
				Aggregatable: runschema.FindingAgg{
					Package:   proc.Attribution.Package,
					DestHost:  dHost,
					FileTier:  proc.Tainted.tier,
					ElapsedMS: elapsedMS,
				},
				Context: runschema.FindingContext{
					PID:          e.PID,
					Comm:         e.Comm,
					Path:         proc.Tainted.path,
					Dest:         e.Dest,
					ProcessChain: chain,
					Cmdline:      proc.Cmdline,
					Cwd:          proc.Cwd,
					Fingerprint:  fingerprint,
					Attribution:  proc.Attribution,
				},
			})
		}
	}

	if haveSendTelemetry {
		for i := range findings {
			n := sentBytes[flowKey(findings[i].Context.PID, findings[i].Context.Dest)]
			findings[i].Aggregatable.BytesSent = &n
		}
	}

	slices.SortFunc(findings, cmpFinding)

	status := "clean"
	if opts.AgentHealth.Degraded || opts.AgentHealth.EventsDropped > 0 {
		status = "degraded"
	} else if len(findings) > 0 {
		status = "findings"
	}

	return runschema.Manifest{
		SchemaVersion:  runschema.SchemaVersion,
		RulesetVersion: runschema.RulesetVersion,
		Status:         status,
		EventCount:     len(events),
		AgentHealth:    opts.AgentHealth,
		Findings:       findings,
	}
}

func flowKey(pid uint32, dest string) string {
	return fmt.Sprintf("%d|%s", pid, dest)
}

func computeFingerprint(rule, tier, host, pkg string) string {
	h := sha256.New()
	h.Write([]byte(rule + "|" + tier + "|" + host + "|" + pkg))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func cmpEvent(a, b runschema.Event) int {
	if n := cmp.Compare(a.TS, b.TS); n != 0 {
		return n
	}
	if n := cmp.Compare(a.PID, b.PID); n != 0 {
		return n
	}
	return strings.Compare(a.Kind, b.Kind)
}

func cmpFinding(a, b runschema.Finding) int {
	if n := strings.Compare(a.Rule, b.Rule); n != 0 {
		return n
	}
	if n := strings.Compare(a.Aggregatable.DestHost, b.Aggregatable.DestHost); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Context.PID, b.Context.PID); n != 0 {
		return n
	}
	return strings.Compare(a.Context.Path, b.Context.Path)
}

func fileTier(path string) string {
	lower := strings.ToLower(path)

	// Safe templates and non-secret examples are never credential-bearing
	if strings.HasSuffix(lower, ".example") ||
		strings.HasSuffix(lower, ".sample") ||
		strings.HasSuffix(lower, ".template") ||
		strings.HasSuffix(lower, ".test") {
		return ""
	}

	switch {
	case strings.Contains(lower, ".env"):
		return "env"
	case strings.Contains(lower, ".npmrc") || strings.Contains(lower, ".yarnrc") || strings.Contains(lower, "pip.conf"):
		return "package_token"
	case strings.Contains(lower, ".aws/credentials") || strings.Contains(lower, ".aws/config"):
		return "cloud_credential"
	case strings.Contains(lower, ".ssh/id_") || strings.Contains(lower, ".ssh/authorized_keys"):
		return "ssh_key"
	case strings.Contains(lower, ".netrc") || strings.Contains(lower, ".git-credentials") || strings.Contains(lower, ".gitconfig"):
		return "git_credential"
	case strings.Contains(lower, "/etc/shadow") || strings.Contains(lower, "/etc/security"):
		return "system_auth"
	default:
		return ""
	}
}

func destHost(dest string) string {
	if host, _, err := net.SplitHostPort(dest); err == nil {
		return host
	}
	if strings.HasPrefix(dest, "[") && strings.HasSuffix(dest, "]") {
		return strings.Trim(dest, "[]")
	}
	return dest
}

// LoadJSONL reads spike or schema JSONL. Spike's TAINTED_EGRESS rows are
// ignored — findings are always recomputed.
func LoadJSONL(r io.Reader) ([]runschema.Event, error) {
	dec := json.NewDecoder(r)
	var out []runschema.Event
	for {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return out, nil
			}
			return nil, err
		}
		kind, _ := rec["kind"].(string)
		if kind == "" {
			kind, _ = rec["type"].(string)
		}
		if kind == "" || kind == "TAINTED_EGRESS" {
			continue
		}
		if kind != "exec" && kind != "open" && kind != "connect" && kind != "send" {
			continue
		}
		ev := runschema.Event{Kind: kind}
		if ts, ok := rec["ts"].(float64); ok {
			ev.TS = int64(ts)
		}
		if pid, ok := rec["pid"].(float64); ok {
			ev.PID = uint32(pid)
		}
		if ppid, ok := rec["ppid"].(float64); ok {
			ev.PPID = uint32(ppid)
		}
		if comm, ok := rec["comm"].(string); ok {
			ev.Comm = comm
		}
		if path, ok := rec["path"].(string); ok {
			ev.Path = path
		}
		if dest, ok := rec["dest"].(string); ok {
			ev.Dest = dest
		}
		if cmdline, ok := rec["cmdline"].(string); ok {
			ev.Cmdline = cmdline
		}
		if cwd, ok := rec["cwd"].(string); ok {
			ev.Cwd = cwd
		}
		if n, ok := rec["bytes_sent"].(float64); ok {
			ev.BytesSent = uint64(n)
		}
		out = append(out, ev)
	}
}

func LoadJSONLFile(path string) ([]runschema.Event, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadJSONL(f)
}

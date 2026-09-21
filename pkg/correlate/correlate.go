package correlate

import (
	"cmp"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/buildlens/buildlens/pkg/runschema"
)

const ruleTaintedEgress = "TAINTED_EGRESS"

// Score is deterministic: same events + same RulesetVersion => byte-identical
// findings. Uses only Event.TS, never time.Now.
func Score(events []runschema.Event) runschema.Manifest {
	sorted := slices.Clone(events)
	slices.SortFunc(sorted, cmpEvent)

	type mark struct {
		path string
		ts   int64
	}
	tainted := map[uint32]mark{}
	var findings []runschema.Finding

	for _, e := range sorted {
		switch e.Kind {
		case "open":
			if tier := fileTier(e.Path); tier != "" {
				tainted[e.PID] = mark{path: e.Path, ts: e.TS}
			}
		case "connect":
			m, ok := tainted[e.PID]
			if !ok {
				continue
			}
			elapsed := (e.TS - m.ts) / 1e6
			if elapsed < 0 {
				elapsed = 0
			}
			findings = append(findings, runschema.Finding{
				Rule:     ruleTaintedEgress,
				Severity: "critical",
				Aggregatable: runschema.FindingAgg{
					Package:   runschema.UnknownPackage(),
					DestHost:  destHost(e.Dest),
					FileTier:  fileTier(m.path),
					ElapsedMS: elapsed,
				},
				Context: runschema.FindingContext{
					PID:  e.PID,
					Comm: e.Comm,
					Path: m.path,
					Dest: e.Dest,
				},
			})
		}
	}

	slices.SortFunc(findings, cmpFinding)
	status := "clean"
	if len(findings) > 0 {
		status = "findings"
	}
	return runschema.Manifest{
		SchemaVersion:  runschema.SchemaVersion,
		RulesetVersion: runschema.RulesetVersion,
		Status:         status,
		EventCount:     len(events),
		Findings:       findings,
	}
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
	if strings.Contains(path, ".env") {
		return "env"
	}
	return ""
}

func destHost(dest string) string {
	host, _, ok := strings.Cut(dest, ":")
	if !ok {
		return dest
	}
	// ponytail: IPv4 host:port only; IPv6 stays as the full dest string.
	if strings.Count(dest, ":") > 1 {
		return dest
	}
	return host
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
		if kind != "exec" && kind != "open" && kind != "connect" {
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
		out = append(out, ev)
	}
}

func LoadJSONLFile(path string) ([]runschema.Event, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return LoadJSONL(f)
}

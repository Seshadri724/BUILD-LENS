// Package runschema is the replay-ready run ledger (ROADMAP M1.8).
// Aggregatable fields are a separate struct from repo-identifying context
// so fleet rollups cannot accidentally join on paths or repo names.
package runschema

const (
	SchemaVersion  = "1"
	RulesetVersion = "1.0.0"
)

// PackageID is the only key used for cross-run aggregation.
type PackageID struct {
	Ecosystem      string `json:"ecosystem"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	IntegrityHash  string `json:"integrity_hash"`
}

func (p PackageID) IsUnknown() bool {
	return p.Name == "" || p.Name == "unknown"
}

func UnknownPackage() PackageID {
	return PackageID{Name: "unknown"}
}

// Event is one kernel observation. TS is the event timestamp (unix nano),
// never wall clock at score time.
type Event struct {
	Kind string `json:"kind"`
	TS   int64  `json:"ts"`
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
	Path string `json:"path,omitempty"`
	Dest string `json:"dest,omitempty"`
}

// FindingAgg is safe to roll up across customers.
type FindingAgg struct {
	Package   PackageID `json:"package"`
	DestHost  string    `json:"dest_host"`
	FileTier  string    `json:"file_tier"`
	ElapsedMS int64     `json:"elapsed_ms"`
}

// FindingContext is repo-identifying. Must not enter aggregate pipelines.
type FindingContext struct {
	PID  uint32 `json:"pid"`
	Comm string `json:"comm"`
	Path string `json:"path"`
	Dest string `json:"dest"`
}

type Finding struct {
	Rule         string         `json:"rule"`
	Severity     string         `json:"severity"`
	Aggregatable FindingAgg     `json:"aggregatable"`
	Context      FindingContext `json:"context"`
}

type Manifest struct {
	SchemaVersion  string    `json:"schema_version"`
	RulesetVersion string    `json:"ruleset_version"`
	Status         string    `json:"status"` // clean | findings | degraded
	EventCount     int       `json:"event_count"`
	Findings       []Finding `json:"findings"`
}

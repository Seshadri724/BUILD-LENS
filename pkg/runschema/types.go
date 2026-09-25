// Package runschema is the replay-ready run ledger (ROADMAP M1.8).
// Aggregatable fields are a separate struct from repo-identifying context
// so fleet rollups cannot accidentally join on paths or repo names.
package runschema

const (
	SchemaVersion  = "1"
	RulesetVersion = "1.2.0"
)

// PackageID is the only key used for cross-run aggregation.
type PackageID struct {
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version,omitempty"`
	IntegrityHash string `json:"integrity_hash,omitempty"`
}

func (p PackageID) IsUnknown() bool {
	return p.Name == "" || p.Name == "unknown"
}

func UnknownPackage() PackageID {
	return PackageID{Name: "unknown"}
}

// Attribution captures the runtime observation evidence of a package.
type Attribution struct {
	Package    PackageID `json:"package"`
	Confidence string    `json:"confidence,omitempty"` // confirmed | probable | unknown
	Lifecycle  string    `json:"lifecycle,omitempty"`  // preinstall | install | postinstall | build | test | runtime | unknown
}

func (a Attribution) IsUnknown() bool {
	return a.Package.IsUnknown()
}

func UnknownAttribution() Attribution {
	return Attribution{
		Package:    UnknownPackage(),
		Confidence: "unknown",
		Lifecycle:  "unknown",
	}
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
	// Host is set on "dns" events: the name that resolved to Dest (an IP, no port).
	Host    string `json:"host,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	Cwd     string `json:"cwd,omitempty"`
	// BytesSent is set on "send" events: total bytes the kernel accepted from
	// PID for Dest over the whole run (tcp_sendmsg return values).
	BytesSent uint64 `json:"bytes_sent,omitempty"`
}

// AgentHealth reports telemetry, event drops, and degradation status.
type AgentHealth struct {
	Degraded       bool   `json:"degraded"`
	DegradedReason string `json:"degraded_reason,omitempty"`
	EventsSeen     uint64 `json:"events_seen"`
	EventsDropped  uint64 `json:"events_dropped"`
	KernelVersion  string `json:"kernel_version,omitempty"`
}

// FindingAgg is safe to roll up across customers.
type FindingAgg struct {
	Package   PackageID `json:"package"`
	DestHost  string    `json:"dest_host"`
	FileTier  string    `json:"file_tier"`
	ElapsedMS int64     `json:"elapsed_ms"`
	// BytesSent is nil when the run has no send telemetry (probe not attached
	// or old recording), so "not measured" is never reported as 0.
	BytesSent *uint64 `json:"bytes_sent,omitempty"`
}

// FindingContext is repo-identifying. Must not enter aggregate pipelines.
type FindingContext struct {
	PID          uint32      `json:"pid"`
	Comm         string      `json:"comm"`
	Path         string      `json:"path"`
	Dest         string      `json:"dest"`
	ProcessChain []string    `json:"process_chain,omitempty"`
	Cmdline      string      `json:"cmdline,omitempty"`
	Cwd          string      `json:"cwd,omitempty"`
	Fingerprint  string      `json:"fingerprint,omitempty"`
	Attribution  Attribution `json:"attribution,omitempty"`
}

type Finding struct {
	Rule         string         `json:"rule"`
	Severity     string         `json:"severity"`
	Aggregatable FindingAgg     `json:"aggregatable"`
	Context      FindingContext `json:"context"`
}

type Manifest struct {
	SchemaVersion  string      `json:"schema_version"`
	RulesetVersion string      `json:"ruleset_version"`
	Status         string      `json:"status"` // clean | findings | degraded
	EventCount     int         `json:"event_count"`
	AgentHealth    AgentHealth `json:"agent_health"`
	Findings       []Finding   `json:"findings"`
}

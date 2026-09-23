package agent

import (
	"time"
)

// RecordOptions controls agent event capture and output behavior.
type RecordOptions struct {
	OutPath  string
	Duration time.Duration
	Debug    bool
	StatsOut string
	Probes   string // "all", "exec", "open", "connect", "send"
	NoJSON   bool
}

// AgentStats tracks runtime telemetry and event counters.
type AgentStats struct {
	RuntimeMS        int64          `json:"runtime_ms"`
	EventsTotal      int            `json:"events_total"`
	RingBufferDrops  uint64         `json:"ring_buffer_drops"`
	FileSize         int64          `json:"file_size_bytes"`
	Counts           map[string]int `json:"counts"`
	AgentCPUTimeMS   int64          `json:"agent_cpu_time_ms"`
}

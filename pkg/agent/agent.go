package agent

import (
	"os"
	"strings"
	"time"
)

// RecordOptions controls agent event capture and output behavior.
type RecordOptions struct {
	OutPath  string
	Duration time.Duration
	Debug    bool
	StatsOut string
	Probes   string // "all", "exec", "open", "connect", "send", "dns" ("dns" = hostname resolution: UDP DNS + TLS SNI)
	NoJSON   bool
	// Enforce "audit" attaches the cgroup egress hook, which records
	// would-block observations but always allows (deny verdicts are Phase 2).
	// Anything else (including "off") records observe-only.
	Enforce string
}

// AgentStats tracks runtime telemetry and event counters.
type AgentStats struct {
	RuntimeMS       int64          `json:"runtime_ms"`
	EventsTotal     int            `json:"events_total"`
	RingBufferDrops uint64         `json:"ring_buffer_drops"`
	FileSize        int64          `json:"file_size_bytes"`
	Counts          map[string]int `json:"counts"`
	AgentCPUTimeMS  int64          `json:"agent_cpu_time_ms"`
}

// JobCgroupPath returns the cgroupv2 path of the current process for scoping
// the enforce hook to this job. ok=false on non-Linux, cgroupv1-only, masked
// hierarchies — and at the machine root, which must never be hooked (that
// would observe — and in Phase 2 gate — every job on the host).
func JobCgroupPath() (path string, ok bool) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	return ParseCgroupV2Path(string(b))
}

// ParseCgroupV2Path extracts the cgroupv2 path from /proc/self/cgroup
// content. Only the "0::/..." unified-hierarchy line counts.
func ParseCgroupV2Path(data string) (string, bool) {
	for _, ln := range strings.Split(data, "\n") {
		rest, found := strings.CutPrefix(ln, "0::")
		if !found || rest == "" || rest == "/" {
			continue
		}
		return "/sys/fs/cgroup" + rest, true
	}
	return "", false
}

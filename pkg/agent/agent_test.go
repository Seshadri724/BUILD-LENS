package agent_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/buildlens/buildlens/pkg/agent"
)

func TestAgentStatsSerialization(t *testing.T) {
	st := agent.AgentStats{
		RuntimeMS:       1250,
		EventsTotal:     42,
		RingBufferDrops: 0,
		FileSize:        1024,
		AgentCPUTimeMS:  15,
		Counts: map[string]int{
			"exec":    10,
			"open":    30,
			"connect": 2,
		},
	}

	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded agent.AgentStats
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.EventsTotal != 42 {
		t.Errorf("events_total = %d, want 42", decoded.EventsTotal)
	}
	if decoded.RingBufferDrops != 0 {
		t.Errorf("ring_buffer_drops = %d, want 0", decoded.RingBufferDrops)
	}
	if decoded.Counts["exec"] != 10 {
		t.Errorf("counts['exec'] = %d, want 10", decoded.Counts["exec"])
	}
}

func TestRecordOptionsDefaults(t *testing.T) {
	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "events.jsonl")

	opts := agent.RecordOptions{
		OutPath:  outPath,
		Duration: 50 * time.Millisecond,
		Debug:    false,
		Probes:   "all",
	}

	// Should execute gracefully (either live or fail-open depending on OS/BTF)
	err := agent.Record(opts)
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	// Done marker should be created on exit
	donePath := outPath + ".done"
	if _, err := os.Stat(donePath); os.IsNotExist(err) {
		t.Errorf("expected done marker %s to exist", donePath)
	}
}

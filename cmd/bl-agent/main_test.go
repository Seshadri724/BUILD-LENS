package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/buildlens/buildlens/pkg/runschema"
)

func TestScoreMissingEventFileReportsDegraded(t *testing.T) {
	tempDir := t.TempDir()
	outManifest := filepath.Join(tempDir, "manifest.json")
	missingFile := filepath.Join(tempDir, "does-not-exist.jsonl")

	err := score([]string{"-in", missingFile, "-out", outManifest})
	if err != nil {
		t.Fatalf("score command should succeed without crashing: %v", err)
	}

	b, err := os.ReadFile(outManifest)
	if err != nil {
		t.Fatalf("manifest not written: %v", err)
	}

	var m runschema.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	if m.Status != "degraded" {
		t.Errorf("expected status 'degraded' when event file is missing, got %q", m.Status)
	}
	if !m.AgentHealth.Degraded {
		t.Errorf("expected AgentHealth.Degraded to be true")
	}
	if m.AgentHealth.DegradedReason == "" {
		t.Errorf("expected non-empty DegradedReason")
	}
}

func TestScoreEmptyPathReportsDegraded(t *testing.T) {
	tempDir := t.TempDir()
	outManifest := filepath.Join(tempDir, "manifest.json")

	err := score([]string{"-out", outManifest})
	if err != nil {
		t.Fatalf("score should succeed: %v", err)
	}

	b, err := os.ReadFile(outManifest)
	if err != nil {
		t.Fatalf("manifest not written: %v", err)
	}

	var m runschema.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	if m.Status != "degraded" {
		t.Errorf("expected status 'degraded' when no -in flag passed, got %q", m.Status)
	}
}

func TestScoreStatsWithDropsReportsDegraded(t *testing.T) {
	tempDir := t.TempDir()
	outManifest := filepath.Join(tempDir, "manifest.json")
	eventsFile := filepath.Join(tempDir, "events.jsonl")
	statsFile := filepath.Join(tempDir, "stats.json")

	// Write 1 benign event
	if err := os.WriteFile(eventsFile, []byte("{\"type\":\"exec\",\"ts\":1,\"pid\":10,\"comm\":\"node\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write stats with ring buffer drops
	statsJSON := `{"runtime_ms": 500, "events_total": 1, "ring_buffer_drops": 5}`
	if err := os.WriteFile(statsFile, []byte(statsJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	err := score([]string{"-in", eventsFile, "-stats", statsFile, "-out", outManifest})
	if err != nil {
		t.Fatalf("score failed: %v", err)
	}

	b, err := os.ReadFile(outManifest)
	if err != nil {
		t.Fatalf("manifest not written: %v", err)
	}

	var m runschema.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	if m.Status != "degraded" {
		t.Errorf("expected status 'degraded' when drops > 0, got %q", m.Status)
	}
	if !m.AgentHealth.Degraded {
		t.Errorf("expected AgentHealth.Degraded = true")
	}
	if m.AgentHealth.EventsDropped != 5 {
		t.Errorf("expected EventsDropped = 5, got %d", m.AgentHealth.EventsDropped)
	}
}

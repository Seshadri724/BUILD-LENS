package correlate_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/buildlens/buildlens/pkg/correlate"
	"github.com/buildlens/buildlens/pkg/runschema"
)

func TestScoreTaintedEnvPost(t *testing.T) {
	m := scoreFile(t, "tainted-env-post")
	if m.Status != "findings" || len(m.Findings) != 1 {
		t.Fatalf("status=%s n=%d", m.Status, len(m.Findings))
	}
	f := m.Findings[0]
	if f.Rule != "TAINTED_EGRESS" || f.Aggregatable.FileTier != "env" || f.Aggregatable.DestHost != "127.0.0.1" {
		t.Fatalf("finding: %+v", f)
	}
	if f.Aggregatable.ElapsedMS != 31 {
		t.Fatalf("elapsed_ms=%d", f.Aggregatable.ElapsedMS)
	}
	if !f.Aggregatable.Package.IsUnknown() {
		t.Fatalf("package should be unknown until attribution ships: %+v", f.Aggregatable.Package)
	}
}

func TestScoreClean(t *testing.T) {
	m := scoreFile(t, "clean-npm-ci")
	if m.Status != "clean" || len(m.Findings) != 0 {
		t.Fatalf("got %+v", m)
	}
}

func TestScoreReplayDeterministic(t *testing.T) {
	events := load(t, "tainted-env-post")
	a, err := json.Marshal(correlate.Score(events).Findings)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(correlate.Score(events).Findings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("replay produced different findings")
	}
}

func TestScoreShuffledInputSameFindings(t *testing.T) {
	events := load(t, "tainted-env-post")
	reversed := []runschema.Event{events[1], events[0]}
	want, _ := json.Marshal(correlate.Score(events).Findings)
	got, _ := json.Marshal(correlate.Score(reversed).Findings)
	if !bytes.Equal(want, got) {
		t.Fatalf("order leaked into findings\nwant %s\ngot  %s", want, got)
	}
}

func scoreFile(t *testing.T, name string) runschema.Manifest {
	t.Helper()
	return correlate.Score(load(t, name))
}

func load(t *testing.T, name string) []runschema.Event {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "corpus", name, "events.jsonl")
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := correlate.LoadJSONL(f)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

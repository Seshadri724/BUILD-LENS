package correlate_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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

func TestAncestorTaintInheritance(t *testing.T) {
	events := []runschema.Event{
		{
			Kind:    "exec",
			TS:      1000000000,
			PID:     100,
			PPID:    1,
			Comm:    "node",
			Cmdline: "node postinstall.js",
			Cwd:     "/repo/node_modules/suspicious-dep",
		},
		{
			Kind: "open",
			TS:   1001000000,
			PID:  100,
			PPID: 1,
			Comm: "node",
			Path: "/home/runner/work/repo/.env",
		},
		{
			Kind: "exec",
			TS:   1020000000,
			PID:  101,
			PPID: 100,
			Comm: "sh",
		},
		{
			Kind: "exec",
			TS:   1030000000,
			PID:  102,
			PPID: 101,
			Comm: "curl",
		},
		{
			Kind: "connect",
			TS:   1044000000,
			PID:  102,
			PPID: 101,
			Comm: "curl",
			Dest: "93.184.216.34:443",
		},
	}

	m := correlate.Score(events)
	if m.Status != "findings" || len(m.Findings) != 1 {
		t.Fatalf("expected 1 finding, got status=%s count=%d", m.Status, len(m.Findings))
	}

	f := m.Findings[0]
	if f.Context.PID != 102 || f.Context.Comm != "curl" {
		t.Errorf("expected child curl PID 102, got pid=%d comm=%s", f.Context.PID, f.Context.Comm)
	}
	if f.Aggregatable.Package.Name != "suspicious-dep" {
		t.Errorf("expected attributed package suspicious-dep, got %s", f.Aggregatable.Package.Name)
	}
	if f.Context.Attribution.Lifecycle != "postinstall" {
		t.Errorf("expected postinstall lifecycle, got %s", f.Context.Attribution.Lifecycle)
	}
	if f.Aggregatable.DestHost != "93.184.216.34" {
		t.Errorf("expected dest 93.184.216.34, got %s", f.Aggregatable.DestHost)
	}
	if f.Aggregatable.FileTier != "env" {
		t.Errorf("expected env tier, got %s", f.Aggregatable.FileTier)
	}
	if f.Aggregatable.ElapsedMS != 43 {
		t.Errorf("expected 43ms elapsed, got %d", f.Aggregatable.ElapsedMS)
	}
	expectedChain := []string{"node", "sh", "curl"}
	if len(f.Context.ProcessChain) != len(expectedChain) {
		t.Errorf("process chain length mismatch: %+v", f.Context.ProcessChain)
	} else {
		for i, c := range expectedChain {
			if f.Context.ProcessChain[i] != c {
				t.Errorf("chain[%d] = %s, want %s", i, f.Context.ProcessChain[i], c)
			}
		}
	}
	if f.Context.Fingerprint == "" {
		t.Errorf("expected non-empty deterministic fingerprint")
	}
}

func TestTaintExpiration(t *testing.T) {
	events := []runschema.Event{
		{
			Kind: "open",
			TS:   1000000000,
			PID:  50,
			Comm: "node",
			Path: "/repo/.env",
		},
		{
			// Connect 5 minutes later (exceeding default 60s window)
			Kind: "connect",
			TS:   1000000000 + (300 * 1e9),
			PID:  50,
			Comm: "node",
			Dest: "1.2.3.4:443",
		},
	}

	m := correlate.Score(events)
	if m.Status != "clean" || len(m.Findings) != 0 {
		t.Errorf("expected expired taint to result in clean status, got: %+v", m)
	}
}

func TestDeduplication(t *testing.T) {
	events := []runschema.Event{
		{Kind: "open", TS: 1000000000, PID: 70, Comm: "node", Path: "/repo/.env"},
		{Kind: "connect", TS: 1010000000, PID: 70, Comm: "node", Dest: "api.drop.com:443"},
		{Kind: "connect", TS: 1020000000, PID: 70, Comm: "node", Dest: "api.drop.com:443"},
		{Kind: "connect", TS: 1030000000, PID: 70, Comm: "node", Dest: "api.drop.com:443"},
	}

	m := correlate.Score(events)
	if len(m.Findings) != 1 {
		t.Fatalf("expected duplicate connects to be deduplicated to 1 finding, got %d", len(m.Findings))
	}
}

func TestAgentHealthDegradation(t *testing.T) {
	events := []runschema.Event{
		{Kind: "exec", TS: 1, PID: 10, Comm: "npm"},
	}
	m := correlate.ScoreWithOptions(events, correlate.ScoreOptions{
		AgentHealth: runschema.AgentHealth{
			Degraded:       true,
			DegradedReason: "ring_buffer_drop",
			EventsDropped:  4,
		},
	})
	if m.Status != "degraded" {
		t.Errorf("expected status degraded when drops occur, got %s", m.Status)
	}
}

func installScriptEgressEvents() []runschema.Event {
	return []runschema.Event{
		{
			Kind:    "exec",
			TS:      1000000000,
			PID:     200,
			PPID:    100,
			Comm:    "node",
			Cmdline: "node node_modules/puppy-helper/postinstall.js",
			Cwd:     "/repo/node_modules/puppy-helper",
		},
		{
			Kind: "connect",
			TS:   1001000000,
			PID:  200,
			PPID: 100,
			Comm: "node",
			Dest: "198.51.100.7:443",
		},
	}
}

func TestInstallScriptEgressFiresByDefault(t *testing.T) {
	m := correlate.Score(installScriptEgressEvents())
	if m.Status != "findings" || len(m.Findings) != 1 {
		t.Fatalf("status=%s n=%d", m.Status, len(m.Findings))
	}
	if m.Findings[0].Rule != "INSTALL_SCRIPT_EGRESS" {
		t.Fatalf("rule=%s", m.Findings[0].Rule)
	}
}

func TestAllowHostsSuppressesInstallScriptEgress(t *testing.T) {
	m := correlate.ScoreWithOptions(installScriptEgressEvents(), correlate.ScoreOptions{
		AllowHosts: []string{"198.51.100.7"},
	})
	if m.Status != "clean" || len(m.Findings) != 0 {
		t.Fatalf("allowlisted IP should be clean, got status=%s findings=%d", m.Status, len(m.Findings))
	}

	// Hostname matching is case-insensitive and tolerates a :port suffix.
	dnsEvents := []runschema.Event{
		{
			Kind:    "exec",
			TS:      1000000000,
			PID:     201,
			PPID:    100,
			Comm:    "node",
			Cmdline: "node node_modules/puppy-helper/postinstall.js",
			Cwd:     "/repo/node_modules/puppy-helper",
		},
		{Kind: "dns", TS: 1000500000, Host: "cdn.custom.example", Dest: "198.51.100.8"},
		{Kind: "connect", TS: 1001000000, PID: 201, PPID: 100, Comm: "node", Dest: "198.51.100.8:443"},
	}
	m = correlate.ScoreWithOptions(dnsEvents, correlate.ScoreOptions{
		AllowHosts: []string{"CDN.Custom.Example:443"},
	})
	if m.Status != "clean" || len(m.Findings) != 0 {
		t.Fatalf("allowlisted hostname should be clean, got status=%s findings=%d", m.Status, len(m.Findings))
	}

	// An unrelated allow entry must not silence the finding.
	m = correlate.ScoreWithOptions(installScriptEgressEvents(), correlate.ScoreOptions{
		AllowHosts: []string{"other.example"},
	})
	if m.Status != "findings" || len(m.Findings) != 1 {
		t.Fatalf("unrelated allow-host should still fire, got status=%s n=%d", m.Status, len(m.Findings))
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

func TestBytesSentAttachedToFinding(t *testing.T) {
	events := []runschema.Event{
		{Kind: "open", TS: 1000, PID: 7, PPID: 1, Comm: "node", Path: "/repo/.env"},
		{Kind: "connect", TS: 2000, PID: 7, PPID: 1, Comm: "node", Dest: "[2001:db8::1]:443"},
		{Kind: "send", TS: 9000, PID: 7, Dest: "[2001:db8::1]:443", BytesSent: 1204},
		{Kind: "send", TS: 9000, PID: 8, Dest: "[2001:db8::1]:443", BytesSent: 99},
	}
	m := correlate.Score(events)
	if len(m.Findings) != 1 {
		t.Fatalf("findings=%d", len(m.Findings))
	}
	if b := m.Findings[0].Aggregatable.BytesSent; b == nil || *b != 1204 {
		t.Fatalf("bytes_sent=%v", b)
	}

	// No send telemetry at all: bytes are unknown, not zero.
	m = correlate.Score(events[:2])
	if b := m.Findings[0].Aggregatable.BytesSent; b != nil {
		t.Fatalf("bytes_sent should be nil without telemetry, got %d", *b)
	}
}

func TestAgentActivityReport(t *testing.T) {
	events, err := correlate.LoadJSONLFile(filepath.Join("..", "..", "testdata", "corpus", "clean-agent-session", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	m := correlate.Score(events)
	if len(m.Agents) != 1 || m.Agents[0].Agent != "claude-code" {
		t.Fatalf("agents = %+v, want one claude-code entry", m.Agents)
	}
	a := m.Agents[0]
	wantCmds := []string{
		"bash -c git status",
		"git status",
		"bash -c curl -H 'Authorization: Bearer ***' https://example.test",
		"git push origin fix-failing-test",
		"git-remote-https origin https://github.com/org/app",
	}
	if !slices.Equal(a.Commands, wantCmds) {
		t.Errorf("commands (in order, token masked, agent prompt left out):\n got %q\nwant %q", a.Commands, wantCmds)
	}
	// git's own .git/config read is skipped like any git process; .env is the agent's.
	if want := []string{"/home/runner/work/app/app/.env"}; !slices.Equal(a.SecretFiles, want) {
		t.Errorf("secret files = %q, want %q", a.SecretFiles, want)
	}
	if want := []string{"api.anthropic.com", "github.com"}; !slices.Equal(a.Hosts, want) {
		t.Errorf("hosts = %q, want %q", a.Hosts, want)
	}

	events, err = correlate.LoadJSONLFile(filepath.Join("..", "..", "testdata", "corpus", "agent-prompt-injection-exfil", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	m = correlate.Score(events)
	if len(m.Findings) != 1 || m.Findings[0].Context.Agent != "claude-code" {
		t.Fatalf("want one finding tagged agent=claude-code, got %+v", m.Findings)
	}
}

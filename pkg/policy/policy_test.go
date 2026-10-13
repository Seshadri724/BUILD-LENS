package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buildlens/buildlens/pkg/policy"
)

var run1 = []string{
	`{"kind":"exec","ts":1000000000,"pid":10,"ppid":1,"comm":"bash","cmdline":"bash -c npm ci","cwd":"/repo"}`,
	`{"kind":"exec","ts":1001000000,"pid":11,"ppid":10,"comm":"npm","cmdline":"npm ci","cwd":"/repo"}`,
	`{"kind":"dns","ts":1002000000,"host":"registry.npmjs.org","dest":"104.16.0.35"}`,
	`{"kind":"connect","ts":1003000000,"pid":11,"ppid":10,"comm":"npm","dest":"104.16.0.35:443"}`,
	`{"kind":"connect","ts":1004000000,"pid":11,"ppid":10,"comm":"npm","dest":"104.16.0.35:443"}`,
	`{"kind":"exec","ts":1005000000,"pid":12,"ppid":11,"comm":"node","cmdline":"node node_modules/puppy-helper/postinstall.js","cwd":"/repo/node_modules/puppy-helper"}`,
	`{"kind":"dns","ts":1006000000,"host":"cdn.custom.example","dest":"198.51.100.8"}`,
	`{"kind":"connect","ts":1007000000,"pid":12,"ppid":11,"comm":"node","dest":"198.51.100.8:443"}`,
	`{"kind":"connect","ts":1008000000,"pid":12,"ppid":11,"comm":"node","dest":"203.0.113.77:443"}`,
}

var run2 = []string{
	`{"kind":"exec","ts":2000000000,"pid":10,"ppid":1,"comm":"bash","cmdline":"bash -c npm ci","cwd":"/repo"}`,
	`{"kind":"exec","ts":2001000000,"pid":11,"ppid":10,"comm":"npm","cmdline":"npm ci","cwd":"/repo"}`,
	`{"kind":"dns","ts":2002000000,"host":"registry.npmjs.org","dest":"104.16.0.35"}`,
	`{"kind":"connect","ts":2003000000,"pid":11,"ppid":10,"comm":"npm","dest":"104.16.0.35:443"}`,
	`{"kind":"connect","ts":2004000000,"pid":11,"ppid":10,"comm":"npm","dest":"127.0.0.1:3000"}`,
}

func writeRun(t *testing.T, name string, lines []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func findRecord(recs []policy.Record, host, pkg string) *policy.Record {
	for i, r := range recs {
		if r.Host == host && r.Package == pkg {
			return &recs[i]
		}
	}
	return nil
}

func TestSummarizeMergesRuns(t *testing.T) {
	r1, r2 := writeRun(t, "run1.jsonl", run1), writeRun(t, "run2.jsonl", run2)
	recs, st, err := policy.SummarizeFiles([]string{r1, r2}, "")
	if err != nil {
		t.Fatal(err)
	}
	if st.Runs != 2 || st.Events != 14 {
		t.Fatalf("stats=%+v, want runs=2 events=14", st)
	}

	reg := findRecord(recs, "registry.npmjs.org", "unknown")
	if reg == nil {
		t.Fatalf("missing registry record: %+v", recs)
	}
	if reg.Connects != 3 || reg.Runs != 2 {
		t.Errorf("registry=%+v, want connects=3 runs=2", reg)
	}

	cdn := findRecord(recs, "cdn.custom.example", "puppy-helper")
	if cdn == nil {
		t.Fatalf("missing cdn record: %+v", recs)
	}
	if cdn.Connects != 1 || cdn.Runs != 1 {
		t.Errorf("cdn=%+v, want connects=1 runs=1", cdn)
	}
	if cdn.Lifecycle != "postinstall" {
		t.Errorf("cdn lifecycle=%q, want postinstall", cdn.Lifecycle)
	}

	// Loopback is noise, never policy.
	if r := findRecord(recs, "127.0.0.1", "unknown"); r != nil {
		t.Errorf("loopback must be excluded, got %+v", r)
	}
}

func TestJSONLRoundTrip(t *testing.T) {
	r1 := writeRun(t, "run1.jsonl", run1)
	recs, _, err := policy.SummarizeFiles([]string{r1}, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := policy.MarshalJSONL(recs)
	if err != nil {
		t.Fatal(err)
	}
	ledger := writeRun(t, "observed.jsonl", strings.Split(strings.TrimSpace(string(raw)), "\n"))
	again, _, err := policy.SummarizeFiles([]string{ledger}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != len(recs) {
		t.Fatalf("round trip changed record count: %d != %d", len(again), len(recs))
	}
	for i := range recs {
		if again[i] != recs[i] {
			t.Fatalf("record %d changed:\n%+v\n%+v", i, again[i], recs[i])
		}
	}
}

func TestPolicyYAMLShape(t *testing.T) {
	r1, r2 := writeRun(t, "run1.jsonl", run1), writeRun(t, "run2.jsonl", run2)
	recs, st, err := policy.SummarizeFiles([]string{r1, r2}, "")
	if err != nil {
		t.Fatal(err)
	}
	y1, err := policy.MarshalYAMLPolicy(recs, st)
	if err != nil {
		t.Fatal(err)
	}
	y2, err := policy.MarshalYAMLPolicy(recs, st)
	if err != nil {
		t.Fatal(err)
	}
	if string(y1) != string(y2) {
		t.Fatal("policy YAML is not deterministic")
	}
	s := string(y1)
	for _, want := range []string{
		"runs_observed: 2",
		"host: registry.npmjs.org",
		"host: cdn.custom.example",
		"puppy-helper",
		"no DNS name observed (hardcoded IP?)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("policy YAML missing %q:\n%s", want, s)
		}
	}
	// Aggregates only: no argv, no file paths.
	for _, leak := range []string{"bash -c npm ci", "postinstall.js", ".env", "SECRET"} {
		if strings.Contains(s, leak) {
			t.Errorf("policy YAML leaked %q:\n%s", leak, s)
		}
	}
}

func TestEmptyInput(t *testing.T) {
	p := writeRun(t, "empty.jsonl", []string{})
	recs, _, err := policy.SummarizeFiles([]string{p}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no records, got %+v", recs)
	}
}

func TestLegacyTypeKeyAndQuietRuns(t *testing.T) {
	// Older fixtures key events with "type"; a run with no egress is still a
	// baseline run and must count toward runs_observed.
	legacy := writeRun(t, "legacy.jsonl", []string{
		`{"type":"exec","ts":1,"pid":10,"ppid":1,"comm":"npm"}`,
		`{"type":"open","ts":2,"pid":10,"ppid":1,"comm":"npm","path":"/usr/bin/node"}`,
	})
	r1 := writeRun(t, "run1.jsonl", run1)
	recs, st, err := policy.SummarizeFiles([]string{legacy, r1}, "")
	if err != nil {
		t.Fatal(err)
	}
	if st.Runs != 2 {
		t.Fatalf("stats=%+v, quiet legacy run must count: want runs=2", st)
	}
	reg := findRecord(recs, "registry.npmjs.org", "unknown")
	if reg == nil || reg.Runs != 1 {
		t.Fatalf("registry=%+v, want runs=1", reg)
	}

	if _, _, err := policy.SummarizeFiles([]string{writeRun(t, "junk.jsonl", []string{`{"foo":1}`})}, ""); err == nil {
		t.Fatal("unrecognized input must error, not silently drop")
	}
}

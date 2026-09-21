// Command bl-agent scores a JSONL event stream into a run manifest + SARIF,
// and manages background recording with fail-open lifecycle hooks.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/buildlens/buildlens/pkg/agent"
	"github.com/buildlens/buildlens/pkg/correlate"
	"github.com/buildlens/buildlens/pkg/runschema"
	"github.com/buildlens/buildlens/pkg/sarif"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bl-agent <score|record> [options]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "score":
		if err := score(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "bl-agent score: %v\n", err)
			os.Exit(1)
		}
	case "record":
		if err := record(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "bl-agent record: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "bl-agent: unknown command %q — exiting 0 (fail-open)\n", os.Args[1])
	}
}

func score(args []string) error {
	fs := flag.NewFlagSet("score", flag.ContinueOnError)
	in := fs.String("in", "", "JSONL events (spike or schema)")
	out := fs.String("out", "buildlens-manifest.json", "manifest JSON output")
	sarifPath := fs.String("sarif", "", "optional SARIF output path")
	lockfile := fs.String("lockfile", "package-lock.json", "path to package-lock.json for attribution")
	statsPath := fs.String("stats", "", "optional path to agent stats JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var m runschema.Manifest
	if *in == "" {
		m = runschema.Manifest{
			SchemaVersion:  runschema.SchemaVersion,
			RulesetVersion: runschema.RulesetVersion,
			Status:         "degraded",
			AgentHealth: runschema.AgentHealth{
				Degraded:       true,
				DegradedReason: "event_file_missing: no input file provided",
			},
		}
	} else {
		events, err := correlate.LoadJSONLFile(*in)
		if err != nil {
			// A missing event file MUST NOT generate a clean manifest
			reason := fmt.Sprintf("event_file_error: %v", err)
			if errors.Is(err, os.ErrNotExist) {
				reason = "event_file_missing: file does not exist"
			}
			m = runschema.Manifest{
				SchemaVersion:  runschema.SchemaVersion,
				RulesetVersion: runschema.RulesetVersion,
				Status:         "degraded",
				AgentHealth: runschema.AgentHealth{
					Degraded:       true,
					DegradedReason: reason,
				},
			}
		} else {
			var health runschema.AgentHealth
			if *statsPath != "" {
				stBytes, err := os.ReadFile(*statsPath)
				if err != nil {
					health.Degraded = true
					health.DegradedReason = fmt.Sprintf("stats_file_missing: %v", err)
				} else {
					var st agent.AgentStats
					if err := json.Unmarshal(stBytes, &st); err != nil {
						health.Degraded = true
						health.DegradedReason = fmt.Sprintf("stats_file_invalid: %v", err)
					} else {
						health.EventsSeen = uint64(st.EventsTotal)
						health.EventsDropped = st.RingBufferDrops
						if st.RingBufferDrops > 0 {
							health.Degraded = true
							health.DegradedReason = fmt.Sprintf("ring_buffer_drop: %d event(s) dropped by kernel", st.RingBufferDrops)
						}
					}
				}
			}

			m = correlate.ScoreWithOptions(events, correlate.ScoreOptions{
				LockfilePath: *lockfile,
				AgentHealth:  health,
			})
		}
	}

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	if *sarifPath != "" {
		if err := sarif.WriteFile(*sarifPath, m); err != nil {
			return err
		}
	}

	// Write to GITHUB_STEP_SUMMARY if available
	if summaryPath := os.Getenv("GITHUB_STEP_SUMMARY"); summaryPath != "" {
		summaryMd := sarif.GenerateStepSummary(m)
		if f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			_, _ = f.WriteString(summaryMd)
			f.Close()
		}
	}

	// Print concise summary
	printSummary(m)
	return nil
}


func printSummary(m runschema.Manifest) {
	if m.Status == "degraded" {
		fmt.Printf("BuildLens — degraded (reason: %s)\n", m.AgentHealth.DegradedReason)
		return
	}

	fmt.Printf("BuildLens — %s, %d findings, %d unique dest hosts (ruleset %s)\n",
		m.Status, len(m.Findings), uniqueDests(m), m.RulesetVersion)

	for _, f := range m.Findings {
		pkgName := f.Aggregatable.Package.Name
		if pkgName == "" {
			pkgName = "unknown"
		}
		chain := strings.Join(f.Context.ProcessChain, " → ")
		if chain == "" {
			chain = f.Context.Comm
		}
		fmt.Printf("  • [%s] %s | pkg: %s | file: %s | dest: %s | chain: %s\n",
			f.Severity, f.Rule, pkgName, f.Context.Path, f.Aggregatable.DestHost, chain)
	}
}

func uniqueDests(m runschema.Manifest) int {
	seen := map[string]struct{}{}
	for _, f := range m.Findings {
		seen[f.Aggregatable.DestHost] = struct{}{}
	}
	return len(seen)
}


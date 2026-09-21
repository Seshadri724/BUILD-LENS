// Command bl-agent scores a JSONL event stream into a run manifest + SARIF.
// Probe attach is still the spike; this is the product-shaped output path.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/buildlens/buildlens/pkg/correlate"
	"github.com/buildlens/buildlens/pkg/runschema"
	"github.com/buildlens/buildlens/pkg/sarif"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bl-agent score -in events.jsonl -out manifest.json [-sarif results.sarif]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "score":
		if err := score(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "bl-agent: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "bl-agent: unknown command %q — exiting 0 (fail-open)\n", os.Args[1])
	}
}

func score(args []string) error {
	fs := flag.NewFlagSet("score", flag.ContinueOnError)
	in := fs.String("in", "", "JSONL events (spike or schema); missing file fail-opens to clean")
	out := fs.String("out", "buildlens-manifest.json", "manifest JSON")
	sarifPath := fs.String("sarif", "", "optional SARIF path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	events, err := correlate.LoadJSONLFile(*in)
	if err != nil {
		return err
	}
	m := correlate.Score(events)
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
	fmt.Printf("BuildLens — %s, %d findings, %d unique dest hosts (ruleset %s)\n",
		m.Status, len(m.Findings), uniqueDests(m), m.RulesetVersion)
	return nil
}

func uniqueDests(m runschema.Manifest) int {
	seen := map[string]struct{}{}
	for _, f := range m.Findings {
		seen[f.Aggregatable.DestHost] = struct{}{}
	}
	return len(seen)
}

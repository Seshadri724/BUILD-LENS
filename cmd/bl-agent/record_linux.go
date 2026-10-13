//go:build linux

package main

import (
	"flag"

	"github.com/buildlens/buildlens/pkg/agent"
)

func record(args []string) error {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	out := fs.String("out", "/tmp/buildlens/events.jsonl", "events output file")
	duration := fs.Duration("duration", 0, "max capture duration (0 for until signal)")
	debug := fs.Bool("debug", false, "stream raw events")
	probes := fs.String("probes", "all", "which probes to attach (all, exec, open, connect, send, dns)")
	noJSON := fs.Bool("no-json", false, "disable json file output")
	statsOut := fs.String("stats-out", "", "optional telemetry stats output file")
	enforce := fs.String("enforce", "off", "egress enforcement: off (default) or audit (attach cgroup hook that logs would-block egress but always allows)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	return agent.Record(agent.RecordOptions{
		OutPath:  *out,
		Duration: *duration,
		Debug:    *debug,
		Probes:   *probes,
		NoJSON:   *noJSON,
		StatsOut: *statsOut,
		Enforce:  *enforce,
	})
}

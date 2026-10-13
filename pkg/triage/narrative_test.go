package triage_test

import (
	"strings"
	"testing"

	"github.com/buildlens/buildlens/pkg/runschema"
	"github.com/buildlens/buildlens/pkg/triage"
)

func taintedFinding() runschema.Finding {
	b := uint64(760)
	return runschema.Finding{
		Rule:     "TAINTED_EGRESS",
		Severity: "critical",
		Aggregatable: runschema.FindingAgg{
			Package:   runschema.PackageID{Ecosystem: "npm", Name: "env-grabber", Version: "9.9.9"},
			DestHost:  "harvest.env-grab.example",
			FileTier:  "runner_env",
			ElapsedMS: 45,
			BytesSent: &b,
		},
		Context: runschema.FindingContext{
			PID:          950,
			Comm:         "node",
			Path:         "/home/runner/work/_temp/_runner_file_commands/add_env_b4a5520c",
			Dest:         "198.51.100.90:443",
			ProcessChain: []string{"node"},
			Cmdline:      "node postinstall.js --token SECRET-VALUE-xyz",
			Cwd:          "/repo/node_modules/env-grabber",
			Fingerprint:  "abc123fp",
			Attribution: runschema.Attribution{
				Package:    runschema.PackageID{Ecosystem: "npm", Name: "env-grabber", Version: "9.9.9"},
				Confidence: "confirmed",
				Lifecycle:  "postinstall",
			},
		},
	}
}

func TestRenderTaintedEgress(t *testing.T) {
	out := triage.Render(taintedFinding())
	for _, want := range []string{
		"TAINTED_EGRESS", "env-grabber@9.9.9", "npm uninstall env-grabber",
		"760", "45 ms", "abc123fp", "runner_env", "add_env_b4a5520c",
		"/repo/node_modules/env-grabber", "Rotate the exposed secret",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("narrative missing %q:\n%s", want, out)
		}
	}
	// Cmdline may carry tokens: it must never reach the narrative.
	if strings.Contains(out, "SECRET-VALUE-xyz") {
		t.Errorf("narrative leaked cmdline secret:\n%s", out)
	}
}

func TestRenderInstallScriptEgress(t *testing.T) {
	f := runschema.Finding{
		Rule:     "INSTALL_SCRIPT_EGRESS",
		Severity: "high",
		Aggregatable: runschema.FindingAgg{
			Package:  runschema.PackageID{Ecosystem: "npm", Name: "quiet-beacon", Version: "1.0.0"},
			DestHost: "203.0.113.77",
		},
		Context: runschema.FindingContext{
			PID:          11,
			Comm:         "node",
			Dest:         "203.0.113.77:443",
			ProcessChain: []string{"npm", "node"},
			Fingerprint:  "fp99",
			Attribution: runschema.Attribution{
				Package:    runschema.PackageID{Ecosystem: "npm", Name: "quiet-beacon", Version: "1.0.0"},
				Confidence: "probable",
				Lifecycle:  "postinstall",
			},
		},
	}
	out := triage.Render(f)
	for _, want := range []string{"INSTALL_SCRIPT_EGRESS", "203.0.113.77", "npm uninstall quiet-beacon"} {
		if !strings.Contains(out, want) {
			t.Errorf("narrative missing %q:\n%s", want, out)
		}
	}
	// No credential tier involved: no rotate note.
	if strings.Contains(out, "Rotate the exposed secret") {
		t.Errorf("unexpected rotate note without credential tier:\n%s", out)
	}
}

func TestRenderAgentExfil(t *testing.T) {
	f := taintedFinding()
	f.Aggregatable.Package = runschema.PackageID{Ecosystem: "agent", Name: "claude-code"}
	f.Context.Agent = "claude-code"
	out := triage.Render(f)
	if !strings.Contains(out, "prompt injection") {
		t.Errorf("agent finding must carry prompt-injection guidance:\n%s", out)
	}
	if !strings.Contains(out, "claude-code") {
		t.Errorf("agent finding must name the agent:\n%s", out)
	}
	// There is no dependency to uninstall when the agent itself is blamed.
	if strings.Contains(out, "npm uninstall claude-code") {
		t.Errorf("must not suggest uninstalling the agent:\n%s", out)
	}
}

func TestRenderUnknownPackage(t *testing.T) {
	f := taintedFinding()
	f.Aggregatable.Package = runschema.PackageID{}
	f.Context.Attribution = runschema.Attribution{}
	out := triage.Render(f)
	if !strings.Contains(out, "Identify the responsible dependency") {
		t.Errorf("unknown package must direct to the process chain:\n%s", out)
	}
	if strings.Contains(out, "npm uninstall") {
		t.Errorf("must not emit a broken uninstall for unknown package:\n%s", out)
	}
}

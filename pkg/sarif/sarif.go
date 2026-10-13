package sarif

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/buildlens/buildlens/pkg/runschema"
	"github.com/buildlens/buildlens/pkg/triage"
)

type logFile struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	Version        string `json:"version"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID               string `json:"id"`
	ShortDescription text   `json:"shortDescription"`
	HelpURI          string `json:"helpUri,omitempty"`
}

type text struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           *region          `json:"region,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             text              `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

func FromManifest(m runschema.Manifest) logFile {
	results := make([]result, 0, len(m.Findings))
	for _, f := range m.Findings {
		pkg := f.Aggregatable.Package
		pkgDisplay := pkg.Name
		if pkg.Version != "" {
			pkgDisplay = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
		}
		if pkgDisplay == "" {
			pkgDisplay = "unknown"
		}

		chain := strings.Join(f.Context.ProcessChain, " → ")
		if chain == "" {
			chain = f.Context.Comm
		}

		lifecycle := f.Context.Attribution.Lifecycle
		if lifecycle == "" {
			lifecycle = "unknown"
		}
		confidence := f.Context.Attribution.Confidence
		if confidence == "" {
			confidence = "unknown"
		}

		msg := fmt.Sprintf("%s\n\n"+
			"Package: %s\n"+
			"Lifecycle: %s\n"+
			"Sensitive file: %s\n"+
			"Process chain: %s\n"+
			"Destination: %s\n"+
			"Bytes sent: %s\n"+
			"Elapsed time: %d ms\n"+
			"Confidence: %s\n\n"+
			"Recommended action:\n%s",
			headline(f), pkgDisplay, lifecycle, fileDisplay(f), chain, destDisplay(f), bytesSent(f), f.Aggregatable.ElapsedMS, confidence, advice(f))
		if f.Context.Agent != "" {
			msg = strings.Replace(msg, "\nPackage:", "\nAI agent: "+f.Context.Agent+"\nPackage:", 1)
		}
		msg += "\n\n" + triage.Render(f)

		fp := f.Context.Fingerprint
		if fp == "" {
			fp = fmt.Sprintf("%s|%s|%s|%s", f.Rule, f.Aggregatable.FileTier, f.Aggregatable.DestHost, pkg.Name)
		}

		locs := []location{
			{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: "package.json"},
					Region:           &region{StartLine: 1},
				},
			},
		}

		results = append(results, result{
			RuleID:    f.Rule,
			Level:     level(f),
			Message:   text{Text: msg},
			Locations: locs,
			PartialFingerprints: map[string]string{
				"buildlens/v1": fp,
			},
		})
	}

	return logFile{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "BuildLens",
				InformationURI: "https://github.com/buildlens/buildlens",
				Version:        m.RulesetVersion,
				Rules: []rule{{
					ID:               "TAINTED_EGRESS",
					ShortDescription: text{Text: "Sensitive file read followed by unexpected network egress"},
					HelpURI:          "https://github.com/buildlens/buildlens/blob/main/docs/rules/TAINTED_EGRESS.md",
				}, {
					ID:               "PROCESS_MEMORY_READ",
					ShortDescription: text{Text: "Process read another process's memory or environment"},
				}, {
					ID:               "INSTALL_SCRIPT_EGRESS",
					ShortDescription: text{Text: "Dependency install script contacted a host other than the package registry"},
				}},
			}},
			Results: results,
		}},
	}
}

// GenerateStepSummary produces markdown formatted for GITHUB_STEP_SUMMARY.
func GenerateStepSummary(m runschema.Manifest) string {
	var sb strings.Builder

	if m.Status == "degraded" {
		sb.WriteString("### ⚠️ BuildLens Runtime: DEGRADED\n\n")
		sb.WriteString(fmt.Sprintf("**Reason:** `%s`\n\n", m.AgentHealth.DegradedReason))
		sb.WriteString("> BuildLens operated in fail-open mode. Builds were not interrupted, but complete runtime observation was unavailable.\n")
		return sb.String()
	}

	if len(m.Findings) == 0 {
		sb.WriteString("### ✅ BuildLens Runtime: CLEAN\n\n")
		sb.WriteString("No suspicious credential access or unauthorized exfiltration detected during build.\n\n")
		sb.WriteString(agentSection(m))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("### 🚨 BuildLens Alert: %d Security Finding(s)\n\n", len(m.Findings)))

	for i, f := range m.Findings {
		pkg := f.Aggregatable.Package
		pkgDisplay := pkg.Name
		if pkg.Version != "" {
			pkgDisplay = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
		}
		if pkgDisplay == "" {
			pkgDisplay = "unknown"
		}

		chain := strings.Join(f.Context.ProcessChain, " → ")
		if chain == "" {
			chain = f.Context.Comm
		}

		lifecycle := f.Context.Attribution.Lifecycle
		confidence := f.Context.Attribution.Confidence
		if confidence == "" {
			confidence = "unknown"
		}
		confidencePct := "90%"
		if confidence == "confirmed" {
			confidencePct = "99%"
		} else if confidence == "unknown" {
			confidencePct = "50%"
		}

		sb.WriteString(fmt.Sprintf("#### Finding %d: %s\n\n", i+1, f.Rule))
		sb.WriteString(fmt.Sprintf("- **Package:** `%s`\n", pkgDisplay))
		if lifecycle != "" {
			sb.WriteString(fmt.Sprintf("- **Lifecycle:** `%s`\n", lifecycle))
		}
		if f.Context.Path != "" {
			sb.WriteString(fmt.Sprintf("- **Sensitive File:** `%s` (%s)\n", f.Context.Path, f.Aggregatable.FileTier))
		}
		sb.WriteString(fmt.Sprintf("- **Process Chain:** `%s`\n", chain))
		sb.WriteString(fmt.Sprintf("- **Destination:** `%s`\n", destDisplay(f)))
		sb.WriteString(fmt.Sprintf("- **Bytes Sent:** `%s`\n", bytesSent(f)))
		sb.WriteString(fmt.Sprintf("- **Elapsed Time:** `%d ms`\n", f.Aggregatable.ElapsedMS))
		sb.WriteString(fmt.Sprintf("- **Confidence:** `%s (%s)`\n\n", confidence, confidencePct))
		if f.Context.Agent != "" {
			sb.WriteString(fmt.Sprintf("- **Via AI agent:** `%s`\n\n", f.Context.Agent))
		}
		sb.WriteString("**Recommended Action:**\n")
		if pkg.Ecosystem == "agent" {
			sb.WriteString(triage.PromptInjectionAdvice + "\n\n")
		} else {
			sb.WriteString("```bash\nnpm uninstall " + pkg.Name + " && npm install --package-lock-only\n```\n\n")
		}
		sb.WriteString("<details><summary>Suggested context (auto-generated)</summary>\n\n")
		sb.WriteString(triage.Render(f))
		sb.WriteString("\n</details>\n\n")
		sb.WriteString("---\n\n")
	}

	sb.WriteString(agentSection(m))
	return sb.String()
}

// agentSection lists what each AI coding agent did, even on a clean run: what
// it ran, which secrets it opened and where it connected.
func agentSection(m runschema.Manifest) string {
	var sb strings.Builder
	for _, a := range m.Agents {
		sb.WriteString(fmt.Sprintf("### 🤖 AI agent activity: `%s`\n\n", a.Agent))
		sb.WriteString(fmt.Sprintf("- **Secret files opened:** %s\n", codeList(a.SecretFiles)))
		sb.WriteString(fmt.Sprintf("- **Hosts contacted:** %s\n", codeList(a.Hosts)))
		sb.WriteString(fmt.Sprintf("- **Commands run:** %d\n\n", len(a.Commands)+a.CommandsOmitted))
		if len(a.Commands) > 0 {
			sb.WriteString("<details><summary>Commands (secret-looking strings masked)</summary>\n\n```text\n")
			for _, c := range a.Commands {
				// A command containing ``` would close the block early.
				sb.WriteString(strings.ReplaceAll(c, "```", "'''") + "\n")
			}
			if a.CommandsOmitted > 0 {
				sb.WriteString(fmt.Sprintf("… and %d more\n", a.CommandsOmitted))
			}
			sb.WriteString("```\n\n</details>\n\n")
		}
	}
	return sb.String()
}

func advice(f runschema.Finding) string {
	if f.Aggregatable.Package.Ecosystem == "agent" {
		return strings.ReplaceAll(triage.PromptInjectionAdvice, "`", "")
	}
	return "Remove the dependency and regenerate package-lock.json."
}

func codeList(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return "`" + strings.Join(items, "`, `") + "`"
}

func headline(f runschema.Finding) string {
	switch f.Rule {
	case "PROCESS_MEMORY_READ":
		return "Critical: dependency read another process's memory or environment"
	case "INSTALL_SCRIPT_EGRESS":
		return "High: dependency install script contacted an unexpected host"
	}
	return "Critical: dependency credential access"
}

func level(f runschema.Finding) string {
	if f.Severity == "critical" {
		return "error"
	}
	return "warning"
}

func fileDisplay(f runschema.Finding) string {
	if f.Context.Path == "" {
		return "none"
	}
	return f.Context.Path
}

func destDisplay(f runschema.Finding) string {
	if f.Aggregatable.DestHost == "" {
		return "none"
	}
	return f.Aggregatable.DestHost
}

func bytesSent(f runschema.Finding) string {
	if f.Aggregatable.BytesSent == nil {
		return "not measured"
	}
	return fmt.Sprint(*f.Aggregatable.BytesSent)
}

func WriteFile(path string, m runschema.Manifest) error {
	b, err := json.MarshalIndent(FromManifest(m), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

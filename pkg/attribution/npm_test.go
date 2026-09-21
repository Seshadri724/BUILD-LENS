package attribution_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/buildlens/buildlens/pkg/attribution"
)

func TestInferPackageFromCwd(t *testing.T) {
	tests := []struct {
		name          string
		cwd           string
		cmdline       string
		wantPkg       string
		wantLifecycle string
	}{
		{
			name:          "standard node_modules package",
			cwd:           "/home/runner/work/repo/node_modules/malicious-pkg",
			cmdline:       "node postinstall.js",
			wantPkg:       "malicious-pkg",
			wantLifecycle: "postinstall",
		},
		{
			name:          "scoped package",
			cwd:           "/home/runner/work/repo/node_modules/@evil/stealer",
			cmdline:       "sh -c node preinstall.js",
			wantPkg:       "@evil/stealer",
			wantLifecycle: "preinstall",
		},
		{
			name:          "node_modules in cmdline",
			cwd:           "/home/runner/work/repo",
			cmdline:       "node ./node_modules/evil-dep/index.js",
			wantPkg:       "evil-dep",
			wantLifecycle: "",
		},
		{
			name:          "outside node_modules",
			cwd:           "/home/runner/work/repo/src",
			cmdline:       "npm test",
			wantPkg:       "",
			wantLifecycle: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, lifecycle := attribution.InferPackageFromCwd(tt.cwd, tt.cmdline)
			if pkg != tt.wantPkg {
				t.Errorf("pkg = %q, want %q", pkg, tt.wantPkg)
			}
			if lifecycle != tt.wantLifecycle {
				t.Errorf("lifecycle = %q, want %q", lifecycle, tt.wantLifecycle)
			}
		})
	}
}

func TestResolveLockfile(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "package-lock.json")

	content := `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/suspicious-package": {
      "version": "1.2.3",
      "integrity": "sha512-test-hash=="
    }
  }
}`
	if err := os.WriteFile(lockPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	v, h, err := attribution.ResolveLockfile(lockPath, "suspicious-package")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "1.2.3" || h != "sha512-test-hash==" {
		t.Errorf("got version=%s, hash=%s", v, h)
	}

	attr := attribution.AttributeProcess(
		"/repo/node_modules/suspicious-package",
		"node postinstall.js",
		lockPath,
	)

	if attr.Package.Name != "suspicious-package" {
		t.Errorf("name = %q", attr.Package.Name)
	}
	if attr.Package.Version != "1.2.3" {
		t.Errorf("version = %q", attr.Package.Version)
	}
	if attr.Package.IntegrityHash != "sha512-test-hash==" {
		t.Errorf("integrity = %q", attr.Package.IntegrityHash)
	}
	if attr.Confidence != "confirmed" {
		t.Errorf("confidence = %q", attr.Confidence)
	}
	if attr.Lifecycle != "postinstall" {
		t.Errorf("lifecycle = %q", attr.Lifecycle)
	}
}

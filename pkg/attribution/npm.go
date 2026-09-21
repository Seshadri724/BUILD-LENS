package attribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/buildlens/buildlens/pkg/runschema"
)

// Lockfile represents npm package-lock.json versions 1, 2, and 3.
type Lockfile struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]LockfilePackage `json:"packages"`
	Dependencies    map[string]LockfilePackage `json:"dependencies"`
}

type LockfilePackage struct {
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
}

// InferPackageFromCwd extracts an npm package name and lifecycle from directory or cmdline.
func InferPackageFromCwd(cwd, cmdline string) (pkgName string, lifecycle string) {
	// Look for node_modules in cwd or cmdline
	target := cwd
	if !strings.Contains(target, "node_modules") && strings.Contains(cmdline, "node_modules") {
		target = cmdline
	}

	norm := filepath.ToSlash(target)
	// Accept absolute paths, relative paths, and command lines such as:
	// `node node_modules/pkg/postinstall.js`.
	idx := strings.LastIndex(norm, "node_modules/")
	if idx != -1 {
		sub := norm[idx+len("node_modules/"):]
		parts := strings.Split(sub, "/")
		if len(parts) > 0 {
			if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
				pkgName = parts[0] + "/" + parts[1]
			} else {
				pkgName = parts[0]
			}
		}
	}

	// Detect lifecycle event
	lowerCmd := strings.ToLower(cmdline)
	switch {
	case strings.Contains(lowerCmd, "postinstall"):
		lifecycle = "postinstall"
	case strings.Contains(lowerCmd, "preinstall"):
		lifecycle = "preinstall"
	case strings.Contains(lowerCmd, "install"):
		lifecycle = "install"
	case strings.Contains(lowerCmd, "build"):
		lifecycle = "build"
	case strings.Contains(lowerCmd, "test"):
		lifecycle = "test"
	}

	return pkgName, lifecycle
}

// ResolveLockfile finds and reads package-lock.json to extract package metadata.
func ResolveLockfile(lockfilePath, pkgName string) (version, integrity string, err error) {
	if lockfilePath == "" || pkgName == "" {
		return "", "", nil
	}

	b, err := os.ReadFile(lockfilePath)
	if err != nil {
		return "", "", err
	}

	var lf Lockfile
	if err := json.Unmarshal(b, &lf); err != nil {
		return "", "", err
	}

	// Check v2/v3 packages map first
	key := "node_modules/" + pkgName
	if pkg, ok := lf.Packages[key]; ok {
		return pkg.Version, pkg.Integrity, nil
	}

	// Check dependencies map (v1/v2 fallback)
	if pkg, ok := lf.Dependencies[pkgName]; ok {
		return pkg.Version, pkg.Integrity, nil
	}

	return "", "", nil
}

// AttributeProcess attempts to accurately attribute an npm dependency with confidence rating.
func AttributeProcess(cwd, cmdline, lockfilePath string) runschema.Attribution {
	pkgName, lifecycle := InferPackageFromCwd(cwd, cmdline)
	if pkgName == "" {
		return runschema.UnknownAttribution()
	}

	version, integrity, _ := ResolveLockfile(lockfilePath, pkgName)

	confidence := "probable"
	if version != "" && integrity != "" {
		confidence = "confirmed"
	}

	return runschema.Attribution{
		Package: runschema.PackageID{
			Ecosystem:     "npm",
			Name:          pkgName,
			Version:       version,
			IntegrityHash: integrity,
		},
		Confidence: confidence,
		Lifecycle:  lifecycle,
	}
}

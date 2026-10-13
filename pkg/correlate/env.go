package correlate

import (
	"slices"
	"strings"
)

// maxEnvNames bounds how many matched names one event carries.
const maxEnvNames = 32

// secretEnvSegments are underscore-separated name segments marking an
// environment variable as secret-bearing. Whole-segment matching keeps
// GITHUB_ACTION quiet while catching AWS_SECRET_ACCESS_KEY: "SECRETARY"
// never appears as a real variable, and splitting on "_" means MONKEY never
// matches KEY.
var secretEnvSegments = []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE", "KEY"}

// SensitiveEnvNames filters environment variable names down to the
// secret-bearing ones, canonicalized to upper case and sorted for
// determinism. Values are never examined — callers must only pass names.
func SensitiveEnvNames(names []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		u := strings.ToUpper(strings.TrimSpace(n))
		if u == "" || seen[u] {
			continue
		}
		if isSecretEnvName(u) {
			seen[u] = true
			out = append(out, u)
			if len(out) >= maxEnvNames {
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

func isSecretEnvName(upper string) bool {
	for _, seg := range strings.Split(upper, "_") {
		if slices.Contains(secretEnvSegments, seg) {
			return true
		}
	}
	return false
}

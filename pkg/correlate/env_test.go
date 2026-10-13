package correlate_test

import (
	"slices"
	"testing"

	"github.com/buildlens/buildlens/pkg/correlate"
)

func TestSensitiveEnvNames(t *testing.T) {
	got := correlate.SensitiveEnvNames([]string{
		"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NODE_AUTH_TOKEN",
		"DB_PASSWORD", "MY_API_KEY", "github_token", "PATH", "HOME",
		"CI", "GITHUB_ACTION", "GITHUB_ACTOR", "GITHUB_WORKSPACE",
		"", "LANG",
	})
	want := []string{
		"AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "GITHUB_TOKEN",
		"MY_API_KEY", "NODE_AUTH_TOKEN",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	// Whole-segment matching: no substring false friends.
	for _, benign := range []string{"SECRETARY", "MONKEY", "KEYBOARD", "TOKENIZER"} {
		if len(correlate.SensitiveEnvNames([]string{benign})) != 0 {
			t.Errorf("%q must not match", benign)
		}
	}

	// Sorted, deduped, bounded.
	many := []string{"B_TOKEN", "A_TOKEN", "B_TOKEN"}
	if got := correlate.SensitiveEnvNames(many); !slices.Equal(got, []string{"A_TOKEN", "B_TOKEN"}) {
		t.Errorf("dedup/sort: %q", got)
	}
}

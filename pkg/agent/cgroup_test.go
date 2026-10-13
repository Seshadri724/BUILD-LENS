package agent_test

import (
	"testing"

	"github.com/buildlens/buildlens/pkg/agent"
)

func TestParseCgroupV2Path(t *testing.T) {
	cases := []struct {
		name string
		data string
		path string
		ok   bool
	}{
		{
			"unified job scope",
			"0::/user.slice/user-1000.slice/session-3.scope\n",
			"/sys/fs/cgroup/user.slice/user-1000.slice/session-3.scope", true,
		},
		{
			"v1-only hierarchy is not hookable",
			"2:memory:/kubepods/besteffort\n1:name=systemd:/kubepods/besteffort\n",
			"", false,
		},
		{
			"machine root must never be hooked",
			"0::/\n",
			"", false,
		},
		{
			"empty hierarchy",
			"",
			"", false,
		},
		{
			"docker container scope",
			"0::/docker/4c1f9a2b3c4d\n",
			"/sys/fs/cgroup/docker/4c1f9a2b3c4d", true,
		},
	}
	for _, tc := range cases {
		path, ok := agent.ParseCgroupV2Path(tc.data)
		if path != tc.path || ok != tc.ok {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", tc.name, path, ok, tc.path, tc.ok)
		}
	}
}

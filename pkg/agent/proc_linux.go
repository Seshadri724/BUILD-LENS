//go:build linux

package agent

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReadProcessCmdline reads /proc/<pid>/cmdline and reconstructs the command-line string.
func ReadProcessCmdline(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	parts := bytes.Split(b, []byte{0})
	var nonEmp []string
	for _, p := range parts {
		if len(p) > 0 {
			nonEmp = append(nonEmp, string(p))
		}
	}
	return strings.Join(nonEmp, " ")
}

// ReadProcessCwd reads the current working directory link from /proc/<pid>/cwd.
func ReadProcessCwd(pid uint32) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return cwd
}

// ReadProcessCPUTimeMs reads user and system CPU ticks for a pid from /proc/<pid>/stat.
func ReadProcessCPUTimeMs(pid int) (int64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(b))
	if len(fields) < 15 {
		return 0, fmt.Errorf("malformed stat file for pid %d", pid)
	}

	// utime is field 14 (index 13), stime is field 15 (index 14)
	utime, err1 := strconv.ParseInt(fields[13], 10, 64)
	stime, err2 := strconv.ParseInt(fields[14], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("failed to parse cpu times")
	}

	// Most x86 Linux systems use sysconf(_SC_CLK_TCK) = 100 ticks per second (10ms per tick)
	totalTicks := utime + stime
	return totalTicks * 10, nil
}

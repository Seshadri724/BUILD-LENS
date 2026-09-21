//go:build !linux

package agent

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"
)

// Record provides a fail-open stub implementation for non-Linux operating systems.
func Record(opts RecordOptions) error {
	log.Printf("BuildLens agent: eBPF monitoring unsupported on %s — operating in fail-open mode", runtime.GOOS)

	if dir := filepath.Dir(opts.OutPath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}

	readyPath := opts.OutPath + ".ready"
	donePath := opts.OutPath + ".done"

	// Write readiness marker so dependent build steps proceed without blocking
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o644); err != nil {
		return fmt.Errorf("write readiness marker: %w", err)
	}
	defer os.Remove(readyPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	if opts.Duration > 0 {
		select {
		case <-sigCh:
		case <-time.After(opts.Duration):
		}
	} else {
		<-sigCh
	}

	_ = os.WriteFile(donePath, []byte("done\n"), 0o644)
	return nil
}

package scheduler_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

type dummyRunner struct{}

func (d *dummyRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return []byte(`<nmaprun scanner="nmap"></nmaprun>`), nil
}

func TestScheduler_Lifecycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scheduler_test_*")
	if err != nil {
		t.Fatalf("temp dir error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("storage init error: %v", err)
	}
	defer store.Close()

	cfg := &config.Config{
		NetworkCIDR:           "172.28.0.0/24",
		DiscoveryInterval:     100 * time.Millisecond,
		VulnerabilityInterval: 100 * time.Millisecond,
		ScanTimeout:           500 * time.Millisecond,
		NmapPath:              "nmap",
	}

	scn := scanner.NewWithRunner(cfg, &dummyRunner{})
	sch := scheduler.New(cfg, store, scn)

	ctx, cancel := context.WithCancel(context.Background())

	sch.Start(ctx)

	// Test EnqueueImmediateScan
	sch.EnqueueImmediateScan("172.28.0.99")

	time.Sleep(150 * time.Millisecond)

	discTime, vulnTime, _, _ := sch.GetNextRuns()
	if discTime == nil {
		t.Errorf("expected discovery next run time to be populated")
	}
	if vulnTime == nil {
		t.Errorf("expected vuln next run time to be populated")
	}

	// Graceful Stop
	cancel()
	sch.Stop()
}

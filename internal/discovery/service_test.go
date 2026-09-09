package discovery_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/discovery"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/storage"
)

const sampleDiscoveryOutput = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sn 172.28.0.0/24">
  <host>
    <status state="up"/>
    <address addr="172.28.0.55" addrtype="ipv4"/>
    <address addr="02:42:AC:1C:00:37" addrtype="mac"/>
    <hostnames><hostname name="test-host"/></hostnames>
  </host>
</nmaprun>`

type mockCmdRunner struct {
	output []byte
}

func (m *mockCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return m.output, nil
}

func TestDiscoveryService_TriggersImmediateOnNewDevice(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "discovery_test_*")
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
		NetworkCIDR: "172.28.0.0/24",
		NmapPath:    "nmap",
	}

	mock := &mockCmdRunner{output: []byte(sampleDiscoveryOutput)}
	scn := scanner.NewWithRunner(cfg, mock)

	newDeviceTriggered := make(chan string, 1)
	onNew := func(ip string) {
		newDeviceTriggered <- ip
	}

	svc := discovery.New(cfg, store, scn, onNew)

	// First Run: device 172.28.0.55 is brand new -> callback MUST be triggered
	devs, err := svc.Run(context.Background())
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}

	select {
	case ip := <-newDeviceTriggered:
		if ip != "172.28.0.55" {
			t.Errorf("expected immediate trigger for 172.28.0.55, got %s", ip)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout: expected onNewDevice callback to be triggered immediately")
	}

	// Second Run: device is already known -> callback MUST NOT be triggered
	_, err = svc.Run(context.Background())
	if err != nil {
		t.Fatalf("second run error: %v", err)
	}

	select {
	case ip := <-newDeviceTriggered:
		t.Fatalf("unexpected callback triggered for already-existing device: %s", ip)
	case <-time.After(100 * time.Millisecond):
		// Expected: no trigger
	}
}

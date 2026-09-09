package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
)

// CommandRunner defines an interface for running external shell commands (enabling mocking).
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// DefaultCommandRunner executes commands via os/exec.
type DefaultCommandRunner struct{}

// Run executes the command with context and returns stdout.
func (r *DefaultCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("command '%s %s' failed: %w (stderr: %s)",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Scanner orchestrates Nmap discovery and vulnerability audits.
type Scanner struct {
	cfg    *config.Config
	runner CommandRunner
}

// New creates a new Scanner instance with the default command runner.
func New(cfg *config.Config) *Scanner {
	return &Scanner{
		cfg:    cfg,
		runner: &DefaultCommandRunner{},
	}
}

// NewWithRunner creates a Scanner with a custom CommandRunner (for unit tests).
func NewWithRunner(cfg *config.Config, runner CommandRunner) *Scanner {
	return &Scanner{
		cfg:    cfg,
		runner: runner,
	}
}

// RunDiscoveryScan executes an Nmap host discovery scan against target CIDR.
func (s *Scanner) RunDiscoveryScan(ctx context.Context, target string) ([]model.Device, error) {
	args := []string{"-sn", "-n", "-oX", "-", target}

	output, err := s.runner.Run(ctx, s.cfg.NmapPath, args...)
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("discovery scan failed: %w", err)
	}

	run, parseErr := ParseNmapXML(output)
	if parseErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to parse discovery xml: %w", parseErr)
	}

	devices := ExtractDevices(run)
	return devices, nil
}

// RunVulnerabilityScan executes service detection and vulnerability scripts against target IPs.
func (s *Scanner) RunVulnerabilityScan(ctx context.Context, targets []string) ([]model.ScanHostResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	vulnScript := s.cfg.VulnScript
	if vulnScript == "" {
		vulnScript = "vulners"
	}

	args := []string{
		"-sV",
		"--script", vulnScript,
		"-n",
		"-oX", "-",
	}

	if s.cfg.Unprivileged {
		args = append(args, "-sT", "-Pn")
	}

	args = append(args, targets...)

	output, err := s.runner.Run(ctx, s.cfg.NmapPath, args...)
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	run, parseErr := ParseNmapXML(output)
	if parseErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to parse vulnerability xml: %w", parseErr)
	}

	results := ExtractHostResults(run)
	return results, nil
}

package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner invokes the Trivy binary and turns its JSON report into findings.
type Runner struct {
	// Binary is the trivy executable to run. Defaults to "trivy" on PATH.
	Binary string
	// Scanners passed to --scanners.
	Scanners []string
	// Severities passed to --severity. Empty means all severities.
	Severities []string
	// IgnoreFile passed to --ignorefile, if set.
	IgnoreFile string
	// ConfigFile passed to --config, if set.
	ConfigFile string
	// ExtraArgs are appended verbatim, for flags this server does not model.
	ExtraArgs []string
}

// ErrNotInstalled is returned when the Trivy binary cannot be found.
type ErrNotInstalled struct {
	Binary string
}

func (e *ErrNotInstalled) Error() string {
	return fmt.Sprintf("trivy binary %q not found on PATH", e.Binary)
}

func (r *Runner) binary() string {
	if r.Binary != "" {
		return r.Binary
	}
	return "trivy"
}

// Version returns the version string reported by the binary. It doubles as an
// availability check at startup.
func (r *Runner) Version(ctx context.Context) (string, error) {
	if _, err := exec.LookPath(r.binary()); err != nil {
		return "", &ErrNotInstalled{Binary: r.binary()}
	}

	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, r.binary(), "--version", "--format", "json")
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("trivy --version: %w", err)
	}

	var v struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil || v.Version == "" {
		return strings.TrimSpace(stdout.String()), nil
	}
	return v.Version, nil
}

// Scan runs a filesystem scan rooted at dir and returns findings keyed by
// absolute file path.
func (r *Runner) Scan(ctx context.Context, dir string) (Findings, error) {
	if _, err := exec.LookPath(r.binary()); err != nil {
		return nil, &ErrNotInstalled{Binary: r.binary()}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.binary(), r.args()...)
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Trivy exits non-zero for genuine failures, but also when --exit-code
		// is configured and findings exist. Trust the output: if we can parse a
		// report, the scan worked.
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("trivy scan failed: %w: %s", err, truncate(stderr.String(), 500))
		}
	}

	var report Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("parsing trivy report: %w", err)
	}

	return report.Flatten(targetResolver(dir)), nil
}

func (r *Runner) args() []string {
	args := []string{"fs", "--format", "json", "--quiet"}

	if len(r.Scanners) > 0 {
		args = append(args, "--scanners", strings.Join(r.Scanners, ","))
	}
	if len(r.Severities) > 0 {
		args = append(args, "--severity", strings.Join(r.Severities, ","))
	}
	if r.IgnoreFile != "" {
		args = append(args, "--ignorefile", r.IgnoreFile)
	}
	if r.ConfigFile != "" {
		args = append(args, "--config", r.ConfigFile)
	}

	args = append(args, r.ExtraArgs...)
	return append(args, ".")
}

// targetResolver maps a Trivy target to an absolute path, rejecting targets
// that are not real files under the scan root. Trivy emits synthetic targets
// (such as "." for an aggregated Terraform result) and targets for downloaded
// modules that may live outside the workspace; neither can carry diagnostics.
func targetResolver(root string) func(string) (string, bool) {
	return func(target string) (string, bool) {
		if target == "" || target == "." {
			return "", false
		}

		path := target
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, target)
		}

		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return "", false
		}
		return path, true
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

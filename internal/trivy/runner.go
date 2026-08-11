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

// Available reports whether the Trivy binary can be found, so the server can
// tell the user at startup rather than after the first scan quietly fails.
func (r *Runner) Available() error {
	if _, err := exec.LookPath(r.binary()); err != nil {
		return &ErrNotInstalled{Binary: r.binary()}
	}
	return nil
}

// Scan runs a filesystem scan rooted at dir and returns findings keyed by
// absolute file path.
func (r *Runner) Scan(ctx context.Context, dir string) (Findings, error) {
	if err := r.Available(); err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.binary(), r.args()...)
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Trivy exits non-zero for genuine failures, but also when --exit-code is
	// configured and findings exist, so the exit status alone cannot decide
	// whether the scan worked. The report is the authority.
	runErr := cmd.Run()

	var report Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		// Unparseable output plus a non-zero exit means the scan really did
		// fail, and the reason is far more useful than the parse error. Trivy
		// prints usage errors to stdout, so the explanation may be in either
		// stream.
		if runErr != nil {
			return nil, fmt.Errorf("trivy scan failed: %w: %s", runErr, truncate(explain(stderr, stdout), 500))
		}
		return nil, fmt.Errorf("parsing trivy report: %w", err)
	}

	return report.Flatten(targetResolver(dir)), nil
}

// explain picks whichever stream carries the diagnosis.
func explain(stderr, stdout bytes.Buffer) string {
	if s := strings.TrimSpace(stderr.String()); s != "" {
		return s
	}
	return stdout.String()
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

package trivy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func requireTrivy(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not installed; skipping integration test")
	}
}

// bucketWorkspace writes a workspace containing a Terraform bucket that fails
// several checks, and returns its root.
func bucketWorkspace(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	body := "resource \"aws_s3_bucket\" \"example\" {\n  bucket = \"example-bucket\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func misconfigRunner() *Runner {
	// The misconfig scanner is fully offline, so this test never needs the
	// vulnerability database.
	return &Runner{Scanners: []string{"misconfig"}}
}

func countFindings(t *testing.T, dir string) int {
	t.Helper()

	findings, err := misconfigRunner().Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	total := 0
	for _, fs := range findings {
		total += len(fs)
	}
	return total
}

func TestScanFindsTerraformMisconfigurations(t *testing.T) {
	requireTrivy(t)

	dir := bucketWorkspace(t)
	findings, err := misconfigRunner().Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	main := findings[filepath.Join(dir, "main.tf")]
	if len(main) == 0 {
		t.Fatal("expected findings for main.tf, keyed by absolute path")
	}
	for _, f := range main {
		if f.Kind != KindMisconfig {
			t.Errorf("finding %s has kind %q", f.ID, f.Kind)
		}
		if !f.HasLocation() {
			t.Errorf("terraform finding %s has no line", f.ID)
		}
		if f.ID == "" || f.Severity == "" {
			t.Errorf("finding is missing an id or severity: %+v", f)
		}
	}
}

// The code actions build ignore rules from Finding.ID. If Trivy ever changes
// the identifier it accepts in an ignore rule, both quick fixes become silent
// no-ops, so the format is asserted against the real binary.
func TestFindingIDIsAcceptedByTrivyIgnores(t *testing.T) {
	requireTrivy(t)

	dir := bucketWorkspace(t)
	baseline := countFindings(t, dir)
	if baseline == 0 {
		t.Fatal("expected a baseline finding to ignore")
	}

	findings, err := misconfigRunner().Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	id := findings[filepath.Join(dir, "main.tf")][0].ID

	t.Run("inline comment", func(t *testing.T) {
		body := "#trivy:ignore:" + id + "\nresource \"aws_s3_bucket\" \"example\" {\n  bucket = \"example-bucket\"\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			original := "resource \"aws_s3_bucket\" \"example\" {\n  bucket = \"example-bucket\"\n}\n"
			_ = os.WriteFile(filepath.Join(dir, "main.tf"), []byte(original), 0o644)
		})

		if got := countFindings(t, dir); got >= baseline {
			t.Errorf("inline ignore of %s left %d findings, baseline was %d", id, got, baseline)
		}
	})

	t.Run("ignore file", func(t *testing.T) {
		path := filepath.Join(dir, ".trivyignore")
		if err := os.WriteFile(path, []byte(id+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(path) })

		if got := countFindings(t, dir); got >= baseline {
			t.Errorf("ignore file entry %s left %d findings, baseline was %d", id, got, baseline)
		}
	})
}

func TestScanReportsMissingBinary(t *testing.T) {
	r := &Runner{Binary: "trivy-does-not-exist-xyz"}

	_, err := r.Scan(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}

	var notInstalled *ErrNotInstalled
	if !errors.As(err, &notInstalled) {
		t.Fatalf("got %T, want *ErrNotInstalled so the server can prompt the user", err)
	}
}

func TestArgsIncludeConfiguredFlags(t *testing.T) {
	r := &Runner{
		Scanners:   []string{"misconfig", "secret"},
		Severities: []string{"HIGH", "CRITICAL"},
		IgnoreFile: ".myignore",
		ConfigFile: "trivy.yaml",
		ExtraArgs:  []string{"--offline-scan"},
	}

	want := []string{
		"fs", "--format", "json", "--quiet",
		"--scanners", "misconfig,secret",
		"--severity", "HIGH,CRITICAL",
		"--ignorefile", ".myignore",
		"--config", "trivy.yaml",
		"--offline-scan",
		".",
	}
	if got := r.args(); !reflect.DeepEqual(got, want) {
		t.Errorf("args = %v\nwant %v", got, want)
	}
}

func TestTargetResolverRejectsSyntheticTargets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	resolve := targetResolver(dir)

	if path, ok := resolve("main.tf"); !ok || path != filepath.Join(dir, "main.tf") {
		t.Errorf("resolve(main.tf) = (%q, %v)", path, ok)
	}
	for _, target := range []string{".", "", "missing.tf", "terraform-aws-modules/rds/aws/main.tf"} {
		if _, ok := resolve(target); ok {
			t.Errorf("resolve(%q) should have been rejected", target)
		}
	}
}

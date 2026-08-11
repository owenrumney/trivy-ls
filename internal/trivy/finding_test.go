package trivy

import (
	"encoding/json"
	"os"
	"path"
	"testing"
)

// loadReport reads the recorded report produced by scanning
// internal/handler/testdata/workspace.
func loadReport(t *testing.T) *Report {
	t.Helper()

	data, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatalf("reading testdata: %v", err)
	}

	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("parsing testdata: %v", err)
	}
	return &r
}

// acceptAll resolves targets without touching the filesystem, so the mapping
// logic can be tested independently of the workspace layout.
func acceptAll(target string) (string, bool) {
	if target == "" || target == "." {
		return "", false
	}
	return path.Join("/ws", target), true
}

func TestFlattenGroupsFindingsByFile(t *testing.T) {
	findings := loadReport(t).Flatten(acceptAll)

	if _, ok := findings["/ws/."]; ok {
		t.Error("synthetic target \".\" should be dropped")
	}

	want := map[string]int{
		"/ws/main.tf":     11,
		"/ws/Dockerfile":  2,
		"/ws/secrets.txt": 1,
	}
	for file, count := range want {
		if got := len(findings[file]); got != count {
			t.Errorf("%s: got %d findings, want %d", file, got, count)
		}
	}
}

func TestFlattenPreservesLineNumbers(t *testing.T) {
	findings := loadReport(t).Flatten(acceptAll)

	for _, f := range findings["/ws/main.tf"] {
		if !f.HasLocation() {
			t.Errorf("terraform finding %s has no location", f.ID)
		}
	}

	// Dockerfile checks assert the absence of an instruction, so Trivy has no
	// line to report. These must survive flattening as file-level findings.
	for _, f := range findings["/ws/Dockerfile"] {
		if f.HasLocation() {
			t.Errorf("dockerfile finding %s unexpectedly has a location", f.ID)
		}
	}
}

func TestFlattenSecret(t *testing.T) {
	findings := loadReport(t).Flatten(acceptAll)

	secrets := findings["/ws/secrets.txt"]
	if len(secrets) != 1 {
		t.Fatalf("got %d secrets, want 1", len(secrets))
	}

	s := secrets[0]
	if s.Kind != KindSecret {
		t.Errorf("kind = %q, want %q", s.Kind, KindSecret)
	}
	if s.ID != "aws-access-key-id" {
		t.Errorf("id = %q", s.ID)
	}
	if s.Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", s.Severity)
	}
	if s.StartLine != 2 {
		t.Errorf("start line = %d, want 2", s.StartLine)
	}
}

func TestFlattenSkipsPassedMisconfigurations(t *testing.T) {
	r := &Report{Results: []Result{{
		Target: "main.tf",
		Misconfigurations: []Misconfiguration{
			{ID: "AWS-0001", Status: "PASS"},
			{ID: "AWS-0002", Status: "FAIL"},
		},
	}}}

	findings := r.Flatten(acceptAll)
	if len(findings["/ws/main.tf"]) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings["/ws/main.tf"]))
	}
	if id := findings["/ws/main.tf"][0].ID; id != "AWS-0002" {
		t.Errorf("kept %q, want the FAIL result", id)
	}
}

func TestFlattenPlacesVulnerabilitiesOnPackageLines(t *testing.T) {
	r := &Report{Results: []Result{{
		Target: "Cargo.lock",
		Class:  "lang-pkgs",
		Packages: []Package{
			{ID: "openssl@0.8.3", Name: "openssl", Version: "0.8.3",
				Locations: []Location{{StartLine: 179, EndLine: 188}}},
		},
		Vulnerabilities: []Vulnerability{
			{VulnerabilityID: "CVE-2018-20997", PkgID: "openssl@0.8.3", PkgName: "openssl",
				InstalledVersion: "0.8.3", FixedVersion: "0.10.0", Severity: "high"},
			{VulnerabilityID: "CVE-9999-0001", PkgID: "unknown@1.0.0", PkgName: "unknown"},
		},
	}}}

	findings := r.Flatten(acceptAll)["/ws/Cargo.lock"]
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	located := findings[0]
	if located.StartLine != 179 {
		t.Errorf("start line = %d, want 179 from the package location", located.StartLine)
	}
	if located.Severity != "HIGH" {
		t.Errorf("severity = %q, want normalised HIGH", located.Severity)
	}
	if located.FixedVersion != "0.10.0" {
		t.Errorf("fixed version = %q", located.FixedVersion)
	}

	// A vulnerability whose package has no recorded location must still be
	// reported, just without a line.
	if findings[1].HasLocation() {
		t.Error("vulnerability with unmatched package should have no location")
	}
}

func TestCheckIDPrefersAVDID(t *testing.T) {
	if got := (Misconfiguration{ID: "AWS-0086"}).CheckID(); got != "AWS-0086" {
		t.Errorf("got %q", got)
	}
	if got := (Misconfiguration{ID: "AWS-0086", AVDID: "AVD-AWS-0086"}).CheckID(); got != "AVD-AWS-0086" {
		t.Errorf("got %q, want the AVD id", got)
	}
}

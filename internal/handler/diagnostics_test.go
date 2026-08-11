package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-lsp/lsp"
	"github.com/owenrumney/trivy-ls/internal/trivy"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "main.tf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSeverityFor(t *testing.T) {
	cases := map[string]lsp.DiagnosticSeverity{
		"CRITICAL": lsp.SeverityError,
		"HIGH":     lsp.SeverityError,
		"MEDIUM":   lsp.SeverityWarning,
		"LOW":      lsp.SeverityInformation,
		"UNKNOWN":  lsp.SeverityHint,
		"":         lsp.SeverityHint,
	}

	for severity, want := range cases {
		if got := severityFor(severity); got != want {
			t.Errorf("severityFor(%q) = %d, want %d", severity, got, want)
		}
	}
}

func TestRangeForSingleLineByDefault(t *testing.T) {
	path := writeFile(t, "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"y\"\n}\n")
	idx := newLineIndex()

	f := trivy.Finding{StartLine: 1, EndLine: 3}
	got := rangeFor(idx, path, f, false)

	if got.Start.Line != 0 || got.End.Line != 0 {
		t.Errorf("got lines %d-%d, want the span collapsed to line 0", got.Start.Line, got.End.Line)
	}
	if got.End.Character != len("resource \"aws_s3_bucket\" \"x\" {") {
		t.Errorf("end character = %d, want the line length", got.End.Character)
	}
}

func TestRangeForFullRange(t *testing.T) {
	path := writeFile(t, "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"y\"\n}\n")
	idx := newLineIndex()

	got := rangeFor(idx, path, trivy.Finding{StartLine: 1, EndLine: 3}, true)

	if got.Start.Line != 0 || got.End.Line != 2 {
		t.Errorf("got lines %d-%d, want 0-2", got.Start.Line, got.End.Line)
	}
}

func TestRangeForFindingWithoutLocation(t *testing.T) {
	path := writeFile(t, "FROM alpine:3.19\nCMD [\"sh\"]\n")
	idx := newLineIndex()

	got := rangeFor(idx, path, trivy.Finding{}, false)

	if got.Start.Line != 0 || got.End.Line != 0 {
		t.Errorf("got lines %d-%d, want the finding pinned to line 0", got.Start.Line, got.End.Line)
	}
	if got.End.Character != len("FROM alpine:3.19") {
		t.Errorf("end character = %d, want the first line's length", got.End.Character)
	}
}

func TestToDiagnostics(t *testing.T) {
	path := writeFile(t, "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"y\"\n}\n")
	idx := newLineIndex()

	findings := []trivy.Finding{{
		ID:        "AWS-0086",
		Kind:      trivy.KindMisconfig,
		Title:     "S3 Access block should block public ACL",
		Message:   "No public access block so not blocking public acls",
		Severity:  "HIGH",
		URL:       "https://avd.aquasec.com/misconfig/aws-0086",
		Resource:  "aws_s3_bucket.x",
		StartLine: 1,
		EndLine:   3,
	}}

	diags := toDiagnostics(idx, path, findings, false)
	if len(diags) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(diags))
	}

	d := diags[0]
	if d.Source != "trivy" {
		t.Errorf("source = %q", d.Source)
	}
	if *d.Severity != lsp.SeverityError {
		t.Errorf("severity = %d, want error", *d.Severity)
	}

	var code string
	if err := json.Unmarshal(d.Code, &code); err != nil || code != "AWS-0086" {
		t.Errorf("code = %s (err %v), want AWS-0086", d.Code, err)
	}
	if d.CodeDescription == nil || d.CodeDescription.Href != "https://avd.aquasec.com/misconfig/aws-0086" {
		t.Errorf("code description = %+v", d.CodeDescription)
	}
	if d.Message != "No public access block so not blocking public acls (aws_s3_bucket.x)" {
		t.Errorf("message = %q", d.Message)
	}

	var data diagnosticData
	if err := json.Unmarshal(d.Data, &data); err != nil || data.ID != "AWS-0086" {
		t.Errorf("data = %s (err %v)", d.Data, err)
	}
}

func TestToDiagnosticsSortsByLine(t *testing.T) {
	path := writeFile(t, "a\nb\nc\nd\n")
	idx := newLineIndex()

	findings := []trivy.Finding{
		{ID: "C", Severity: "LOW", StartLine: 3},
		{ID: "A", Severity: "LOW", StartLine: 1},
		{ID: "B", Severity: "LOW", StartLine: 2},
	}

	diags := toDiagnostics(idx, path, findings, false)
	for i, want := range []int{0, 1, 2} {
		if diags[i].Range.Start.Line != want {
			t.Errorf("diagnostic %d on line %d, want %d", i, diags[i].Range.Start.Line, want)
		}
	}
}

func TestMessageFallsBackToTitleThenID(t *testing.T) {
	if got := message(trivy.Finding{ID: "X", Title: "title"}); got != "title" {
		t.Errorf("got %q, want the title", got)
	}
	if got := message(trivy.Finding{ID: "X"}); got != "X" {
		t.Errorf("got %q, want the id", got)
	}
}

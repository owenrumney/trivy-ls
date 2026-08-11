package handler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-lsp/lsp"
	"github.com/owenrumney/trivy-ls/internal/trivy"
)

func TestCommentPrefix(t *testing.T) {
	cases := map[string]struct {
		prefix string
		ok     bool
	}{
		"main.tf":            {"#", true},
		"deploy.yaml":        {"#", true},
		"Dockerfile":         {"#", true},
		"Dockerfile.debug":   {"#", true},
		"Containerfile":      {"#", true},
		"Makefile":           {"#", true},
		"template.json":      {"", false},
		"cloudformation.yml": {"#", true},
	}

	for name, want := range cases {
		prefix, ok := commentPrefix(name)
		if prefix != want.prefix || ok != want.ok {
			t.Errorf("commentPrefix(%q) = (%q, %v), want (%q, %v)", name, prefix, ok, want.prefix, want.ok)
		}
	}
}

func TestIndentOf(t *testing.T) {
	cases := map[string]string{
		"resource {":      "",
		"  bucket = \"\"": "  ",
		"\t\tkey = 1":     "\t\t",
		"":                "",
	}

	for line, want := range cases {
		if got := indentOf(line); got != want {
			t.Errorf("indentOf(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestOverlaps(t *testing.T) {
	f := trivy.Finding{StartLine: 5, EndLine: 10}

	inside := lsp.Range{Start: lsp.Position{Line: 6}, End: lsp.Position{Line: 6}}
	if !overlaps(f, inside) {
		t.Error("a cursor inside the span should overlap")
	}

	before := lsp.Range{Start: lsp.Position{Line: 1}, End: lsp.Position{Line: 2}}
	if overlaps(f, before) {
		t.Error("a range before the span should not overlap")
	}

	// A finding with no location sits on line 0.
	if !overlaps(trivy.Finding{}, lsp.Range{}) {
		t.Error("an unlocated finding should overlap line 0")
	}
}

func TestCoversLine(t *testing.T) {
	f := trivy.Finding{StartLine: 5, EndLine: 10}

	if !coversLine(f, 4) {
		t.Error("line 4 (1-based 5) should be covered")
	}
	if !coversLine(f, 9) {
		t.Error("line 9 (1-based 10) should be covered")
	}
	if coversLine(f, 10) {
		t.Error("line past the span should not be covered")
	}
	if !coversLine(trivy.Finding{}, 0) {
		t.Error("an unlocated finding should cover line 0")
	}
}

func TestIgnoreInlineActionInsertsCommentAboveLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(path, []byte("resource \"x\" \"y\" {\n  foo = 1\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := New()
	uri := pathToURI(path)

	action, ok := h.ignoreInlineAction(uri, trivy.Finding{ID: "AWS-0086", StartLine: 2, EndLine: 2})
	if !ok {
		t.Fatal("expected an inline ignore action")
	}

	edits := action.Edit.Changes[uri]
	if len(edits) != 1 {
		t.Fatalf("got %d edits, want 1", len(edits))
	}
	if edits[0].NewText != "  #trivy:ignore:AWS-0086\n" {
		t.Errorf("new text = %q, want the comment to match the line indent", edits[0].NewText)
	}
	if edits[0].Range.Start.Line != 1 {
		t.Errorf("insert line = %d, want 1", edits[0].Range.Start.Line)
	}
}

func TestIgnoreInlineActionSkippedWithoutLocation(t *testing.T) {
	h := New()
	if _, ok := h.ignoreInlineAction(pathToURI("/tmp/Dockerfile"), trivy.Finding{ID: "DS-0026"}); ok {
		t.Error("a finding with no line cannot take an inline ignore comment")
	}
}

func TestAddToIgnoreFile(t *testing.T) {
	dir := t.TempDir()

	h := New()
	h.root = dir

	if err := h.addToIgnoreFile("AWS-0086"); err != nil {
		t.Fatal(err)
	}
	// Adding the same check twice must not duplicate the entry.
	if err := h.addToIgnoreFile("AWS-0086"); err != nil {
		t.Fatal(err)
	}
	if err := h.addToIgnoreFile("AWS-0087"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".trivyignore"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "AWS-0086\nAWS-0087\n" {
		t.Errorf("ignore file = %q", string(data))
	}
}

func TestAddToIgnoreFileWithoutRoot(t *testing.T) {
	if err := New().addToIgnoreFile("AWS-0086"); err == nil {
		t.Error("expected an error when no workspace root is known")
	}
}

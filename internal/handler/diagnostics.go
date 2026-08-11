package handler

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/owenrumney/go-lsp/lsp"
	"github.com/owenrumney/trivy-ls/internal/trivy"
)

// diagnosticSource is the value shown next to each diagnostic in the editor.
const diagnosticSource = "trivy"

// severityFor maps Trivy severities onto LSP diagnostic severities.
//
// CRITICAL and HIGH are errors because they are what a user is expected to act
// on; MEDIUM warns; anything lower is informational so it does not drown out
// the compiler diagnostics sharing the same gutter.
func severityFor(s string) lsp.DiagnosticSeverity {
	switch strings.ToUpper(s) {
	case "CRITICAL", "HIGH":
		return lsp.SeverityError
	case "MEDIUM":
		return lsp.SeverityWarning
	case "LOW":
		return lsp.SeverityInformation
	default:
		return lsp.SeverityHint
	}
}

// lineIndex caches file contents so ranges can end at the true end of a line
// rather than an arbitrary column.
type lineIndex struct {
	cache map[string][]string
}

func newLineIndex() *lineIndex {
	return &lineIndex{cache: map[string][]string{}}
}

func (l *lineIndex) lines(path string) []string {
	if lines, ok := l.cache[path]; ok {
		return lines
	}

	var lines []string
	if data, err := os.ReadFile(path); err == nil {
		lines = strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	}
	l.cache[path] = lines
	return lines
}

// lineLen returns the length of a 0-based line, or 0 if it cannot be read.
func (l *lineIndex) lineLen(path string, line int) int {
	lines := l.lines(path)
	if line < 0 || line >= len(lines) {
		return 0
	}
	return len(lines[line])
}

// rangeFor converts a finding's 1-based line span into an LSP range.
//
// Findings with no line information (checks that assert the absence of
// something) are reported against the first line of the file. By default only
// the first line of a span is underlined, because IaC findings routinely cover
// an entire resource block and a 20-line squiggle is unreadable.
func rangeFor(idx *lineIndex, path string, f trivy.Finding, fullRange bool) lsp.Range {
	if !f.HasLocation() {
		return lsp.Range{
			Start: lsp.Position{Line: 0, Character: 0},
			End:   lsp.Position{Line: 0, Character: idx.lineLen(path, 0)},
		}
	}

	start := f.StartLine - 1
	end := start
	if fullRange && f.EndLine > f.StartLine {
		end = f.EndLine - 1
	}

	return lsp.Range{
		Start: lsp.Position{Line: start, Character: 0},
		End:   lsp.Position{Line: end, Character: idx.lineLen(path, end)},
	}
}

// diagnosticData is attached to each diagnostic so a client that round-trips it
// through a code action request can be matched back to its finding.
type diagnosticData struct {
	ID   string     `json:"id"`
	Kind trivy.Kind `json:"kind"`
}

func toDiagnostics(idx *lineIndex, path string, findings []trivy.Finding, fullRange bool) []lsp.Diagnostic {
	diags := make([]lsp.Diagnostic, 0, len(findings))

	for _, f := range findings {
		severity := severityFor(f.Severity)

		code, err := json.Marshal(f.ID)
		if err != nil {
			code = nil
		}

		diag := lsp.Diagnostic{
			Range:    rangeFor(idx, path, f, fullRange),
			Severity: &severity,
			Code:     code,
			Source:   diagnosticSource,
			Message:  message(f),
		}

		if f.URL != "" {
			diag.CodeDescription = &lsp.CodeDescription{Href: lsp.URI(f.URL)}
		}
		if data, err := json.Marshal(diagnosticData{ID: f.ID, Kind: f.Kind}); err == nil {
			diag.Data = data
		}

		diags = append(diags, diag)
	}

	// Stable ordering keeps client-side diagnostic lists from jumping around
	// between scans.
	sort.SliceStable(diags, func(i, j int) bool {
		if diags[i].Range.Start.Line != diags[j].Range.Start.Line {
			return diags[i].Range.Start.Line < diags[j].Range.Start.Line
		}
		return diags[i].Message < diags[j].Message
	})

	return diags
}

func message(f trivy.Finding) string {
	msg := f.Message
	if msg == "" {
		msg = f.Title
	}
	if msg == "" {
		msg = f.ID
	}

	if f.Kind == trivy.KindMisconfig && f.Resource != "" {
		return msg + " (" + f.Resource + ")"
	}
	return msg
}

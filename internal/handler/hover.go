package handler

import (
	"context"
	"strings"

	"github.com/owenrumney/go-lsp/lsp"
	"github.com/owenrumney/trivy-ls/internal/trivy"
)

// Hover renders the details of every finding on the hovered line. Diagnostics
// only carry a one-line message, so hover is where the description, resolution
// and advisory link live.
func (h *Handler) Hover(_ context.Context, params *lsp.HoverParams) (*lsp.Hover, error) {
	findings := h.findingsFor(params.TextDocument.URI)
	if len(findings) == 0 {
		return nil, nil
	}

	var sections []string
	for _, f := range findings {
		if coversLine(f, params.Position.Line) {
			sections = append(sections, f.Detail())
		}
	}

	if len(sections) == 0 {
		return nil, nil
	}

	return &lsp.Hover{
		Contents: lsp.NewHoverContents(lsp.Markdown, strings.Join(sections, "\n\n---\n\n")),
	}, nil
}

// coversLine reports whether a finding applies to a 0-based line. Findings
// with no line information are attributed to the first line of the file.
func coversLine(f trivy.Finding, line int) bool {
	if !f.HasLocation() {
		return line == 0
	}

	start := f.StartLine - 1
	end := start
	if f.EndLine > f.StartLine {
		end = f.EndLine - 1
	}
	return line >= start && line <= end
}

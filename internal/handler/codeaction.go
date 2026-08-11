package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/owenrumney/go-lsp/lsp"
	"github.com/owenrumney/trivy-ls/internal/trivy"
)

// CommandIgnore appends a check ID to the workspace ignore file.
const CommandIgnore = "trivy-ls.addToIgnoreFile"

// defaultIgnoreFile is the ignore file Trivy reads by default.
const defaultIgnoreFile = ".trivyignore"

// CodeAction offers ignore and advisory actions for the findings under the
// cursor.
func (h *Handler) CodeAction(_ context.Context, params *lsp.CodeActionParams) ([]lsp.CodeAction, error) {
	findings := h.findingsFor(params.TextDocument.URI)
	if len(findings) == 0 {
		return nil, nil
	}

	var actions []lsp.CodeAction
	seen := map[string]struct{}{}

	for _, f := range findings {
		if !overlaps(f, params.Range) {
			continue
		}
		// A single check can fail several times in one file; one set of
		// actions per check ID is enough.
		if _, dup := seen[f.ID]; dup {
			continue
		}
		seen[f.ID] = struct{}{}

		if action, ok := h.ignoreInlineAction(params.TextDocument.URI, f); ok {
			actions = append(actions, action)
		}
		actions = append(actions, h.ignoreFileAction(f))
		if f.URL != "" {
			actions = append(actions, openAdvisoryAction(f))
		}
	}

	return actions, nil
}

// overlaps reports whether a finding's line span intersects the requested
// range. Findings with no line information sit on the first line.
func overlaps(f trivy.Finding, r lsp.Range) bool {
	start, end := 0, 0
	if f.HasLocation() {
		start = f.StartLine - 1
		end = start
		if f.EndLine > f.StartLine {
			end = f.EndLine - 1
		}
	}
	return start <= r.End.Line && end >= r.Start.Line
}

// ignoreInlineAction builds a quick fix inserting a `trivy:ignore` comment
// directly above the offending line. It is skipped for findings with no line
// to anchor to, and for file types with no line comment syntax.
func (h *Handler) ignoreInlineAction(uri lsp.DocumentURI, f trivy.Finding) (lsp.CodeAction, bool) {
	if !f.HasLocation() {
		return lsp.CodeAction{}, false
	}

	path, ok := uriToPath(uri)
	if !ok {
		return lsp.CodeAction{}, false
	}

	prefix, ok := commentPrefix(path)
	if !ok {
		return lsp.CodeAction{}, false
	}

	line := f.StartLine - 1
	indent := indentOf(h.lineText(uri, path, line))

	kind := lsp.CodeActionQuickFix
	preferred := true

	return lsp.CodeAction{
		Title:       fmt.Sprintf("Ignore %s on this line", f.ID),
		Kind:        &kind,
		IsPreferred: &preferred,
		Edit: &lsp.WorkspaceEdit{
			Changes: map[lsp.DocumentURI][]lsp.TextEdit{
				uri: {{
					Range: lsp.Range{
						Start: lsp.Position{Line: line, Character: 0},
						End:   lsp.Position{Line: line, Character: 0},
					},
					NewText: fmt.Sprintf("%s%strivy:ignore:%s\n", indent, prefix, f.ID),
				}},
			},
		},
	}, true
}

// ignoreFileAction adds the check to the workspace ignore file. It runs as a
// command rather than a workspace edit because the ignore file usually does
// not exist yet, and clients vary in whether they honour file creation.
func (h *Handler) ignoreFileAction(f trivy.Finding) lsp.CodeAction {
	kind := lsp.CodeActionQuickFix
	arg, _ := json.Marshal(f.ID)

	return lsp.CodeAction{
		Title: fmt.Sprintf("Ignore %s workspace-wide (%s)", f.ID, h.ignoreFileName()),
		Kind:  &kind,
		Command: &lsp.Command{
			Title:     "Add to ignore file",
			Command:   CommandIgnore,
			Arguments: []json.RawMessage{arg},
		},
	}
}

func openAdvisoryAction(f trivy.Finding) lsp.CodeAction {
	arg, _ := json.Marshal(f.URL)

	return lsp.CodeAction{
		Title: fmt.Sprintf("Open advisory for %s", f.ID),
		Command: &lsp.Command{
			Title:     "Open advisory",
			Command:   CommandOpenURL,
			Arguments: []json.RawMessage{arg},
		},
	}
}

// addToIgnoreFile appends a check ID to the ignore file, creating it if needed,
// and skips IDs that are already listed.
func (h *Handler) addToIgnoreFile(id string) error {
	h.mu.RLock()
	root := h.root
	h.mu.RUnlock()

	if root == "" {
		return fmt.Errorf("no workspace root")
	}

	path := filepath.Join(root, h.ignoreFileName())

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == id {
			return nil
		}
	}

	body := string(existing)
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	body += id + "\n"

	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// ignoreFileName is the configured ignore file, relative to the workspace root.
func (h *Handler) ignoreFileName() string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.cfg.IgnoreFile != "" {
		return h.cfg.IgnoreFile
	}
	return defaultIgnoreFile
}

// lineText returns a line of a document, preferring the open buffer over disk
// so the edit lands correctly when the file has unsaved changes.
func (h *Handler) lineText(uri lsp.DocumentURI, path string, line int) string {
	if text, ok := h.docs.Text(uri); ok {
		return nthLine(text, line)
	}
	if data, err := os.ReadFile(path); err == nil {
		return nthLine(string(data), line)
	}
	return ""
}

func nthLine(text string, line int) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if line < 0 || line >= len(lines) {
		return ""
	}
	return lines[line]
}

func indentOf(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// commentPrefix returns the line comment marker for a file, and whether the
// format supports comments at all. JSON does not, so inline ignores are not
// offered for it.
func commentPrefix(path string) (string, bool) {
	base := strings.ToLower(filepath.Base(path))
	switch filepath.Ext(base) {
	case ".json":
		return "", false
	case ".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".toml", ".sh", ".bash", ".py", ".rb":
		return "#", true
	}

	if strings.HasPrefix(base, "dockerfile") || strings.HasPrefix(base, "containerfile") {
		return "#", true
	}
	if base == "makefile" {
		return "#", true
	}

	// Trivy's remaining targets (k8s manifests, CI config, shell) are all
	// hash-commented formats.
	return "#", true
}

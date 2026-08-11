package handler

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenrumney/go-lsp/lsp"
	"github.com/owenrumney/go-lsp/servertest"
)

// lspURI is a small helper so tests can build URIs from raw strings.
func lspURI(s string) lsp.DocumentURI { return lsp.DocumentURI(s) }

// requireTrivy skips a test when the Trivy binary is unavailable, so the unit
// tests still run on a machine without it.
func requireTrivy(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not installed; skipping end-to-end test")
	}
}

// startServer boots the language server against the fixture workspace and
// waits for the first scan to publish.
func startServer(t *testing.T) (*servertest.Harness, string) {
	t.Helper()

	root, err := filepath.Abs("testdata/workspace")
	if err != nil {
		t.Fatal(err)
	}

	// The vulnerability scanner needs a database download, so the fixture scan
	// is limited to the two offline scanners.
	h := servertest.New(t, New(),
		servertest.WithServerOptions(Options()...),
		servertest.WithInitializeParams(&lsp.InitializeParams{
			WorkspaceFolders: []lsp.WorkspaceFolder{{
				URI:  pathToURI(root),
				Name: "workspace",
			}},
			InitializationOptions: json.RawMessage(`{"scanners":["misconfig","secret"]}`),
		}))

	return h, root
}

func TestServerPublishesTerraformDiagnostics(t *testing.T) {
	requireTrivy(t)

	h, root := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	uri := pathToURI(filepath.Join(root, "main.tf"))
	diags, err := h.WaitForDiagnostics(ctx, uri)
	if err != nil {
		t.Fatalf("waiting for diagnostics: %v", err)
	}

	if len(diags) == 0 {
		t.Fatal("expected diagnostics for main.tf")
	}

	for _, d := range diags {
		if d.Source != "trivy" {
			t.Errorf("diagnostic source = %q, want trivy", d.Source)
		}
		if d.Message == "" {
			t.Error("diagnostic has an empty message")
		}
		if d.Severity == nil {
			t.Error("diagnostic has no severity")
		}
	}

	// The open security group is the finding a user would expect to see.
	if !hasCode(diags, "AWS-0107") && !hasCode(diags, "AVD-AWS-0107") {
		t.Errorf("expected the open ingress finding; got codes %v", codesOf(diags))
	}
}

// A Dockerfile check that asserts the absence of an instruction carries no
// line number, and must still surface as a file-level diagnostic.
func TestServerPublishesFileLevelDockerfileDiagnostics(t *testing.T) {
	requireTrivy(t)

	h, root := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	uri := pathToURI(filepath.Join(root, "Dockerfile"))
	diags, err := h.WaitForDiagnostics(ctx, uri)
	if err != nil {
		t.Fatalf("waiting for diagnostics: %v", err)
	}

	if len(diags) == 0 {
		t.Fatal("expected diagnostics for Dockerfile")
	}
	for _, d := range diags {
		if d.Range.Start.Line != 0 {
			t.Errorf("diagnostic %s on line %d, want line 0", d.Message, d.Range.Start.Line)
		}
	}
}

func TestServerPublishesSecretDiagnostics(t *testing.T) {
	requireTrivy(t)

	h, root := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	uri := pathToURI(filepath.Join(root, "secrets.txt"))
	diags, err := h.WaitForDiagnostics(ctx, uri)
	if err != nil {
		t.Fatalf("waiting for diagnostics: %v", err)
	}

	if len(diags) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(diags))
	}
	if diags[0].Range.Start.Line != 1 {
		t.Errorf("secret on line %d, want line 1", diags[0].Range.Start.Line)
	}
	if *diags[0].Severity != lsp.SeverityError {
		t.Errorf("severity = %d, want error for a critical secret", *diags[0].Severity)
	}
}

func TestServerOffersHoverAndCodeActions(t *testing.T) {
	requireTrivy(t)

	h, root := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	uri := pathToURI(filepath.Join(root, "main.tf"))
	diags, err := h.WaitForDiagnostics(ctx, uri)
	if err != nil {
		t.Fatalf("waiting for diagnostics: %v", err)
	}

	line := diags[0].Range.Start.Line

	hover, err := h.Hover(uri, line, 0)
	if err != nil {
		t.Fatalf("hover: %v", err)
	}
	if hover == nil || hover.Contents.Markup == nil || hover.Contents.Markup.Value == "" {
		t.Fatal("expected hover content on a line with a finding")
	}

	actions, err := h.CodeAction(&lsp.CodeActionParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: uri},
		Range: lsp.Range{
			Start: lsp.Position{Line: line},
			End:   lsp.Position{Line: line},
		},
	})
	if err != nil {
		t.Fatalf("code action: %v", err)
	}
	if len(actions) == 0 {
		t.Fatal("expected code actions on a line with a finding")
	}

	var sawInlineIgnore bool
	for _, a := range actions {
		if a.Edit != nil && len(a.Edit.Changes[uri]) > 0 {
			sawInlineIgnore = true
		}
	}
	if !sawInlineIgnore {
		t.Error("expected an inline ignore quick fix among the code actions")
	}
}

func TestServerReportsCapabilities(t *testing.T) {
	requireTrivy(t)

	h, _ := startServer(t)

	if h.InitResult == nil {
		t.Fatal("no initialize result recorded")
	}
	if name := h.InitResult.ServerInfo.Name; name != serverName {
		t.Errorf("server name = %q, want %q", name, serverName)
	}

	caps := h.InitResult.Capabilities
	if caps.HoverProvider == nil {
		t.Error("hover should be advertised")
	}
	if caps.CodeActionProvider == nil {
		t.Error("code actions should be advertised")
	}

	// Clients decide whether to forward workspace/executeCommand based on this
	// list, so an empty one silently disables every command.
	if caps.ExecuteCommandProvider == nil {
		t.Fatal("execute command should be advertised")
	}
	want := map[string]bool{CommandScan: false, CommandOpenURL: false, CommandIgnore: false}
	for _, cmd := range caps.ExecuteCommandProvider.Commands {
		want[cmd] = true
	}
	for cmd, found := range want {
		if !found {
			t.Errorf("command %q is not advertised", cmd)
		}
	}
}

func hasCode(diags []lsp.Diagnostic, want string) bool {
	for _, c := range codesOf(diags) {
		if c == want {
			return true
		}
	}
	return false
}

func codesOf(diags []lsp.Diagnostic) []string {
	codes := make([]string, 0, len(diags))
	for _, d := range diags {
		var code string
		if err := json.Unmarshal(d.Code, &code); err == nil {
			codes = append(codes, code)
		}
	}
	return codes
}

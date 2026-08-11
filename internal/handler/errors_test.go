package handler

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owenrumney/go-lsp/lsp"
	"github.com/owenrumney/go-lsp/servertest"
)

// missingBinary is a trivy path that cannot exist, so these tests exercise the
// failure path without needing Trivy installed.
const missingBinary = "trivy-does-not-exist-xyz"

// startFailingServer boots a server pointed at a binary that does not exist.
func startFailingServer(t *testing.T, options string) (*servertest.Harness, string) {
	t.Helper()

	root, err := filepath.Abs("testdata/workspace")
	if err != nil {
		t.Fatal(err)
	}

	h := servertest.New(t, New(),
		servertest.WithServerOptions(Options()...),
		servertest.WithInitializeParams(&lsp.InitializeParams{
			WorkspaceFolders: []lsp.WorkspaceFolder{{
				URI:  pathToURI(root),
				Name: "workspace",
			}},
			InitializationOptions: json.RawMessage(options),
		}))

	return h, root
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A scan the user asked for must never fail silently: an explicit action that
// reports nothing reads as "no findings", which on a security tool is the most
// damaging thing the server could say. Background scans still report only once,
// so a broken configuration does not raise a dialog on every save.
func TestScanFailureIsReportedOncePerBackgroundRunAndAlwaysOnRequest(t *testing.T) {
	h, root := startFailingServer(t, `{"trivyPath":"`+missingBinary+`"}`)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	msg, err := h.WaitForMessage(ctx)
	if err != nil {
		t.Fatalf("waiting for the missing binary message: %v", err)
	}
	if !strings.Contains(msg.Message, missingBinary) {
		t.Errorf("message should name the binary it looked for, got %q", msg.Message)
	}
	if !strings.Contains(msg.Message, "trivyPath") {
		t.Errorf("message should name the setting that fixes it, got %q", msg.Message)
	}

	// Every failure is logged, so the LSP log is never silent even when the
	// dialog is suppressed.
	waitUntil(t, "the failure to be logged", func() bool { return len(h.LogMessages()) > 0 })

	logs, dialogs := len(h.LogMessages()), len(h.Messages())

	if err := h.DidSave(pathToURI(filepath.Join(root, "main.tf"))); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the background scan to log", func() bool { return len(h.LogMessages()) > logs })

	if got := len(h.Messages()); got != dialogs {
		t.Errorf("background scan raised %d extra dialogs, want 0", got-dialogs)
	}

	if _, err := h.ExecuteCommand(CommandScan, nil); err != nil {
		t.Fatalf("executing %s: %v", CommandScan, err)
	}
	waitUntil(t, "the requested scan to report", func() bool { return len(h.Messages()) > dialogs })
}

// With no scan to surface it, a missing binary would otherwise go unmentioned
// until the user asked for a scan and wondered why nothing happened.
func TestMissingTrivyIsReportedWhenNoScanRunsAtStartup(t *testing.T) {
	h, _ := startFailingServer(t, `{"trivyPath":"`+missingBinary+`","scanOnOpen":false}`)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	msg, err := h.WaitForMessage(ctx)
	if err != nil {
		t.Fatalf("waiting for the startup message: %v", err)
	}
	if !strings.Contains(msg.Message, missingBinary) {
		t.Errorf("message should name the binary it looked for, got %q", msg.Message)
	}
}

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/owenrumney/go-lsp/document"
	"github.com/owenrumney/go-lsp/lsp"
	"github.com/owenrumney/go-lsp/server"
	"github.com/owenrumney/trivy-ls/internal/trivy"
)

// Version is the server version, overridden at build time via ldflags.
var Version = "dev"

const (
	serverName = "trivy-ls"

	// CommandScan triggers a workspace rescan.
	//
	// The commands are namespaced "trivy-ls." rather than "trivy." because
	// VS Code resolves code action commands against a single global registry,
	// where the Aqua Trivy extension already claims the "trivy." prefix.
	CommandScan = "trivy-ls.scan"
	// CommandOpenURL asks the client to open a finding's advisory page.
	CommandOpenURL = "trivy-ls.openUrl"
)

// progressToken identifies the scan progress indicator. A fixed token is
// sufficient because only one scan runs at a time.
var progressToken = lsp.ProgressToken(`"trivy-ls/scan"`)

// Handler implements the LSP surface of the Trivy language server.
//
// Trivy scans a whole workspace rather than a single buffer, and takes seconds
// rather than milliseconds, so scans run on a background goroutine and are
// coalesced: a request that arrives while a scan is in flight queues at most
// one follow-up scan.
type Handler struct {
	docs   *document.Store
	client *server.Client

	mu        sync.RWMutex
	cfg       Config
	root      string
	findings  trivy.Findings
	published map[lsp.DocumentURI]struct{}

	scanReq   chan struct{}
	scanOnce  sync.Once
	warnOnce  sync.Once
	scanState sync.Mutex
}

// Options returns the server options that declare capabilities go-lsp cannot
// infer from the handler's method set. Clients route workspace/executeCommand
// using the advertised command list, so it has to be explicit.
func Options() []server.Option {
	return []server.Option{
		server.WithCodeActionOptions(lsp.CodeActionOptions{
			CodeActionKinds: []lsp.CodeActionKind{lsp.CodeActionQuickFix},
		}),
		server.WithExecuteCommandOptions(lsp.ExecuteCommandOptions{
			Commands: []string{CommandScan, CommandOpenURL, CommandIgnore},
		}),
	}
}

// New returns a Handler ready to be passed to server.NewServer.
func New() *Handler {
	return &Handler{
		docs:      document.NewStore(),
		cfg:       defaultConfig(),
		findings:  trivy.Findings{},
		published: map[lsp.DocumentURI]struct{}{},
		scanReq:   make(chan struct{}, 1),
	}
}

// SetClient receives the outbound client before any request is dispatched.
func (h *Handler) SetClient(client *server.Client) { h.client = client }

// Initialize records the workspace root and client configuration.
func (h *Handler) Initialize(_ context.Context, params *lsp.InitializeParams) (*lsp.InitializeResult, error) {
	cfg := parseConfig(params.InitializationOptions)
	root := rootFrom(params)

	h.mu.Lock()
	h.cfg = cfg
	h.root = root
	h.mu.Unlock()

	if root != "" && cfg.scanOnOpen() {
		h.trigger()
	}

	return &lsp.InitializeResult{
		ServerInfo: &lsp.ServerInfo{Name: serverName, Version: Version},
	}, nil
}

// Shutdown satisfies the lifecycle handler. The scan goroutine exits with the
// process; there is no state to flush.
func (h *Handler) Shutdown(_ context.Context) error { return nil }

// rootFrom picks the workspace root, preferring workspace folders over the
// deprecated rootUri and rootPath fields.
func rootFrom(params *lsp.InitializeParams) string {
	if len(params.WorkspaceFolders) > 0 {
		if path, ok := uriToPath(params.WorkspaceFolders[0].URI); ok {
			return path
		}
	}
	if params.RootURI != nil {
		if path, ok := uriToPath(*params.RootURI); ok {
			return path
		}
	}
	if params.RootPath != nil && *params.RootPath != "" {
		return filepath.Clean(*params.RootPath)
	}
	return ""
}

// --- text document sync -------------------------------------------------

func (h *Handler) DidOpen(_ context.Context, params *lsp.DidOpenTextDocumentParams) error {
	_, err := h.docs.Open(params)
	return err
}

func (h *Handler) DidChange(_ context.Context, params *lsp.DidChangeTextDocumentParams) error {
	_, err := h.docs.Change(params)
	return err
}

func (h *Handler) DidClose(_ context.Context, params *lsp.DidCloseTextDocumentParams) error {
	h.docs.Close(params)
	return nil
}

// DidSave rescans the workspace. Trivy reads from disk, so a save is the
// earliest point at which a rescan can see the user's edits.
func (h *Handler) DidSave(_ context.Context, _ *lsp.DidSaveTextDocumentParams) error {
	h.mu.RLock()
	scan := h.cfg.scanOnSave()
	h.mu.RUnlock()

	if scan {
		h.trigger()
	}
	return nil
}

// DidChangeConfiguration re-reads settings and rescans, so a client can change
// scanners or severities without a restart.
func (h *Handler) DidChangeConfiguration(_ context.Context, params *lsp.DidChangeConfigurationParams) error {
	if params.Settings == nil {
		return nil
	}

	raw, err := json.Marshal(params.Settings)
	if err != nil {
		return nil
	}
	cfg := parseConfig(raw)

	h.mu.Lock()
	h.cfg = cfg
	h.mu.Unlock()

	h.trigger()
	return nil
}

// --- commands -----------------------------------------------------------

// ExecuteCommand handles the server's custom commands.
func (h *Handler) ExecuteCommand(ctx context.Context, params *lsp.ExecuteCommandParams) (any, error) {
	switch params.Command {
	case CommandScan:
		h.trigger()
		return nil, nil

	case CommandOpenURL:
		if len(params.Arguments) == 0 {
			return nil, errors.New(CommandOpenURL + " requires a url argument")
		}
		var url string
		if err := json.Unmarshal(params.Arguments[0], &url); err != nil {
			return nil, fmt.Errorf("%s: %w", CommandOpenURL, err)
		}
		external := true
		_, err := h.client.ShowDocument(ctx, &lsp.ShowDocumentParams{
			URI:      lsp.URI(url),
			External: &external,
		})
		return nil, err

	case CommandIgnore:
		if len(params.Arguments) == 0 {
			return nil, errors.New(CommandIgnore + " requires a check id argument")
		}
		var id string
		if err := json.Unmarshal(params.Arguments[0], &id); err != nil {
			return nil, fmt.Errorf("%s: %w", CommandIgnore, err)
		}
		if err := h.addToIgnoreFile(id); err != nil {
			return nil, err
		}
		h.trigger()
		return nil, nil

	default:
		return nil, fmt.Errorf("unknown command %q", params.Command)
	}
}

// --- scanning -----------------------------------------------------------

// trigger requests a scan, coalescing with any request already queued.
func (h *Handler) trigger() {
	h.scanOnce.Do(func() { go h.scanLoop() })

	select {
	case h.scanReq <- struct{}{}:
	default:
		// A scan is already queued and will observe the current state.
	}
}

func (h *Handler) scanLoop() {
	for range h.scanReq {
		h.scan(context.Background())
	}
}

func (h *Handler) scan(ctx context.Context) {
	h.scanState.Lock()
	defer h.scanState.Unlock()

	h.mu.RLock()
	cfg, root := h.cfg, h.root
	h.mu.RUnlock()

	if root == "" {
		return
	}

	h.beginProgress(ctx)
	defer h.endProgress(ctx)

	findings, err := cfg.runner().Scan(ctx, root)
	if err != nil {
		h.reportScanError(ctx, err)
		return
	}

	h.publish(ctx, findings, cfg.FullRange)
}

// publish sends diagnostics for every file with findings and clears
// diagnostics for files that had findings in the previous scan but no longer
// do. Without the second step, fixed findings would linger in the editor.
func (h *Handler) publish(ctx context.Context, findings trivy.Findings, fullRange bool) {
	idx := newLineIndex()
	current := make(map[lsp.DocumentURI]struct{}, len(findings))

	for path, fs := range findings {
		uri := pathToURI(path)
		current[uri] = struct{}{}

		_ = h.client.PublishDiagnostics(ctx, &lsp.PublishDiagnosticsParams{
			URI:         uri,
			Diagnostics: toDiagnostics(idx, path, fs, fullRange),
		})
	}

	h.mu.Lock()
	stale := h.published
	h.findings = findings
	h.published = current
	h.mu.Unlock()

	for uri := range stale {
		if _, still := current[uri]; still {
			continue
		}
		_ = h.client.PublishDiagnostics(ctx, &lsp.PublishDiagnosticsParams{
			URI:         uri,
			Diagnostics: []lsp.Diagnostic{},
		})
	}
}

// findingsFor returns the findings recorded for a document URI.
func (h *Handler) findingsFor(uri lsp.DocumentURI) []trivy.Finding {
	path, ok := uriToPath(uri)
	if !ok {
		return nil
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.findings[path]
}

// reportScanError tells the user once when Trivy is missing, and logs
// everything else without nagging.
func (h *Handler) reportScanError(ctx context.Context, err error) {
	var notInstalled *trivy.ErrNotInstalled
	if errors.As(err, &notInstalled) {
		h.warnOnce.Do(func() {
			_ = h.client.ShowMessage(ctx, &lsp.ShowMessageParams{
				Type: lsp.MessageTypeError,
				Message: fmt.Sprintf(
					"%s: %s. Install Trivy or set trivyPath in the server settings.",
					serverName, notInstalled.Error(),
				),
			})
		})
		return
	}

	_ = h.client.LogMessage(ctx, &lsp.LogMessageParams{
		Type:    lsp.MessageTypeError,
		Message: serverName + ": " + err.Error(),
	})
}

func (h *Handler) beginProgress(ctx context.Context) {
	if err := h.client.CreateWorkDoneProgress(ctx, &lsp.WorkDoneProgressCreateParams{
		Token: progressToken,
	}); err != nil {
		return
	}

	value, err := json.Marshal(lsp.WorkDoneProgressBegin{
		Kind:    "begin",
		Title:   "Trivy scan",
		Message: "scanning workspace",
	})
	if err != nil {
		return
	}

	_ = h.client.Progress(ctx, &lsp.ProgressParams{Token: progressToken, Value: value})
}

func (h *Handler) endProgress(ctx context.Context) {
	value, err := json.Marshal(lsp.WorkDoneProgressEnd{Kind: "end"})
	if err != nil {
		return
	}
	_ = h.client.Progress(ctx, &lsp.ProgressParams{Token: progressToken, Value: value})
}

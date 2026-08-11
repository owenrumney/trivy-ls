package handler

import (
	"encoding/json"

	"github.com/owenrumney/trivy-ls/internal/trivy"
)

// Config is the server configuration, supplied by the client either as
// initializationOptions or via workspace/didChangeConfiguration under a
// "trivy" key.
type Config struct {
	// TrivyPath is the trivy executable to run. Defaults to "trivy" on PATH.
	TrivyPath string `json:"trivyPath"`
	// Scanners passed to --scanners.
	Scanners []string `json:"scanners"`
	// Severities passed to --severity. Empty means all.
	Severities []string `json:"severities"`
	// IgnoreFile passed to --ignorefile.
	IgnoreFile string `json:"ignoreFile"`
	// ConfigFile passed to --config.
	ConfigFile string `json:"configFile"`
	// ExtraArgs are appended to the trivy command line verbatim.
	ExtraArgs []string `json:"extraArgs"`

	// ScanOnSave rescans the workspace when a file is saved. Default true.
	ScanOnSave *bool `json:"scanOnSave"`
	// ScanOnOpen scans the workspace once at startup. Default true.
	ScanOnOpen *bool `json:"scanOnOpen"`
	// FullRange underlines the whole span a finding covers rather than just
	// its first line. Default false, because IaC findings routinely span
	// entire resource blocks.
	FullRange bool `json:"fullRange"`
}

func defaultConfig() Config {
	scanOnSave, scanOnOpen := true, true
	return Config{
		TrivyPath:  "trivy",
		Scanners:   []string{"misconfig", "secret", "vuln"},
		ScanOnSave: &scanOnSave,
		ScanOnOpen: &scanOnOpen,
	}
}

// parseConfig merges raw client-supplied options over the defaults. Options may
// be given either bare or nested under a "trivy" key, since clients differ.
func parseConfig(raw json.RawMessage) Config {
	cfg := defaultConfig()
	if len(raw) == 0 {
		return cfg
	}

	var nested struct {
		Trivy json.RawMessage `json:"trivy"`
	}
	if err := json.Unmarshal(raw, &nested); err == nil && len(nested.Trivy) > 0 {
		raw = nested.Trivy
	}

	// Unmarshalling onto the defaults leaves unset fields untouched, except
	// for slices, which we restore below if the client omitted them.
	scanners := cfg.Scanners
	cfg.Scanners = nil
	if err := json.Unmarshal(raw, &cfg); err != nil {
		cfg = defaultConfig()
		return cfg
	}
	if len(cfg.Scanners) == 0 {
		cfg.Scanners = scanners
	}
	if cfg.TrivyPath == "" {
		cfg.TrivyPath = "trivy"
	}
	if cfg.ScanOnSave == nil {
		v := true
		cfg.ScanOnSave = &v
	}
	if cfg.ScanOnOpen == nil {
		v := true
		cfg.ScanOnOpen = &v
	}

	return cfg
}

func (c Config) scanOnSave() bool { return c.ScanOnSave == nil || *c.ScanOnSave }
func (c Config) scanOnOpen() bool { return c.ScanOnOpen == nil || *c.ScanOnOpen }

func (c Config) runner() *trivy.Runner {
	return &trivy.Runner{
		Binary:     c.TrivyPath,
		Scanners:   c.Scanners,
		Severities: c.Severities,
		IgnoreFile: c.IgnoreFile,
		ConfigFile: c.ConfigFile,
		ExtraArgs:  c.ExtraArgs,
	}
}

package handler

import (
	"reflect"
	"testing"
)

func TestParseConfigDefaults(t *testing.T) {
	cfg := parseConfig(nil)

	if cfg.TrivyPath != "trivy" {
		t.Errorf("trivy path = %q", cfg.TrivyPath)
	}
	if !reflect.DeepEqual(cfg.Scanners, []string{"misconfig", "secret", "vuln"}) {
		t.Errorf("scanners = %v", cfg.Scanners)
	}
	if !cfg.scanOnSave() || !cfg.scanOnOpen() {
		t.Error("scanning should be enabled by default")
	}
	if cfg.FullRange {
		t.Error("full range should be off by default")
	}
}

func TestParseConfigOverrides(t *testing.T) {
	cfg := parseConfig([]byte(`{
		"trivyPath": "/opt/trivy",
		"scanners": ["misconfig"],
		"severities": ["HIGH", "CRITICAL"],
		"scanOnSave": false,
		"fullRange": true
	}`))

	if cfg.TrivyPath != "/opt/trivy" {
		t.Errorf("trivy path = %q", cfg.TrivyPath)
	}
	if !reflect.DeepEqual(cfg.Scanners, []string{"misconfig"}) {
		t.Errorf("scanners = %v", cfg.Scanners)
	}
	if !reflect.DeepEqual(cfg.Severities, []string{"HIGH", "CRITICAL"}) {
		t.Errorf("severities = %v", cfg.Severities)
	}
	if cfg.scanOnSave() {
		t.Error("scanOnSave should be disabled")
	}
	if !cfg.scanOnOpen() {
		t.Error("scanOnOpen should still default to true")
	}
	if !cfg.FullRange {
		t.Error("fullRange should be enabled")
	}
}

// Clients differ on whether settings arrive bare or namespaced, so both are
// accepted.
func TestParseConfigAcceptsNestedTrivyKey(t *testing.T) {
	cfg := parseConfig([]byte(`{"trivy": {"trivyPath": "/opt/trivy", "scanners": ["secret"]}}`))

	if cfg.TrivyPath != "/opt/trivy" {
		t.Errorf("trivy path = %q", cfg.TrivyPath)
	}
	if !reflect.DeepEqual(cfg.Scanners, []string{"secret"}) {
		t.Errorf("scanners = %v", cfg.Scanners)
	}
}

func TestParseConfigInvalidJSONFallsBackToDefaults(t *testing.T) {
	cfg := parseConfig([]byte(`not json`))

	if cfg.TrivyPath != "trivy" {
		t.Errorf("trivy path = %q, want the default", cfg.TrivyPath)
	}
}

func TestRunnerFromConfig(t *testing.T) {
	cfg := parseConfig([]byte(`{"trivyPath": "/opt/trivy", "ignoreFile": ".myignore", "extraArgs": ["--offline-scan"]}`))
	r := cfg.runner()

	if r.Binary != "/opt/trivy" {
		t.Errorf("binary = %q", r.Binary)
	}
	if r.IgnoreFile != ".myignore" {
		t.Errorf("ignore file = %q", r.IgnoreFile)
	}
	if !reflect.DeepEqual(r.ExtraArgs, []string{"--offline-scan"}) {
		t.Errorf("extra args = %v", r.ExtraArgs)
	}
}

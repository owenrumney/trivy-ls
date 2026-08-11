package trivy

import (
	"fmt"
	"strings"
)

// Kind distinguishes the scanner that produced a finding.
type Kind string

const (
	KindMisconfig     Kind = "misconfiguration"
	KindSecret        Kind = "secret"
	KindVulnerability Kind = "vulnerability"
)

// Finding is a scanner-independent view of a single Trivy result, flattened so
// the LSP layer does not need to care which scanner produced it.
type Finding struct {
	ID          string
	Kind        Kind
	Title       string
	Message     string
	Description string
	Resolution  string
	Severity    string
	URL         string
	References  []string

	// StartLine and EndLine are 1-based. Zero means "no line information",
	// in which case the finding applies to the file as a whole.
	StartLine int
	EndLine   int

	// Resource is set for misconfigurations (e.g. aws_s3_bucket.acme_bucket).
	Resource string

	// Package fields are set for vulnerabilities.
	PkgName      string
	PkgVersion   string
	FixedVersion string
}

// HasLocation reports whether the finding can be placed on a specific line.
func (f Finding) HasLocation() bool { return f.StartLine > 0 }

// Label is a short one-line description used in code action titles.
func (f Finding) Label() string {
	if f.Title != "" {
		return f.Title
	}
	if f.Message != "" {
		return f.Message
	}
	return f.ID
}

// Detail renders the finding as markdown for hover.
func (f Finding) Detail() string {
	var b strings.Builder

	fmt.Fprintf(&b, "**%s** — %s\n\n", f.Severity, f.Label())

	if f.Kind == KindVulnerability && f.PkgName != "" {
		fmt.Fprintf(&b, "`%s` %s", f.PkgName, f.PkgVersion)
		if f.FixedVersion != "" {
			fmt.Fprintf(&b, " → fixed in **%s**", f.FixedVersion)
		}
		b.WriteString("\n\n")
	}

	if f.Resource != "" {
		fmt.Fprintf(&b, "Resource: `%s`\n\n", f.Resource)
	}

	if f.Message != "" && f.Message != f.Title {
		fmt.Fprintf(&b, "%s\n\n", f.Message)
	}

	if f.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", strings.TrimSpace(f.Description))
	}

	if f.Resolution != "" {
		fmt.Fprintf(&b, "**Resolution:** %s\n\n", f.Resolution)
	}

	if f.URL != "" {
		fmt.Fprintf(&b, "[%s](%s)", f.ID, f.URL)
	} else {
		b.WriteString(f.ID)
	}

	return strings.TrimSpace(b.String())
}

// Findings groups findings by the file path they apply to. Paths are absolute.
type Findings map[string][]Finding

// Flatten converts a report into findings keyed by absolute file path.
// resolve maps a Trivy target to an absolute path on disk; targets it rejects
// (synthetic targets, or files that are not present) are dropped.
func (r *Report) Flatten(resolve func(target string) (string, bool)) Findings {
	out := Findings{}

	for _, res := range r.Results {
		path, ok := resolve(res.Target)
		if !ok {
			continue
		}

		for _, m := range res.Misconfigurations {
			if m.Status != "" && m.Status != "FAIL" {
				continue
			}
			out[path] = append(out[path], Finding{
				ID:          m.CheckID(),
				Kind:        KindMisconfig,
				Title:       m.Title,
				Message:     m.Message,
				Description: m.Description,
				Resolution:  m.Resolution,
				Severity:    normaliseSeverity(m.Severity),
				URL:         m.PrimaryURL,
				References:  m.References,
				StartLine:   m.CauseMetadata.StartLine,
				EndLine:     m.CauseMetadata.EndLine,
				Resource:    m.CauseMetadata.Resource,
			})
		}

		for _, s := range res.Secrets {
			out[path] = append(out[path], Finding{
				ID:        s.RuleID,
				Kind:      KindSecret,
				Title:     s.Title,
				Message:   fmt.Sprintf("%s secret detected", s.Category),
				Severity:  normaliseSeverity(s.Severity),
				StartLine: s.StartLine,
				EndLine:   s.EndLine,
			})
		}

		if len(res.Vulnerabilities) > 0 {
			locations := packageLocations(res.Packages)
			for _, v := range res.Vulnerabilities {
				loc := locations[v.PkgID]
				out[path] = append(out[path], Finding{
					ID:           v.VulnerabilityID,
					Kind:         KindVulnerability,
					Title:        v.Title,
					Message:      vulnMessage(v),
					Description:  v.Description,
					Severity:     normaliseSeverity(v.Severity),
					URL:          v.PrimaryURL,
					References:   v.References,
					StartLine:    loc.StartLine,
					EndLine:      loc.EndLine,
					PkgName:      v.PkgName,
					PkgVersion:   v.InstalledVersion,
					FixedVersion: v.FixedVersion,
				})
			}
		}
	}

	return out
}

func vulnMessage(v Vulnerability) string {
	msg := fmt.Sprintf("%s in %s %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion)
	if v.FixedVersion != "" {
		msg += fmt.Sprintf(" (fixed in %s)", v.FixedVersion)
	}
	return msg
}

// packageLocations indexes the first recorded location of each package so
// vulnerabilities can be placed on the line that declares the package.
func packageLocations(pkgs []Package) map[string]Location {
	locations := make(map[string]Location, len(pkgs))
	for _, p := range pkgs {
		if len(p.Locations) == 0 {
			continue
		}
		if _, seen := locations[p.ID]; !seen {
			locations[p.ID] = p.Locations[0]
		}
	}
	return locations
}

func normaliseSeverity(s string) string {
	if s == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(s)
}

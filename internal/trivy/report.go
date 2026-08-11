package trivy

// Report is the top level of a Trivy JSON report (SchemaVersion 2).
type Report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []Result `json:"Results"`
}

// Result holds the findings for a single scan target. A target is usually a
// file path relative to the scan root, but for some scanners it can be a
// synthetic name such as "." that does not exist on disk.
type Result struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Type              string             `json:"Type"`
	Packages          []Package          `json:"Packages"`
	Vulnerabilities   []Vulnerability    `json:"Vulnerabilities"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations"`
	Secrets           []Secret           `json:"Secrets"`
}

// Package is an installed package discovered in a lockfile or image layer.
// Vulnerabilities reference packages by ID; the locations recorded here are
// the only way to place a vulnerability on a line.
type Package struct {
	ID        string     `json:"ID"`
	Name      string     `json:"Name"`
	Version   string     `json:"Version"`
	Locations []Location `json:"Locations"`
}

// Location is a 1-based line span within the target file.
type Location struct {
	StartLine int `json:"StartLine"`
	EndLine   int `json:"EndLine"`
}

// Vulnerability is a CVE (or equivalent advisory) affecting a package.
type Vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgID            string   `json:"PkgID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Status           string   `json:"Status"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
}

// Misconfiguration is a failed IaC / config check.
type Misconfiguration struct {
	Type          string        `json:"Type"`
	ID            string        `json:"ID"`
	AVDID         string        `json:"AVDID"`
	Title         string        `json:"Title"`
	Description   string        `json:"Description"`
	Message       string        `json:"Message"`
	Resolution    string        `json:"Resolution"`
	Severity      string        `json:"Severity"`
	PrimaryURL    string        `json:"PrimaryURL"`
	References    []string      `json:"References"`
	Status        string        `json:"Status"`
	CauseMetadata CauseMetadata `json:"CauseMetadata"`
}

// CauseMetadata locates the cause of a misconfiguration. StartLine and EndLine
// are zero for checks that assert the *absence* of something (for example
// "no HEALTHCHECK defined"), because there is no line to point at.
type CauseMetadata struct {
	Resource  string `json:"Resource"`
	Provider  string `json:"Provider"`
	Service   string `json:"Service"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

// Secret is a secret detected by the secret scanner. Its lines are always set.
type Secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

// CheckID returns the identifier used in ignore rules and AVD lookups.
// Trivy has used both AVDID and ID over time; prefer whichever is set.
func (m Misconfiguration) CheckID() string {
	if m.AVDID != "" {
		return m.AVDID
	}
	return m.ID
}

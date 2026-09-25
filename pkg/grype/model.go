package grype

import (
	"time"
)

const SchemaVersion = 1

type ScanReport struct {
	Matches []Match `json:"matches"`
	Source  Source  `json:"source"`
}

type Match struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	// RelatedVulnerabilities are the records grype links to the match (for a distro advisory, the NVD record of its CVE); grype puts them next to vulnerability.
	RelatedVulnerabilities []RelatedVulnerability `json:"relatedVulnerabilities,omitempty"`
	Artifact               Artifact               `json:"artifact"`
}

type Vulnerability struct {
	ID          string        `json:"id"`
	DataSource  string        `json:"dataSource"`
	Namespace   string        `json:"namespace"`
	Severity    string        `json:"severity"`
	URLs        []string      `json:"urls"`
	Description string        `json:"description"`
	Cvss        []Cvss        `json:"cvss"`
	Fix         Fix           `json:"fix"`
	Advisories  []interface{} `json:"advisories"`
	EPSS        []EPSS        `json:"epss,omitempty"` // Array in Grype 0.100.0
	// RelatedVulnerabilities is always empty in grype's JSON, which puts related records on the
	// match (see Match.RelatedVulnerabilities). The legacy formula and cvss code still reads it
	// (getEPSSScore and getCVSSScore in pkg/scan), so their fallbacks to related records never fire.
	RelatedVulnerabilities []RelatedVulnerability `json:"relatedVulnerabilities,omitempty"`
	KnownExploited         []KnownExploited       `json:"knownExploited,omitempty"`
	CWEs                   []CWE                  `json:"cwes,omitempty"`
	Risk                   float64                `json:"risk"`
}

type Cvss struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Metrics Metrics `json:"metrics"`
}

type Metrics struct {
	BaseScore           float64 `json:"baseScore"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type Artifact struct {
	Name      string         `json:"name"`
	Version   string         `json:"version"`
	Type      string         `json:"type"`
	FoundBy   string         `json:"foundBy"`
	Locations []Location     `json:"locations"`
	Metadata  map[string]any `json:"metadata"`
}

type Location struct {
	Path    string `json:"path"`
	LayerID string `json:"layerID"`
}

type Source struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
	Image  ImageInfo   `json:"image"`
}

type ImageInfo struct {
	UserInput         string    `json:"userInput"`
	ImageID           string    `json:"imageID"`
	ImageDigest       string    `json:"imageDigest"`
	ImageManifest     string    `json:"imageManifest"`
	ImageConfig       string    `json:"imageConfig"`
	ImageConfigDigest string    `json:"imageConfigDigest"`
	ImageLayers       []string  `json:"imageLayers"`
	ImageSize         int64     `json:"imageSize"`
	ManifestDigest    string    `json:"manifestDigest"`
	MediaType         string    `json:"mediaType"`
	Tags              []string  `json:"tags"`
	RepoDigests       []string  `json:"repoDigests"`
	Architecture      string    `json:"architecture"`
	OS                string    `json:"os"`
	Created           time.Time `json:"created"`
	BuiltBy           string    `json:"builtBy"`
	BuildKit          string    `json:"buildKit"`
	Distro            Distro    `json:"distro"`
}

type Distro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	ID      string `json:"id"`
	IDLike  string `json:"idLike"`
}

type VersionInfo struct {
	Version    string    `json:"version"`
	BuildDate  time.Time `json:"buildDate"`
	GitCommit  string    `json:"gitCommit"`
	GitTag     string    `json:"gitTag"`
	Platform   string    `json:"platform"`
	Compiler   string    `json:"compiler"`
	GoVersion  string    `json:"goVersion"`
	LibVersion string    `json:"libVersion"`
}

type Report struct {
	SBOM    any
	Matches []Match
}

// EPSS represents Exploit Prediction Scoring System data
type EPSS struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"epss"`       // EPSS score (0.0-1.0)
	Percentile float64 `json:"percentile"` // EPSS percentile
	Date       string  `json:"date"`       // Date of EPSS data
}

// RelatedVulnerability represents related vulnerability information
type RelatedVulnerability struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	URLs        []string `json:"urls"`
	Description string   `json:"description"`
	Cvss        []Cvss   `json:"cvss"`
	EPSS        []EPSS   `json:"epss,omitempty"`
}

// KnownExploited is an entry of the CISA KEV catalogue that grype attaches to a vulnerability.
type KnownExploited struct {
	CVE                        string `json:"cve"`
	DateAdded                  string `json:"dateAdded,omitempty"` // YYYY-MM-DD
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// CWE is a weakness class assigned to one of the vulnerability's CVEs.
type CWE struct {
	CVE string `json:"cve"`
	CWE string `json:"cwe"`
}

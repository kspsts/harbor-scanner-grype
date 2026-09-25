package harbor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
)

// Severity represents the severity of a image/component in terms of vulnerability.
type Severity int64

// Sevxxx is the list of severity of image after scanning.
const (
	_ Severity = iota
	SevUnknown
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return severityToString[s]
}

var severityToString = map[Severity]string{
	SevUnknown:  "Unknown",
	SevLow:      "Low",
	SevMedium:   "Medium",
	SevHigh:     "High",
	SevCritical: "Critical",
}

var stringToSeverity = map[string]Severity{
	"Unknown":  SevUnknown,
	"Low":      SevLow,
	"Medium":   SevMedium,
	"High":     SevHigh,
	"Critical": SevCritical,
}

// MarshalJSON marshals the Severity enum value as a quoted JSON string.
func (s Severity) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(severityToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmarshals quoted JSON string to the Severity enum value.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var value string
	err := json.Unmarshal(b, &value)
	if err != nil {
		return err
	}
	*s = stringToSeverity[value]
	return nil
}

type CapabilityType string

const (
	CapabilityTypeSBOM          CapabilityType = "sbom"
	CapabilityTypeVulnerability CapabilityType = "vulnerability"
)

var SupportedSBOMMediaTypes = []api.MediaType{
	api.MediaTypeSPDX,
	api.MediaTypeCycloneDX,
}

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	MimeType   string `json:"mime_type,omitempty"`
}

// ScanReportQuery is a struct for the query parameters at "/scan/{scan_request_id}/report".
type ScanReportQuery struct {
	SBOMMediaType api.MediaType `schema:"sbom_media_type"`
}

type ScanRequest struct {
	Registry     Registry     `json:"registry"`
	Artifact     Artifact     `json:"artifact"`
	Capabilities []Capability `json:"enabled_capabilities"`
}

// GetImageRef returns the reference grype and syft pull, host:port/repository@digest, and whether the
// registry speaks plain HTTP. hostMap (SCANNER_REGISTRY_HOST_MAP) replaces the registry host from
// Harbor's request with a host[:port] the scanner can reach; a target without a port keeps the port.
func (c ScanRequest) GetImageRef(hostMap etc.HostMap) (imageRef string, nonSSL bool, err error) {
	registryURL, err := url.Parse(c.Registry.URL)
	if err != nil {
		return "", false, fmt.Errorf("parsing registry URL: %w", err)
	}

	host, port := registryURL.Hostname(), registryURL.Port()
	if port == "" {
		switch registryURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	if target, ok := hostMap.Lookup(host); ok {
		if targetHost, targetPort, splitErr := net.SplitHostPort(target); splitErr == nil {
			host, port = targetHost, targetPort
		} else {
			host = target
		}
	}

	repo := fmt.Sprintf("%s@%s", c.Artifact.Repository, c.Artifact.Digest)
	if port == "" {
		imageRef = fmt.Sprintf("%s/%s", host, repo)
	} else {
		// net.JoinHostPort brackets host when it is an IPv6 literal, e.g. "[::1]:5000".
		imageRef = fmt.Sprintf("%s/%s", net.JoinHostPort(host, port), repo)
	}
	return imageRef, registryURL.Scheme == "http", nil
}

type ScanResponse struct {
	ID string `json:"id"`
}

type ScanReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	Artifact    Artifact  `json:"artifact"`
	Scanner     Scanner   `json:"scanner"`
	Severity    Severity  `json:"severity,omitempty"`

	// For SBOM
	MediaType api.MediaType `json:"media_type,omitempty"`
	SBOM      any           `json:"sbom,omitempty"`

	// For vulnerabilities
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities,omitempty"`
}

type Layer struct {
	Digest string `json:"digest,omitempty"`
	DiffID string `json:"diff_id,omitempty"`
}

type CVSSDetails struct {
	ScoreV2  *float32 `json:"score_v2,omitempty"`
	ScoreV3  *float32 `json:"score_v3,omitempty"`
	VectorV2 string   `json:"vector_v2"`
	VectorV3 string   `json:"vector_v3"`
}

// VulnerabilityItem is an item in the vulnerability result returned by vulnerability details API.
type VulnerabilityItem struct {
	ID               string         `json:"id"`
	Pkg              string         `json:"package"`
	Version          string         `json:"version"`
	FixVersion       string         `json:"fix_version,omitempty"`
	Severity         Severity       `json:"severity"`
	Description      string         `json:"description"`
	Links            []string       `json:"links"`
	Layer            *Layer         `json:"layer"` // Not defined by Scanners API
	PreferredCVSS    *CVSSDetails   `json:"preferred_cvss,omitempty"`
	CweIDs           []string       `json:"cwe_ids,omitempty"`
	VendorAttributes map[string]any `json:"vendor_attributes,omitempty"`
}

type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct {
	Type              CapabilityType `json:"type"`
	ConsumesMIMETypes []string       `json:"consumes_mime_types"`
	ProducesMIMETypes []api.MIMEType `json:"produces_mime_types"`

	// For /metadata
	AdditionalAttributes *CapabilityAttributes `json:"additional_attributes,omitempty"`

	// For /scan
	Parameters *CapabilityAttributes `json:"parameters,omitempty"`
}

type CapabilityAttributes struct {
	SBOMMediaTypes []api.MediaType `json:"sbom_media_types,omitempty"`
}

func GetScannerMetadata() Scanner {
	version, ok := os.LookupEnv("GRYPE_VERSION")
	if !ok {
		version = "Unknown"
	}
	return Scanner{
		Name:    "Grype",
		Vendor:  "Anchore",
		Version: version,
	}
}

package scan

import (
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/exploitdb"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/policy"
)

type Transformer interface {
	Transform(mediaType api.MediaType, request harbor.ScanRequest, report grype.Report) *harbor.ScanReport
	TransformSBOM(mediaType api.MediaType, request harbor.ScanRequest, sbom any) *harbor.ScanReport
}

type transformer struct {
	clock      Clock
	config     etc.RiskConfig
	thresholds policy.Thresholds
	exploits   policy.ExploitLookup
}

// NewTransformer builds Harbor reports from grype output. exploits may be nil: the policy then
// finds exploits only through vulnerability links.
func NewTransformer(clock Clock, config etc.RiskConfig, thresholds policy.Thresholds, exploits policy.ExploitLookup) Transformer {
	return &transformer{
		clock:      clock,
		config:     config,
		thresholds: thresholds,
		exploits:   exploits,
	}
}

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (c *SystemClock) Now() time.Time {
	return time.Now()
}

func (t *transformer) Transform(mediaType api.MediaType, request harbor.ScanRequest, report grype.Report) *harbor.ScanReport {
	now := t.clock.Now()
	scanReport := &harbor.ScanReport{
		GeneratedAt: now,
		Artifact:    request.Artifact,
		Scanner:     harbor.GetScannerMetadata(),
	}

	if mediaType == api.MediaTypeSPDX || mediaType == api.MediaTypeCycloneDX {
		scanReport.MediaType = mediaType
		scanReport.SBOM = report.SBOM
		return scanReport
	}

	if t.config.Risk.PolicyMode() {
		warnIfRiskMissing(report.Matches)
	}

	// One Harbor item per grype match: a CVE found in libcrypto3, libssl3 and openssl is three
	// items, each with its own package. now is read once, here, rather than once per match, so a
	// policy-mode item's dated explanation (see toItem) agrees across every item of one report.
	var vulnerabilities []harbor.VulnerabilityItem
	var maxSeverity harbor.Severity
	for _, match := range report.Matches {
		item := t.toItem(match, now)
		if item.Severity > maxSeverity {
			maxSeverity = item.Severity
		}
		vulnerabilities = append(vulnerabilities, item)
	}

	scanReport.Vulnerabilities = vulnerabilities
	scanReport.Severity = maxSeverity
	return scanReport
}

// warnIfRiskMissing logs one warning per report when a match has EPSS but no risk score. grype
// 0.117.0 gives every finding whose EPSS is above 0 a risk above 0 (the lowest seen is 0.0066), so
// a zero risk there means grype's JSON has no "risk" field, which reads as 0: the policy ladder
// would then rate every such finding Low.
func warnIfRiskMissing(matches []grype.Match) {
	for _, m := range matches {
		v := m.Vulnerability
		if len(v.EPSS) > 0 && v.EPSS[0].Score > 0 && v.Risk == 0 {
			slog.Warn("grype JSON has EPSS but no risk score; the policy ladder needs grype 0.117.0 or newer",
				slog.String("vulnerability", v.ID))
			return
		}
	}
}

// toItem builds one Harbor item from a grype match. asOf is the day (in its own time zone) that
// dates a policy-mode explanation; legacy modes ignore it.
func (t *transformer) toItem(match grype.Match, asOf time.Time) harbor.VulnerabilityItem {
	vuln := match.Vulnerability
	item := harbor.VulnerabilityItem{
		ID:          vuln.ID,
		Pkg:         match.Artifact.Name,
		Version:     match.Artifact.Version,
		Description: vuln.Description,
		Links:       vuln.URLs,
	}
	if len(vuln.Fix.Versions) > 0 {
		item.FixVersion = vuln.Fix.Versions[0]
	}

	switch {
	case !t.config.Risk.Enabled:
		item.Severity = mapGrypeSeverityToHarbor(vuln.Severity)
	case t.config.Risk.PolicyMode():
		res := policy.Evaluate(match, t.exploits, t.thresholds, asOf)
		item.Severity = res.Severity
		item.Description = withReason(res.Reason, vuln.Description)
		item.Links = appendMissing(vuln.URLs, res.Links)
	default:
		severity, info := t.calculateSeverityWithInfo(vuln)
		item.Severity = severity
		item.Description = vuln.Description + info
	}

	if len(vuln.Cvss) > 0 {
		cvss := vuln.Cvss[0] // Use first CVSS entry
		item.PreferredCVSS = &harbor.CVSSDetails{
			VectorV2: cvss.Vector,
			VectorV3: cvss.Vector,
		}
		if cvss.Version == "2.0" {
			score := float32(cvss.Metrics.BaseScore)
			item.PreferredCVSS.ScoreV2 = &score
		} else if cvss.Version == "3.0" || cvss.Version == "3.1" {
			score := float32(cvss.Metrics.BaseScore)
			item.PreferredCVSS.ScoreV3 = &score
		}
	}
	return item
}

// withReason puts the explanation in front of the description; Harbor shows both as one paragraph.
func withReason(reason, description string) string {
	if description == "" {
		return reason
	}
	return reason + " — " + description
}

// appendMissing merges extra into links without duplicates, and never returns nil: a policy-mode
// item with no links then reports "links": [] rather than "links": null. The vulnerability
// database and our own links write an Exploit-DB link in different forms (trailing slash, http vs
// https, "www." or not), so those are deduped by numeric id (exploitdb.IDFromURL); every other
// link is deduped by exact string match.
func appendMissing(links, extra []string) []string {
	out := make([]string, 0, len(links)+len(extra))
	out = append(out, links...)

	ids := make(map[string]bool, len(out))
	for _, link := range out {
		if id, ok := exploitdb.IDFromURL(link); ok {
			ids[id] = true
		}
	}

	for _, link := range extra {
		if id, ok := exploitdb.IDFromURL(link); ok {
			if ids[id] {
				continue
			}
			ids[id] = true
			out = append(out, link)
			continue
		}
		if !slices.Contains(out, link) {
			out = append(out, link)
		}
	}
	return out
}

func mapGrypeSeverityToHarbor(severity string) harbor.Severity {
	switch severity {
	case "Critical":
		return harbor.SevCritical
	case "High":
		return harbor.SevHigh
	case "Medium":
		return harbor.SevMedium
	case "Low":
		return harbor.SevLow
	default:
		return harbor.SevUnknown
	}
}

// calculateSeverity calculates severity based on configured mode
func (t *transformer) calculateSeverity(vuln grype.Vulnerability) harbor.Severity {
	switch t.config.Risk.Mode {
	case "formula":
		return t.calculateRiskBasedSeverity(vuln)
	case "cvss":
		return t.calculateCVSSBasedSeverity(vuln)
	default:
		// Fallback to original Grype severity
		return mapGrypeSeverityToHarbor(vuln.Severity)
	}
}

// calculateSeverityWithInfo calculates severity and returns risk calculation info
func (t *transformer) calculateSeverityWithInfo(vuln grype.Vulnerability) (harbor.Severity, string) {
	switch t.config.Risk.Mode {
	case "formula":
		return t.calculateRiskBasedSeverityWithInfo(vuln)
	case "cvss":
		return t.calculateCVSSBasedSeverityWithInfo(vuln)
	default:
		// Fallback to original Grype severity
		return mapGrypeSeverityToHarbor(vuln.Severity), ""
	}
}

// calculateRiskBasedSeverity calculates severity based on Risk = EPSS * (CVSS/10)
func (t *transformer) calculateRiskBasedSeverity(vuln grype.Vulnerability) harbor.Severity {
	severity, _ := t.calculateRiskBasedSeverityWithInfo(vuln)
	return severity
}

// calculateRiskBasedSeverityWithInfo calculates severity and returns risk calculation info
func (t *transformer) calculateRiskBasedSeverityWithInfo(vuln grype.Vulnerability) (harbor.Severity, string) {
	// Get EPSS score
	epssScore := t.getEPSSScore(vuln)

	// Get CVSS score
	cvssScore := t.getCVSSScore(vuln)

	// Calculate risk: Risk = EPSS * (CVSS/10)
	// EPSS is in decimal format (0.006460 = 0.646%), so we multiply by 100 to get percentage
	riskPercentage := epssScore * 100 * (cvssScore / 10.0)

	// Determine severity based on thresholds
	severity := t.mapRiskToSeverity(riskPercentage)

	// Create risk calculation info
	riskInfo := fmt.Sprintf(" [RISK: %.3f%%] EPSS: %.6f%% × CVSS: %.1f ÷ 10 = %.3f%% → %s",
		riskPercentage, epssScore*100, cvssScore, riskPercentage, severity.String())

	return severity, riskInfo
}

// calculateCVSSBasedSeverity calculates severity based on CVSS score only
func (t *transformer) calculateCVSSBasedSeverity(vuln grype.Vulnerability) harbor.Severity {
	severity, _ := t.calculateCVSSBasedSeverityWithInfo(vuln)
	return severity
}

// calculateCVSSBasedSeverityWithInfo calculates severity based on CVSS score and returns calculation info
func (t *transformer) calculateCVSSBasedSeverityWithInfo(vuln grype.Vulnerability) (harbor.Severity, string) {
	// Get CVSS score
	cvssScore := t.getCVSSScore(vuln)

	// Map CVSS score to severity based on configured thresholds
	severity := t.mapCVSSToSeverity(cvssScore)

	// Create CVSS calculation info
	riskInfo := fmt.Sprintf(" [CVSS: %.1f] Direct CVSS scoring → %s",
		cvssScore, severity.String())

	return severity, riskInfo
}

// getEPSSScore extracts EPSS score from vulnerability
func (t *transformer) getEPSSScore(vuln grype.Vulnerability) float64 {
	// Try to get EPSS from main vulnerability first
	if len(vuln.EPSS) > 0 && vuln.EPSS[0].Score > 0 {
		return vuln.EPSS[0].Score
	}

	// Try to get EPSS from related vulnerabilities
	for _, related := range vuln.RelatedVulnerabilities {
		if len(related.EPSS) > 0 && related.EPSS[0].Score > 0 {
			return related.EPSS[0].Score
		}
	}

	// Return default EPSS if not available
	return t.config.Risk.Defaults.EPSS
}

// getCVSSScore extracts CVSS score from vulnerability
func (t *transformer) getCVSSScore(vuln grype.Vulnerability) float64 {
	// Try to get CVSS v3 score first, then v2 from main vulnerability
	for _, cvss := range vuln.Cvss {
		if cvss.Version == "3.0" || cvss.Version == "3.1" {
			return cvss.Metrics.BaseScore
		}
	}

	// Fallback to CVSS v2 from main vulnerability
	for _, cvss := range vuln.Cvss {
		if cvss.Version == "2.0" {
			return cvss.Metrics.BaseScore
		}
	}

	// Try to get CVSS from related vulnerabilities
	for _, related := range vuln.RelatedVulnerabilities {
		// Try CVSS v3 first
		for _, cvss := range related.Cvss {
			if cvss.Version == "3.0" || cvss.Version == "3.1" {
				return cvss.Metrics.BaseScore
			}
		}
		// Fallback to CVSS v2
		for _, cvss := range related.Cvss {
			if cvss.Version == "2.0" {
				return cvss.Metrics.BaseScore
			}
		}
	}

	// Return default CVSS if not available
	return t.config.Risk.Defaults.CVSS
}

// mapRiskToSeverity maps risk percentage to Harbor severity
func (t *transformer) mapRiskToSeverity(riskPercentage float64) harbor.Severity {
	if riskPercentage >= t.config.Risk.Thresholds.Critical {
		return harbor.SevCritical
	} else if riskPercentage >= t.config.Risk.Thresholds.High {
		return harbor.SevHigh
	} else if riskPercentage >= t.config.Risk.Thresholds.Medium {
		return harbor.SevMedium
	} else if riskPercentage >= t.config.Risk.Thresholds.Low {
		return harbor.SevLow
	}
	return harbor.SevUnknown
}

// mapCVSSToSeverity maps CVSS score to Harbor severity
func (t *transformer) mapCVSSToSeverity(cvssScore float64) harbor.Severity {
	if cvssScore >= t.config.Risk.CVSSThresholds.Critical {
		return harbor.SevCritical
	} else if cvssScore >= t.config.Risk.CVSSThresholds.High {
		return harbor.SevHigh
	} else if cvssScore >= t.config.Risk.CVSSThresholds.Medium {
		return harbor.SevMedium
	} else if cvssScore >= t.config.Risk.CVSSThresholds.Low {
		return harbor.SevLow
	}
	return harbor.SevUnknown
}

func (t *transformer) TransformSBOM(mediaType api.MediaType, request harbor.ScanRequest, sbom any) *harbor.ScanReport {
	return &harbor.ScanReport{
		GeneratedAt: t.clock.Now(),
		Artifact:    request.Artifact,
		Scanner:     harbor.GetScannerMetadata(),
		MediaType:   mediaType,
		SBOM:        sbom,
	}
}

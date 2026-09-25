package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

func cvss(scores ...float64) []grype.Cvss {
	var out []grype.Cvss
	for _, s := range scores {
		out = append(out, grype.Cvss{Version: "3.1", Metrics: grype.Metrics{BaseScore: s}})
	}
	return out
}

func TestSeverityFactorMatchesGrype(t *testing.T) {
	assert.InDelta(t, 0.94, severityFactor("Critical", cvss(9.8)), 1e-9)
	assert.InDelta(t, 0.75, severityFactor("High", nil), 1e-9)
	assert.InDelta(t, 0.5, severityFactor("", cvss(5.0, 0)), 1e-9, "unknown severity counts as 5, zero scores are skipped")
	assert.InDelta(t, 0.175, severityFactor("Negligible", cvss(2.0, 4.0)), 1e-9)
}

// Rows of `grype` output for an n8n image on Alpine: EPSS × factor × 100 is the RISK column.
func TestSeverityFactorReproducesGrypeRiskColumn(t *testing.T) {
	assert.InDelta(t, 49.3, 0.524*severityFactor("Critical", cvss(9.8))*100, 0.05)  // CVE-2025-15467
	assert.InDelta(t, 74.5, 0.784*severityFactor("Critical", cvss(10.0))*100, 0.05) // GHSA-v4pr-fm98-w9pg
}

func TestEstimateRiskUsesGrypeValue(t *testing.T) {
	v := grype.Vulnerability{Severity: "High", Risk: 69.0,
		EPSS: []grype.EPSS{{CVE: "CVE-2023-45288", Score: 0.92}}}
	est := estimateRisk(v)
	assert.Equal(t, 69.0, est.value)
	assert.False(t, est.rescaled)
	assert.Equal(t, "CVE-2023-45288", est.epss.CVE)
}

func TestEstimateRiskKeepsGrypeValueWhenFirstEPSSIsHighest(t *testing.T) {
	v := grype.Vulnerability{Severity: "High", Risk: 45.0,
		EPSS: []grype.EPSS{{CVE: "CVE-2099-1001", Score: 0.60}, {CVE: "CVE-2099-1000", Score: 0.02}}}
	est := estimateRisk(v)
	assert.Equal(t, 45.0, est.value)
	assert.False(t, est.rescaled)
	assert.Equal(t, "CVE-2099-1001", est.epss.CVE)
}

func TestEstimateRiskRescalesAdvisoriesToHighestEPSS(t *testing.T) {
	// An Amazon advisory without CVSS: grype multiplies the first EPSS (2%) by 0.75.
	v := grype.Vulnerability{ID: "ALAS2-2099-0001", Severity: "High", Risk: 1.5,
		EPSS: []grype.EPSS{{CVE: "CVE-2099-1000", Score: 0.02}, {CVE: "CVE-2099-1001", Score: 0.60}}}
	est := estimateRisk(v)
	assert.InDelta(t, 45.0, est.value, 1e-9)
	assert.True(t, est.rescaled)
	assert.Equal(t, 1.5, est.reported)
	assert.Equal(t, "CVE-2099-1001", est.epss.CVE)
}

func TestEstimateRiskPicksHighestEPSSAnywhereInTheList(t *testing.T) {
	v := grype.Vulnerability{ID: "ELSA-2099-0001", Severity: "High", Risk: 1.5,
		EPSS: []grype.EPSS{{CVE: "CVE-2099-1000", Score: 0.02}, {CVE: "CVE-2099-1001", Score: 0.10},
			{CVE: "CVE-2099-1002", Score: 0.60}, {CVE: "CVE-2099-1003", Score: 0.05}}}
	est := estimateRisk(v)
	assert.InDelta(t, 45.0, est.value, 1e-9)
	assert.Equal(t, "CVE-2099-1002", est.epss.CVE)
}

func TestEstimateRiskKeepsGrypeValueWhenFirstTiesWithHighest(t *testing.T) {
	v := grype.Vulnerability{Severity: "High", Risk: 45.0,
		EPSS: []grype.EPSS{{CVE: "CVE-2099-1000", Score: 0.60}, {CVE: "CVE-2099-1001", Score: 0.60}}}
	est := estimateRisk(v)
	assert.False(t, est.rescaled)
	assert.Equal(t, "CVE-2099-1000", est.epss.CVE)
}

func TestEstimateRiskKeepsGrypeValueForKEV(t *testing.T) {
	// grype: threat 1 × 0.75 × KEV 1.05 = 78.75; EPSS takes no part.
	v := grype.Vulnerability{Severity: "High", Risk: 78.75,
		KnownExploited: []grype.KnownExploited{{CVE: "CVE-2099-1000"}},
		EPSS:           []grype.EPSS{{CVE: "CVE-2099-1000", Score: 0.02}, {CVE: "CVE-2099-1001", Score: 0.60}}}
	est := estimateRisk(v)
	assert.Equal(t, 78.75, est.value)
	assert.False(t, est.rescaled)
}

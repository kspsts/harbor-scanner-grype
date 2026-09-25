package scan

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/policy"
	"github.com/stretchr/testify/assert"
)

func TestCalculateRiskBasedSeverity(t *testing.T) {
	// Test configuration with custom thresholds for formula mode
	config := etc.RiskConfig{Risk: etc.RiskConfigData{
		Mode:    "formula",
		Enabled: true,
		Thresholds: etc.RiskThresholds{
			Critical: 75.0,
			High:     50.0,
			Medium:   25.0,
			Low:      10.0,
		},
		Defaults: etc.RiskDefaults{
			EPSS: 0.1,
			CVSS: 5.0,
		},
	}}

	transformer := &transformer{
		clock:  &SystemClock{},
		config: config,
	}

	tests := []struct {
		name             string
		vulnerability    grype.Vulnerability
		expectedSeverity harbor.Severity
		description      string
	}{
		{
			name: "High risk - high EPSS and CVSS",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-1234",
				EPSS: []grype.EPSS{
					{Score: 0.8}, // 80% EPSS
				},
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 9.0, // High CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevHigh,
			description:      "Risk = 0.8 * (9.0/10) = 0.72 = 72% -> High (below 75% threshold for Critical)",
		},
		{
			name: "Critical risk - very high EPSS and CVSS",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-5678",
				EPSS: []grype.EPSS{
					{Score: 0.9}, // 90% EPSS
				},
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 9.5, // Very high CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevCritical,
			description:      "Risk = 0.9 * (9.5/10) = 0.855 = 85.5% -> Critical",
		},
		{
			name: "Medium risk",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-9012",
				EPSS: []grype.EPSS{
					{Score: 0.6}, // 60% EPSS
				},
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 8.0, // High CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevMedium,
			description:      "Risk = 0.6 * (8.0/10) = 0.48 = 48% -> Medium (below 50% threshold for High)",
		},
		{
			name: "Low risk",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-3456",
				EPSS: []grype.EPSS{
					{Score: 0.3}, // 30% EPSS
				},
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 7.0, // Medium-high CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevLow,
			description:      "Risk = 0.3 * (7.0/10) = 0.21 = 21% -> Low (below 25% threshold for Medium)",
		},
		{
			name: "Low risk - exact threshold",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-7890",
				EPSS: []grype.EPSS{
					{Score: 0.2}, // 20% EPSS
				},
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 5.0, // Medium CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevLow,
			description:      "Risk = 0.2 * (5.0/10) = 0.1 = 10% -> Low (exactly at threshold)",
		},
		{
			name: "Unknown risk - very low",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-1111",
				EPSS: []grype.EPSS{
					{Score: 0.05}, // 5% EPSS
				},
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 3.0, // Low CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevUnknown,
			description:      "Risk = 0.05 * (3.0/10) = 0.015 = 1.5% -> Unknown",
		},
		{
			name: "Missing EPSS - uses default",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-2222",
				// No EPSS data
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 8.0,
						},
					},
				},
			},
			expectedSeverity: harbor.SevUnknown,
			description:      "Risk = 0.1 * (8.0/10) = 0.08 = 8% -> Unknown (using default EPSS 0.1, below 10% threshold)",
		},
		{
			name: "Missing CVSS - uses default",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-3333",
				EPSS: []grype.EPSS{
					{Score: 0.8},
				},
				// No CVSS data
			},
			expectedSeverity: harbor.SevMedium,
			description:      "Risk = 0.8 * (5.0/10) = 0.4 = 40% -> Medium (using default CVSS 5.0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformer.calculateSeverity(tt.vulnerability)
			assert.Equal(t, tt.expectedSeverity, result, tt.description)
		})
	}
}

func TestMapRiskToSeverity(t *testing.T) {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{
		Thresholds: etc.RiskThresholds{
			Critical: 75.0,
			High:     50.0,
			Medium:   25.0,
			Low:      10.0,
		},
	}}

	transformer := &transformer{
		config: config,
	}

	tests := []struct {
		riskPercentage   float64
		expectedSeverity harbor.Severity
	}{
		{85.0, harbor.SevCritical},
		{75.0, harbor.SevCritical},
		{60.0, harbor.SevHigh},
		{50.0, harbor.SevHigh},
		{35.0, harbor.SevMedium},
		{25.0, harbor.SevMedium},
		{15.0, harbor.SevLow},
		{10.0, harbor.SevLow},
		{5.0, harbor.SevUnknown},
		{0.0, harbor.SevUnknown},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Risk_%.1f", tt.riskPercentage), func(t *testing.T) {
			result := transformer.mapRiskToSeverity(tt.riskPercentage)
			assert.Equal(t, tt.expectedSeverity, result)
		})
	}
}

func TestCalculateCVSSBasedSeverity(t *testing.T) {
	// Test configuration with CVSS thresholds
	config := etc.RiskConfig{Risk: etc.RiskConfigData{
		Mode:    "cvss",
		Enabled: true,
		CVSSThresholds: etc.CVSSThresholds{
			Critical: 9.0,
			High:     7.0,
			Medium:   4.0,
			Low:      0.1,
		},
		Defaults: etc.RiskDefaults{
			CVSS: 5.0,
		},
	}}

	transformer := &transformer{
		clock:  &SystemClock{},
		config: config,
	}

	tests := []struct {
		name             string
		vulnerability    grype.Vulnerability
		expectedSeverity harbor.Severity
		description      string
	}{
		{
			name: "Critical CVSS - very high score",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-1234",
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 9.5, // Very high CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevCritical,
			description:      "CVSS 9.5 >= 9.0 -> Critical",
		},
		{
			name: "High CVSS",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-5678",
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 8.0, // High CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevHigh,
			description:      "CVSS 8.0 >= 7.0 -> High",
		},
		{
			name: "Medium CVSS",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-9012",
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 5.0, // Medium CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevMedium,
			description:      "CVSS 5.0 >= 4.0 -> Medium",
		},
		{
			name: "Low CVSS",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-3456",
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 2.0, // Low CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevLow,
			description:      "CVSS 2.0 >= 0.1 -> Low",
		},
		{
			name: "Unknown CVSS - very low",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-7890",
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 0.05, // Very low CVSS
						},
					},
				},
			},
			expectedSeverity: harbor.SevUnknown,
			description:      "CVSS 0.05 < 0.1 -> Unknown",
		},
		{
			name: "Missing CVSS - uses default",
			vulnerability: grype.Vulnerability{
				ID: "CVE-2023-1111",
				// No CVSS data
			},
			expectedSeverity: harbor.SevMedium,
			description:      "CVSS 5.0 (default) >= 4.0 -> Medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformer.calculateSeverity(tt.vulnerability)
			assert.Equal(t, tt.expectedSeverity, result, tt.description)
		})
	}
}

func TestMapCVSSToSeverity(t *testing.T) {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{
		CVSSThresholds: etc.CVSSThresholds{
			Critical: 9.0,
			High:     7.0,
			Medium:   4.0,
			Low:      0.1,
		},
	}}

	transformer := &transformer{
		config: config,
	}

	tests := []struct {
		cvssScore        float64
		expectedSeverity harbor.Severity
	}{
		{9.5, harbor.SevCritical},
		{9.0, harbor.SevCritical},
		{8.0, harbor.SevHigh},
		{7.0, harbor.SevHigh},
		{5.0, harbor.SevMedium},
		{4.0, harbor.SevMedium},
		{2.0, harbor.SevLow},
		{0.1, harbor.SevLow},
		{0.05, harbor.SevUnknown},
		{0.0, harbor.SevUnknown},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("CVSS_%.1f", tt.cvssScore), func(t *testing.T) {
			result := transformer.mapCVSSToSeverity(tt.cvssScore)
			assert.Equal(t, tt.expectedSeverity, result)
		})
	}
}

func TestTransformWithRiskCalculation(t *testing.T) {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{
		Mode:    "formula",
		Enabled: true,
		Thresholds: etc.RiskThresholds{
			Critical: 75.0,
			High:     50.0,
			Medium:   25.0,
			Low:      10.0,
		},
		Defaults: etc.RiskDefaults{
			EPSS: 0.1,
			CVSS: 5.0,
		},
	}}

	transformer := NewTransformer(&SystemClock{}, config, policy.Thresholds{}, nil)

	request := harbor.ScanRequest{
		Artifact: harbor.Artifact{
			Repository: "test/repo",
			Digest:     "sha256:1234567890",
		},
	}

	report := grype.Report{
		Matches: []grype.Match{{
			Vulnerability: grype.Vulnerability{
				ID: "CVE-2023-1234",
				EPSS: []grype.EPSS{
					{Score: 0.9}, // 90% EPSS
				},
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 9.0, // High CVSS
						},
					},
				},
			},
			Artifact: grype.Artifact{Name: "libssl3", Version: "3.0.11"},
		}},
	}

	// Use any MediaType that's not SPDX or CycloneDX to trigger vulnerability processing
	result := transformer.Transform("application/vnd.security.vulnerability.report", request, report)

	assert.NotNil(t, result)
	assert.Equal(t, harbor.SevCritical, result.Severity)
	assert.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, harbor.SevCritical, result.Vulnerabilities[0].Severity)
	assert.Equal(t, "libssl3", result.Vulnerabilities[0].Pkg)
}

// The one-item-per-match fix applies to every risk mode, not just policy mode (see
// TestTransformOneItemPerMatch in transformer_policy_test.go for the policy-mode version): a CVE
// found in three packages must stay three items, each with its own package, in formula mode too.
func TestTransformFormulaModeOneItemPerMatch(t *testing.T) {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{
		Mode:    "formula",
		Enabled: true,
		Thresholds: etc.RiskThresholds{
			Critical: 75.0,
			High:     50.0,
			Medium:   25.0,
			Low:      10.0,
		},
		Defaults: etc.RiskDefaults{
			EPSS: 0.1,
			CVSS: 5.0,
		},
	}}
	transformer := NewTransformer(&SystemClock{}, config, policy.Thresholds{}, nil)

	vuln := grype.Vulnerability{
		ID:   "CVE-2025-15467",
		EPSS: []grype.EPSS{{Score: 0.9}},
		Cvss: []grype.Cvss{{Version: "3.1", Metrics: grype.Metrics{BaseScore: 9.0}}},
	}
	report := grype.Report{Matches: []grype.Match{
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "libcrypto3", Version: "3.5.4-r0"}},
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "libssl3", Version: "3.5.4-r0"}},
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "openssl", Version: "3.5.4-r0"}},
	}}
	request := harbor.ScanRequest{Artifact: harbor.Artifact{Repository: "test/repo", Digest: "sha256:1234567890"}}

	result := transformer.Transform("application/vnd.security.vulnerability.report", request, report)

	assert.Len(t, result.Vulnerabilities, 3)
	var packages []string
	for _, item := range result.Vulnerabilities {
		packages = append(packages, item.Pkg)
	}
	assert.Equal(t, []string{"libcrypto3", "libssl3", "openssl"}, packages)
}

// SPDX and CycloneDX requests are SBOM requests, not vulnerability scans: Transform must return
// only the SBOM, without touching report.Matches at all.
func TestTransformSBOMMediaTypesReturnSBOMOnly(t *testing.T) {
	transformer := NewTransformer(&SystemClock{}, etc.RiskConfig{}, policy.Thresholds{}, nil)
	sbom := map[string]string{"format": "spdx"}
	report := grype.Report{
		SBOM: sbom,
		Matches: []grype.Match{{
			Vulnerability: grype.Vulnerability{ID: "CVE-2023-1234", Severity: "High"},
			Artifact:      grype.Artifact{Name: "pkg", Version: "1.0"},
		}},
	}
	request := harbor.ScanRequest{Artifact: harbor.Artifact{Repository: "test/repo", Digest: "sha256:1234567890"}}

	for _, mediaType := range []api.MediaType{api.MediaTypeSPDX, api.MediaTypeCycloneDX} {
		t.Run(string(mediaType), func(t *testing.T) {
			result := transformer.Transform(mediaType, request, report)
			assert.Equal(t, mediaType, result.MediaType)
			assert.Equal(t, sbom, result.SBOM)
			assert.Empty(t, result.Vulnerabilities)
			// Severity is left at its Go zero value (distinct from SevUnknown, which is 1 — see
			// harbor.Severity's iota), so the "severity" field is omitted from the SBOM JSON.
			assert.Zero(t, result.Severity)
		})
	}
}

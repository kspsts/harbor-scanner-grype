package scan

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/policy"
)

type fakeExploits map[string][]string

func (f fakeExploits) Lookup(cve string) []string { return f[cve] }

var testRequest = harbor.ScanRequest{Artifact: harbor.Artifact{Repository: "library/n8n", Digest: "sha256:0123"}}

var policyThresholds = policy.Thresholds{Critical: 70, High: 30, Medium: 10}

// fixedClock pins the assessment date so policy-mode tests can use exact-string expectations for
// the dated explanation ("High на 2026-09-25: …").
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// countingClock counts Now() calls; the first call returns first, and every later call returns a
// day later still. A test can then tell whether Transform read the clock once for the whole
// report (every item shares one date) or once per item (a later item would land on a different
// date, since the clock has crossed midnight by then).
type countingClock struct {
	first time.Time
	calls int
}

func (c *countingClock) Now() time.Time {
	t := c.first
	if c.calls > 0 {
		t = c.first.AddDate(0, 0, c.calls)
	}
	c.calls++
	return t
}

func policyTransformer(exploits policy.ExploitLookup) Transformer {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{Enabled: true, Mode: "policy"}}
	clock := fixedClock{time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}
	return NewTransformer(clock, config, policyThresholds, exploits)
}

func TestTransformOneItemPerMatch(t *testing.T) {
	vuln := grype.Vulnerability{ID: "CVE-2025-15467", Severity: "Critical", Risk: 49.3,
		EPSS: []grype.EPSS{{CVE: "CVE-2025-15467", Score: 0.524}}, Fix: grype.Fix{Versions: []string{"3.5.5-r0"}}}
	report := grype.Report{Matches: []grype.Match{
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "libcrypto3", Version: "3.5.4-r0"}},
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "libssl3", Version: "3.5.4-r0"}},
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "openssl", Version: "3.5.4-r0"}},
	}}

	result := policyTransformer(nil).Transform("application/vnd.security.vulnerability.report", testRequest, report)

	require.Len(t, result.Vulnerabilities, 3)
	var packages []string
	for _, item := range result.Vulnerabilities {
		packages = append(packages, item.Pkg)
		assert.Equal(t, "CVE-2025-15467", item.ID)
		assert.Equal(t, "3.5.4-r0", item.Version)
		assert.Equal(t, "3.5.5-r0", item.FixVersion)
		assert.Equal(t, harbor.SevHigh, item.Severity)
	}
	assert.Equal(t, []string{"libcrypto3", "libssl3", "openssl"}, packages)
}

func TestTransformPolicyModeExplainsLevel(t *testing.T) {
	// urls has three spare slots after its one element. If appendMissing ever aliased the input
	// instead of copying it (the "out := links" mutant), appending the Exploit-DB link below would
	// land in that spare capacity and become visible through urls[:2][1].
	urls := make([]string, 1, 4)
	urls[0] = "https://github.com/advisories/GHSA-83qj-6fr2-vhqg"
	report := grype.Report{Matches: []grype.Match{
		{
			Vulnerability: grype.Vulnerability{
				ID: "GHSA-83qj-6fr2-vhqg", Severity: "Critical", Risk: 98.7,
				Description:    "Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT",
				URLs:           urls,
				KnownExploited: []grype.KnownExploited{{CVE: "CVE-2025-24813", DateAdded: "2025-04-01"}},
			},
			Artifact: grype.Artifact{Name: "tomcat-embed-core", Version: "10.1.30"},
		},
		{
			Vulnerability: grype.Vulnerability{
				ID: "CVE-2023-45288", Severity: "High", Risk: 69.0,
				Description: "An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data.",
				EPSS:        []grype.EPSS{{CVE: "CVE-2023-45288", Score: 0.92}},
			},
			Artifact: grype.Artifact{Name: "stdlib", Version: "go1.21.0"},
		},
	}}

	result := policyTransformer(fakeExploits{"CVE-2025-24813": {"52134"}}).
		Transform("application/vnd.security.vulnerability.report", testRequest, report)

	require.Len(t, result.Vulnerabilities, 2)
	tomcat, golang := result.Vulnerabilities[0], result.Vulnerabilities[1]

	assert.Equal(t, harbor.SevCritical, tomcat.Severity)
	assert.Equal(t, "Critical на 2026-09-25: есть в каталоге KEV с 2025-04-01; есть эксплойт в Exploit-DB (52134); риск grype 98.7."+
		" — Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT", tomcat.Description)
	assert.Equal(t, []string{"https://github.com/advisories/GHSA-83qj-6fr2-vhqg", "https://www.exploit-db.com/exploits/52134"}, tomcat.Links)
	assert.Equal(t, "", urls[:2][1], "appendMissing must copy links, not write into the caller's spare capacity")

	assert.Equal(t, harbor.SevHigh, golang.Severity)
	assert.Equal(t, "High на 2026-09-25: риск grype 69.0, порог High от 30 (EPSS 92%, критичность grype High); эксплойтов не найдено; в KEV нет."+
		" — An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data.", golang.Description)

	assert.Equal(t, harbor.SevCritical, result.Severity)
}

func TestTransformWithRiskDisabledKeepsGrypeSeverity(t *testing.T) {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{Enabled: false, Mode: "policy"}}
	tr := NewTransformer(&SystemClock{}, config, policyThresholds, nil)
	report := grype.Report{Matches: []grype.Match{{
		Vulnerability: grype.Vulnerability{ID: "CVE-2023-45288", Severity: "High", Description: "HTTP/2 flood"},
		Artifact:      grype.Artifact{Name: "stdlib", Version: "go1.21.0"},
	}}}

	result := tr.Transform("application/vnd.security.vulnerability.report", testRequest, report)

	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, harbor.SevHigh, result.Vulnerabilities[0].Severity)
	assert.Equal(t, "HTTP/2 flood", result.Vulnerabilities[0].Description)
}

// A finding without a description in the DB shows only the explanation.
func TestTransformPolicyModeWithoutDescription(t *testing.T) {
	report := grype.Report{Matches: []grype.Match{{
		Vulnerability: grype.Vulnerability{ID: "CVE-2099-0101"},
		Artifact:      grype.Artifact{Name: "pkg", Version: "1.0"},
	}}}
	result := policyTransformer(nil).Transform("application/vnd.security.vulnerability.report", testRequest, report)
	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "Unknown на 2026-09-25: EPSS нет, критичность grype неизвестна; эксплойтов не найдено; в KEV нет.", result.Vulnerabilities[0].Description)
}

// An Exploit-DB link that the vulnerability already lists is not added twice.
func TestTransformPolicyModeDoesNotDuplicateLinks(t *testing.T) {
	report := grype.Report{Matches: []grype.Match{{
		Vulnerability: grype.Vulnerability{ID: "CVE-2099-0200", Severity: "High", Risk: 40,
			EPSS: []grype.EPSS{{CVE: "CVE-2099-0200", Score: 0.5}},
			URLs: []string{"https://www.exploit-db.com/exploits/1"}},
		Artifact: grype.Artifact{Name: "pkg", Version: "1.0"},
	}}}
	result := policyTransformer(fakeExploits{"CVE-2099-0200": {"1", "2"}}).
		Transform("application/vnd.security.vulnerability.report", testRequest, report)
	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, []string{"https://www.exploit-db.com/exploits/1", "https://www.exploit-db.com/exploits/2"}, result.Vulnerabilities[0].Links)
}

// The vulnerability database often writes the same Exploit-DB exploit in a different URL form
// (trailing slash, http instead of https) than the one appendMissing builds from Exploit-DB ids.
// The two must be recognised as the same exploit by numeric id, not added twice.
func TestTransformPolicyModeDedupesLinksByExploitDBID(t *testing.T) {
	report := grype.Report{Matches: []grype.Match{{
		Vulnerability: grype.Vulnerability{ID: "CVE-2099-0201", Severity: "High", Risk: 40,
			EPSS: []grype.EPSS{{CVE: "CVE-2099-0201", Score: 0.5}},
			URLs: []string{"http://www.exploit-db.com/exploits/1/"}},
		Artifact: grype.Artifact{Name: "pkg", Version: "1.0"},
	}}}
	result := policyTransformer(fakeExploits{"CVE-2099-0201": {"1", "2"}}).
		Transform("application/vnd.security.vulnerability.report", testRequest, report)
	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, []string{
		"http://www.exploit-db.com/exploits/1/",
		"https://www.exploit-db.com/exploits/2",
	}, result.Vulnerabilities[0].Links)
}

// A policy-mode item with nothing to link to still gets a non-nil, empty slice, so Harbor's JSON
// shows "links": [] rather than "links": null.
func TestTransformPolicyModeLinksNeverNil(t *testing.T) {
	report := grype.Report{Matches: []grype.Match{{
		Vulnerability: grype.Vulnerability{ID: "CVE-2099-0102", Severity: "Low"},
		Artifact:      grype.Artifact{Name: "pkg", Version: "1.0"},
	}}}
	result := policyTransformer(nil).Transform("application/vnd.security.vulnerability.report", testRequest, report)
	require.Len(t, result.Vulnerabilities, 1)
	assert.NotNil(t, result.Vulnerabilities[0].Links)
	assert.Empty(t, result.Vulnerabilities[0].Links)
}

// The PoC link firstPoC finds often comes from a related record's URLs, not the vulnerability's
// own URLs, so it would otherwise be absent from vuln.URLs and left out of Links entirely.
func TestTransformPolicyModePoCFromRelatedRecordIsLinked(t *testing.T) {
	report := grype.Report{Matches: []grype.Match{{
		Vulnerability: grype.Vulnerability{
			ID: "CVE-2025-15467", Severity: "Critical", Risk: 49.3,
			EPSS: []grype.EPSS{{CVE: "CVE-2025-15467", Score: 0.524}},
		},
		RelatedVulnerabilities: []grype.RelatedVulnerability{{ID: "CVE-2025-15467", URLs: []string{"https://github.com/guiimoraes/CVE-2025-15467"}}},
		Artifact:               grype.Artifact{Name: "pkg", Version: "1.0"},
	}}}

	result := policyTransformer(nil).Transform("application/vnd.security.vulnerability.report", testRequest, report)

	require.Len(t, result.Vulnerabilities, 1)
	assert.Contains(t, result.Vulnerabilities[0].Description, "есть PoC (")
	assert.Equal(t, []string{"https://github.com/guiimoraes/CVE-2025-15467"}, result.Vulnerabilities[0].Links)
}

// Transform must read the clock once for the whole report, not once per item: every item of one
// report must carry the same assessment date, and GeneratedAt must be that same, first reading.
func TestTransformReadsClockOncePerReport(t *testing.T) {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{Enabled: true, Mode: "policy"}}
	clock := &countingClock{first: time.Date(2026, 9, 25, 23, 59, 59, 0, time.UTC)}
	tr := NewTransformer(clock, config, policyThresholds, nil)

	vuln := grype.Vulnerability{ID: "CVE-2099-0500", Severity: "High"}
	report := grype.Report{Matches: []grype.Match{
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "a", Version: "1"}},
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "b", Version: "1"}},
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "c", Version: "1"}},
	}}

	result := tr.Transform("application/vnd.security.vulnerability.report", testRequest, report)

	require.Len(t, result.Vulnerabilities, 3)
	assert.Equal(t, 1, clock.calls, "Transform must call Now() once, not once per item")
	assert.Equal(t, clock.first, result.GeneratedAt)
	for _, item := range result.Vulnerabilities {
		assert.Contains(t, item.Description, "на 2026-09-25")
	}
}

// captureLogs redirects the default slog logger to a buffer for the rest of the test, as
// pkg/exploitdb's watcher tests do. The tests in this package are not parallel, so swapping the
// process-wide default logger is safe.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

const noRiskWarning = "grype JSON has EPSS but no risk score"

// reportWithoutRisk is what a grype older than 0.117.0 gives: EPSS, but no "risk", which reads as 0.
func reportWithoutRisk() grype.Report {
	return grype.Report{Matches: []grype.Match{
		{
			Vulnerability: grype.Vulnerability{ID: "CVE-2023-45288", Severity: "High",
				EPSS: []grype.EPSS{{CVE: "CVE-2023-45288", Score: 0.92}}},
			Artifact: grype.Artifact{Name: "stdlib", Version: "go1.21.0"},
		},
		{
			Vulnerability: grype.Vulnerability{ID: "CVE-2025-15467", Severity: "Critical",
				EPSS: []grype.EPSS{{CVE: "CVE-2025-15467", Score: 0.524}}},
			Artifact: grype.Artifact{Name: "libssl3", Version: "3.5.4-r0"},
		},
	}}
}

// Without grype's risk the ladder would rate every finding with EPSS Low; one warning per report,
// naming the first such finding, says why.
func TestTransformPolicyModeWarnsOnceWhenRiskIsMissing(t *testing.T) {
	buf := captureLogs(t)

	policyTransformer(nil).Transform("application/vnd.security.vulnerability.report", testRequest, reportWithoutRisk())

	assert.Equal(t, 1, strings.Count(buf.String(), noRiskWarning), buf.String())
	assert.Contains(t, buf.String(), "vulnerability=CVE-2023-45288")
}

func TestTransformDoesNotWarnWhenRiskIsNotMissing(t *testing.T) {
	t.Run("normal policy-mode report", func(t *testing.T) {
		buf := captureLogs(t)
		report := grype.Report{Matches: []grype.Match{
			{Vulnerability: grype.Vulnerability{ID: "CVE-2023-45288", Severity: "High", Risk: 69.0,
				EPSS: []grype.EPSS{{CVE: "CVE-2023-45288", Score: 0.92}}}},
			// the lowest risk seen next to EPSS in grype 0.117.0 reports
			{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0600", Severity: "Negligible", Risk: 0.00655,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0600", Score: 0.00131}}}},
			// no EPSS, or an EPSS of 0: grype 0.117.0 gives these a risk of 0 too
			{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0601", Severity: "High"}},
			{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0602", Severity: "High",
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0602", Score: 0}}}},
		}}

		policyTransformer(nil).Transform("application/vnd.security.vulnerability.report", testRequest, report)

		assert.NotContains(t, buf.String(), noRiskWarning)
	})

	t.Run("formula mode does not use grype's risk", func(t *testing.T) {
		buf := captureLogs(t)
		config := etc.RiskConfig{Risk: etc.RiskConfigData{Enabled: true, Mode: "formula"}}
		tr := NewTransformer(fixedClock{time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}, config, policy.Thresholds{}, nil)

		tr.Transform("application/vnd.security.vulnerability.report", testRequest, reportWithoutRisk())

		assert.NotContains(t, buf.String(), noRiskWarning)
	})
}

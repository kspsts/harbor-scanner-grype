package policy

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

// Reduced reports of grype 0.117.0 with its DB built 2026-09-15, run offline. The GitHub ones scan
// lockfiles with one affected version per advisory, in grype's default mode (GHSA ids) and with
// --by-cve (the CVE id where there is one).
const (
	githubFixture      = "testdata/grype-github-lockfiles.json"
	githubByCVEFixture = "testdata/grype-github-lockfiles-bycve.json"
	ubuntuFixture      = "testdata/grype-ubuntu-18.10.json"
)

var realAsOf = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func realFixtures(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("testdata/grype-*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files, "run Task 12 of the plan to create the fixtures")
	return files
}

func realFixture(t *testing.T, file string) []grype.Match {
	t.Helper()
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	var doc struct {
		Matches []grype.Match `json:"matches"`
	}
	require.NoError(t, json.Unmarshal(data, &doc), file)
	require.NotEmpty(t, doc.Matches, file)
	return doc.Matches
}

func realMatches(t *testing.T) []grype.Match {
	t.Helper()
	var all []grype.Match
	for _, file := range realFixtures(t) {
		all = append(all, realFixture(t, file)...)
	}
	return all
}

// The rescaling for advisories reuses grype's formula; on real scans the formula must give
// exactly the risk grype reported.
func TestSeverityFactorAgreesWithGrypeOnRealScans(t *testing.T) {
	checked := 0
	for _, m := range realMatches(t) {
		v := m.Vulnerability
		if len(v.EPSS) == 0 || len(v.KnownExploited) > 0 {
			continue
		}
		want := math.Min(v.EPSS[0].Score*severityFactor(v.Severity, v.Cvss), 1) * 100
		assert.InDelta(t, want, v.Risk, 1e-6, "%s in %s", v.ID, m.Artifact.Name)
		checked++
	}
	assert.Greater(t, checked, 10)
}

// The Amazon Linux 2 advisory lists two CVEs and the first EPSS is not the highest: the policy
// rescales it and never goes below grype's own number.
func TestRescaleHappensOnARealAdvisory(t *testing.T) {
	rescaled := 0
	for _, m := range realMatches(t) {
		est := estimateRisk(m.Vulnerability)
		assert.GreaterOrEqual(t, est.value, est.reported-1e-9, m.Vulnerability.ID)
		if est.rescaled {
			rescaled++
		}
	}
	assert.GreaterOrEqual(t, rescaled, 1)
}

func TestEvaluateExplainsEveryRealFinding(t *testing.T) {
	for _, m := range realMatches(t) {
		res := Evaluate(m, nil, Thresholds{Critical: 70, High: 30, Medium: 10}, realAsOf)
		assert.True(t, strings.HasPrefix(res.Reason, res.Severity.String()+" на 2026-09-25: "), res.Reason)
		assert.True(t, strings.HasSuffix(res.Reason, "."), res.Reason)
		assert.LessOrEqual(t, utf8.RuneCountInString(res.Reason), 300, res.Reason)
		for _, bad := range []string{"%!", "  ", "..", "\n"} {
			assert.NotContains(t, res.Reason, bad, res.Reason)
		}
	}
}

// The GitHub scans hit every advisory of knownMalwareAdvisories and those whose title opens with
// one of malwarePrefixes: each is Critical with a malware explanation, whichever id grype reports.
func TestRealMalwareAdvisoriesAreCritical(t *testing.T) {
	for _, file := range []string{githubFixture, githubByCVEFixture} {
		total, listed := 0, 0
		byPrefix := map[string]int{}
		for _, m := range realFixture(t, file) {
			v := m.Vulnerability
			prefix := ""
			for _, p := range malwarePrefixes {
				if strings.HasPrefix(v.Description, p) {
					prefix = p
				}
			}
			if !knownMalwareAdvisories[v.ID] && prefix == "" {
				continue
			}
			total++
			if knownMalwareAdvisories[v.ID] {
				listed++
			}
			if prefix != "" {
				byPrefix[prefix]++
			}
			res := Evaluate(m, nil, thresholds, realAsOf)
			assert.Equal(t, harbor.SevCritical, res.Severity, "%s %s in %s: %s", v.ID, m.Artifact.Name, file, res.Reason)
			assert.Contains(t, res.Reason, "вредонос", "%s %s in %s", v.ID, m.Artifact.Name, file)
		}
		t.Logf("%s: %d malware findings, %d by the allow-list, by prefix %v", file, total, listed, byPrefix)
		assert.GreaterOrEqual(t, total, 62, file)
	}
}

func TestRealDoubtfulAdvisoriesAreNotMalware(t *testing.T) {
	// Left off knownMalwareAdvisories by the review of 2026-09-25: intent or payload is doubtful.
	doubtful := []string{"GHSA-jgg6-4rpr-wfh7", "GHSA-q5h6-49gg-2wfg", "GHSA-3hfp-gqgh-xc5g", "GHSA-98x5-vq43-vc5p",
		"GHSA-rfj2-4g26-7jw5", "GHSA-c6p9-24rc-jr5h", "GHSA-75w2-qv55-x7fv", "GHSA-457r-cqc8-9vj9",
		"GHSA-8jh9-wqpf-q52c", "GHSA-pg98-6v7f-2xfv", "GHSA-qq6h-5g6j-q3cm"}
	byID := map[string][]grype.Match{}
	for _, m := range realFixture(t, githubFixture) {
		byID[m.Vulnerability.ID] = append(byID[m.Vulnerability.ID], m)
	}
	present := 0
	for _, id := range doubtful {
		if len(byID[id]) == 0 {
			t.Logf("%s is not in the fixture", id)
			continue
		}
		present++
		for _, m := range byID[id] {
			isMalware, source := collectFacts(m, nil).malware()
			assert.False(t, isMalware, "%s in %s is flagged as malware (%s)", id, m.Artifact.Name, source)
		}
	}
	t.Logf("%d of %d doubtful advisories are in the fixture", present, len(doubtful))
	assert.GreaterOrEqual(t, present, 8)
}

// Ubuntu keys its finding by the CVE, and CVE-2018-3779 is also in knownMalwareAdvisories, as the
// alias of the active-support typosquat: the rails flaw in ruby-activesupport must stay a flaw.
func TestRealUbuntuCVEKeyedFindingIsNotMalware(t *testing.T) {
	require.True(t, knownMalwareAdvisories["CVE-2018-3779"], "the collision this test is about")
	found := 0
	for _, m := range realFixture(t, ubuntuFixture) {
		if m.Vulnerability.ID != "CVE-2018-3779" {
			continue
		}
		found++
		isMalware, _ := collectFacts(m, nil).malware()
		assert.False(t, isMalware, m.Artifact.Name)
		res := Evaluate(m, nil, thresholds, realAsOf)
		assert.NotContains(t, res.Reason, "вредонос", res.Reason)
		require.Empty(t, m.Vulnerability.KnownExploited, "not in KEV in the fixture, so nothing makes it Critical")
		assert.NotEqual(t, harbor.SevCritical, res.Severity, res.Reason)
		t.Logf("%s %s: %s", m.Vulnerability.ID, m.Artifact.Name, res.Reason)
	}
	assert.Equal(t, 1, found)
}

func TestRealKEVFindingsAreCritical(t *testing.T) {
	perFile := map[string]int{}
	for _, file := range realFixtures(t) {
		for _, m := range realFixture(t, file) {
			if len(m.Vulnerability.KnownExploited) == 0 {
				continue
			}
			perFile[file]++
			res := Evaluate(m, nil, thresholds, realAsOf)
			assert.Equal(t, harbor.SevCritical, res.Severity, "%s in %s: %s", m.Vulnerability.ID, file, res.Reason)
			assert.True(t, strings.HasPrefix(res.Reason, "Critical на 2026-09-25: есть в каталоге KEV"), res.Reason)
		}
	}
	t.Logf("KEV findings: %v", perFile)
	assert.GreaterOrEqual(t, perFile[githubFixture], 3)
	assert.GreaterOrEqual(t, perFile[githubByCVEFixture], 3)
}

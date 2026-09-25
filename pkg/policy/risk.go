package policy

import (
	"math"
	"strings"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

// stringSeverityScore is grype's severityToScore: the middle of each severity range.
var stringSeverityScore = map[string]float64{
	"negligible": 0.5,
	"low":        3.0,
	"medium":     5.0,
	"high":       7.5,
	"critical":   9.0,
}

// severityFactor reproduces severity() from grype v0.117.0 grype/vulnerability/metadata.go:
// the average of the string severity and the mean non-zero CVSS base score, both on a 0–1 scale.
// Without any non-zero CVSS score, the factor is the string severity alone.
func severityFactor(severity string, cvss []grype.Cvss) float64 {
	score, ok := stringSeverityScore[strings.ToLower(severity)]
	if !ok {
		score = 5.0
	}
	var sum float64
	var n int
	for _, c := range cvss {
		if c.Metrics.BaseScore != 0 {
			sum += c.Metrics.BaseScore
			n++
		}
	}
	if n == 0 {
		return score / 10
	}
	return (score/10 + sum/float64(n)/10) / 2
}

// riskEstimate is the risk the ladder compares with the thresholds.
type riskEstimate struct {
	value    float64    // 0–100
	reported float64    // the risk grype reported
	rescaled bool       // value uses the highest EPSS of the record instead of the first
	epss     grype.EPSS // the first EPSS entry, or the highest when rescaled; the zero value when the record has no EPSS
}

// estimateRisk returns grype's risk. When the record carries EPSS for several CVEs and the first
// one, which grype uses, is not the highest, it applies grype's formula to the highest EPSS:
// Amazon and Oracle advisories bundle many CVEs and grype would take whichever comes first.
// KEV records are left as grype reported them: grype's threat is 1 regardless of EPSS, so there
// is nothing to rescale.
func estimateRisk(v grype.Vulnerability) riskEstimate {
	est := riskEstimate{value: v.Risk, reported: v.Risk}
	if len(v.EPSS) == 0 {
		return est
	}
	est.epss = v.EPSS[0]
	// For KEV entries grype ignores EPSS (threat is 1), so there is nothing to rescale.
	if len(v.KnownExploited) > 0 {
		return est
	}
	highest := v.EPSS[0]
	for _, e := range v.EPSS[1:] {
		if e.Score > highest.Score {
			highest = e
		}
	}
	if highest.Score <= v.EPSS[0].Score {
		return est
	}
	est.value = math.Min(highest.Score*severityFactor(v.Severity, v.Cvss), 1) * 100
	est.rescaled = true
	est.epss = highest
	return est
}

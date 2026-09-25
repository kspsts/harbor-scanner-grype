package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

// reason is the explanation put in front of the vulnerability description in Harbor:
// "<level>: <main reason>; <fact>; <fact>." or, dated, "<level> на <YYYY-MM-DD>: <main reason>;
// <fact>; <fact>." Harbor shows it as one paragraph.
type reason struct {
	level harbor.Severity
	main  string
	facts []string
}

// text renders the explanation, dated when asOf is not the zero time. Harbor keeps a finding's
// first description; later scans change only its level and a few other fields, so the explanation
// can outlive the level it explains. The date lets a reader see when the assessment behind it was
// made.
func (r reason) text(asOf time.Time) string {
	s := r.level.String()
	if !asOf.IsZero() {
		s += " на " + asOf.Format("2006-01-02")
	}
	s += ": " + r.main
	for _, f := range r.facts {
		s += "; " + f
	}
	return s + "."
}

// String renders the explanation without a date, for callers with no clock of their own.
func (r reason) String() string {
	return r.text(time.Time{})
}

// formatPercent renders an EPSS probability (0–1) as a percentage with one decimal, without a
// trailing ".0": 0.92 → "92%", 0.524 → "52.4%". Below 0.1% it is "<0.1%", as in grype's table.
func formatPercent(p float64) string {
	v := p * 100
	if v > 0 && v < 0.1 {
		return "<0.1%"
	}
	return strings.TrimSuffix(strconv.FormatFloat(v, 'f', 1, 64), ".0") + "%"
}

// formatRisk renders a grype risk (0–100) as grype's table does: one decimal, "<0.1" below 0.1.
func formatRisk(r float64) string {
	if r > 0 && r < 0.1 {
		return "<0.1"
	}
	return strconv.FormatFloat(r, 'f', 1, 64)
}

// shownRisk is the risk as formatRisk shows it. The ladder compares this value with the
// thresholds, so the level always agrees with the text: 29.96 is shown as 30.0 and reaches the
// High threshold of 30, and a risk shown as "<0.1" counts as 0.
func shownRisk(r float64) float64 {
	if r < 0.1 {
		return 0
	}
	v, err := strconv.ParseFloat(strconv.FormatFloat(r, 'f', 1, 64), 64)
	if err != nil {
		return r
	}
	return v
}

// formatThreshold renders a threshold as set: 70 → "70", 12.5 → "12.5".
func formatThreshold(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// maxShownExploitIDs is how many Exploit-DB ids the explanation names; the rest become "и ещё N".
const maxShownExploitIDs = 3

// exploitFact names the exploits of a finding: Exploit-DB ids first, at most maxShownExploitIDs,
// else the PoC link.
func exploitFact(f facts) string {
	switch {
	case len(f.exploits) > 0:
		return "есть эксплойт в Exploit-DB (" + listIDs(f.exploits, maxShownExploitIDs) + ")"
	case f.poc != "":
		return "есть PoC (" + shortURL(f.poc) + ")"
	default:
		return "эксплойтов не найдено"
	}
}

func listIDs(ids []string, limit int) string {
	if len(ids) <= limit {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:limit], ", ") + fmt.Sprintf(" и ещё %d", len(ids)-limit)
}

// shortURL drops the scheme and "www." and caps the length at 80 characters: a longer link keeps
// its first 79 and ends with the one-character ellipsis "…", never "...", so the explanation has
// no run of dots. It cuts only on a rune boundary, so it never splits a multi-byte character.
func shortURL(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	u = strings.TrimPrefix(u, "www.")
	if runes := []rune(u); len(runes) > 80 {
		u = string(runes[:79]) + "…"
	}
	return u
}

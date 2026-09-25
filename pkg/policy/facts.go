package policy

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

// pocPattern marks links to public exploits or proof-of-concept code: the pattern from the design
// spec, section 4.2 (docs/superpowers/specs/2026-09-25-policy-mode-design.md).
var pocPattern = regexp.MustCompile(`(?i)exploit-db\.com|packetstormsecurity\.com/files|rapid7\.com/db/modules|metasploit|0day\.today|seebug\.org|github\.com/[^/]+/[^/]*(poc|exploit|cve-\d{4}-\d+)`)

const (
	// packetStormVendorAdvisories matches Packet Storm's copies of vendor and Secunia advisories,
	// under titles such as "Slackware Security Advisory - curl Updates" or "Kernel Live Patch
	// Security Notice LSN-0053-1": the file slug opens with the publisher's name right after
	// /files/<id>/, followed by "Security Advisory/Notice/Bulletin/Announcement". Researcher
	// advisories ("Qualys Security Advisory - …") are not listed: they carry exploitation details.
	packetStormVendorAdvisories = `packetstormsecurity\.com/files/\d+/((Red-Hat|Ubuntu|Kernel-Live-Patch|Debian|Gentoo-Linux|(open)?SUSE|Slackware|Mandriva-Linux|FreeBSD|VMware|Apple|Cisco|HP|Asterisk-Project|OpenSSL|Siemens|Secunia)-Security-(Advisory|Notice|Bulletin|Announcement)|USN-\d|Security-Notice-For-)`

	// packetStormIndexPages matches Packet Storm's author, date and tags listings.
	packetStormIndexPages = `packetstormsecurity\.com/files/(author|date|tags)/`

	// exploitDBNonExploitPages matches Exploit-DB pages that hold no exploit: its docs, papers, GHDB,
	// author and search pages (bare, or followed by /, ? or #), the bare exploits index, and the
	// home page (with or without a query or fragment).
	exploitDBNonExploitPages = `exploit-db\.com(/(docs|papers|ghdb|google-hacking-database|author|search)([/?#]|$)|/exploits/?([?#]|$)|/?([?#]|$))`
)

// notPoCPattern marks links that pocPattern matches but that hold no exploit: Packet Storm's copies
// of vendor advisories, its author/date/tags index pages, and Exploit-DB pages that are not a
// specific exploit.
var notPoCPattern = regexp.MustCompile(`(?i)` + packetStormVendorAdvisories + `|` + packetStormIndexPages + `|` + exploitDBNonExploitPages)

// isPoC reports whether a link points to a public exploit or proof-of-concept code.
func isPoC(u string) bool {
	return pocPattern.MatchString(u) && !notPoCPattern.MatchString(u)
}

// networkVector matches the base attack vector "network" in CVSS v2, v3 and v4 vectors,
// but not the environmental MAV:N.
var networkVector = regexp.MustCompile(`(^|/)AV:N(/|$)`)

// facts are what the rules look at, collected from one grype match.
type facts struct {
	vuln     grype.Vulnerability
	cves     []string
	exploits []string // Exploit-DB ids
	poc      string   // first link to a proof of concept
	network  bool     // one of attackVectors has AV:N
	vectors  bool     // attackVectors has at least one vector
}

func collectFacts(m grype.Match, lookup ExploitLookup) facts {
	f := facts{vuln: m.Vulnerability, cves: cveIDs(m), poc: firstPoC(m), network: networkReachable(m), vectors: hasVector(m)}
	if lookup != nil {
		f.exploits = exploitIDs(f.cves, lookup)
	}
	return f
}

func (f facts) hasExploit() bool {
	return len(f.exploits) > 0 || f.poc != ""
}

// malwarePrefixes are the openings of GitHub advisories about malicious packages. "Malicious code in"
// marks packages from OpenSSF malicious-packages that GitHub imported. "Embedded malware in" (lower
// case "malware", unlike "Embedded Malicious Code in") marks the 2021 npm hijacks of ua-parser-js,
// coa and rc.
var malwarePrefixes = []string{
	"Malware in ", "Malicious code in ", "Malicious Package in ", "Embedded Malicious Code in ", "Embedded malware in ",
}

// malware reports whether the finding is a malicious package rather than a flaw: GitHub publishes
// such advisories with one of the fixed openings in malwarePrefixes, or — for crates pulled from
// crates.io — with RustSec's "removed from crates.io ... malicious code" wording; for the rest,
// knownMalwareAdvisories lists, by the vulnerability id grype reports, the GitHub advisories whose
// titles follow neither, but only for GitHub advisory findings (Namespace "github:..."): grype keys
// a distro finding by the CVE id itself, and that id can collide with an unrelated map entry. CWE-506
// is embedded malicious code.
func (f facts) malware() (bool, string) {
	for _, p := range malwarePrefixes {
		if strings.HasPrefix(f.vuln.Description, p) {
			return true, "github"
		}
	}
	if strings.Contains(f.vuln.Description, "removed from crates.io") && strings.Contains(f.vuln.Description, "malicious code") {
		return true, "github"
	}
	if strings.HasPrefix(f.vuln.Namespace, "github:") && knownMalwareAdvisories[f.vuln.ID] {
		return true, "github"
	}
	for _, c := range f.vuln.CWEs {
		if c.CWE == "CWE-506" {
			return true, "cwe"
		}
	}
	return false, ""
}

// cveIDs lists the CVEs of a finding: its own id, related records, and the CVEs grype attached
// EPSS, KEV and CWE data for. Advisories such as ALAS or ELSA reach their CVEs this way.
func cveIDs(m grype.Match) []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	add(m.Vulnerability.ID)
	for _, r := range m.RelatedVulnerabilities {
		add(r.ID)
	}
	for _, e := range m.Vulnerability.EPSS {
		add(e.CVE)
	}
	for _, k := range m.Vulnerability.KnownExploited {
		add(k.CVE)
	}
	for _, c := range m.Vulnerability.CWEs {
		add(c.CVE)
	}
	return out
}

// exploitIDs merges the Exploit-DB ids of every CVE in cves into one sorted, de-duplicated list.
// It does not modify the slices lookup.Lookup returns.
func exploitIDs(cves []string, lookup ExploitLookup) []string {
	var out []string
	seen := map[string]bool{}
	for _, cve := range cves {
		for _, id := range lookup.Lookup(cve) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Slice(out, func(a, b int) bool {
		x, errX := strconv.Atoi(out[a])
		y, errY := strconv.Atoi(out[b])
		if errX != nil || errY != nil {
			return out[a] < out[b]
		}
		return x < y
	})
	return out
}

// firstPoC returns the first link to a proof of concept (isPoC), checking the vulnerability's own
// URLs before those of related records.
func firstPoC(m grype.Match) string {
	for _, u := range m.Vulnerability.URLs {
		if isPoC(u) {
			return u
		}
	}
	for _, r := range m.RelatedVulnerabilities {
		for _, u := range r.URLs {
			if isPoC(u) {
				return u
			}
		}
	}
	return ""
}

// networkReachable reports whether the attack vector is the network: AV:N in at least one of
// attackVectors.
func networkReachable(m grype.Match) bool {
	for _, c := range attackVectors(m) {
		if networkVector.MatchString(c.Vector) {
			return true
		}
	}
	return false
}

// hasVector reports whether attackVectors has at least one vector, i.e. whether the attack vector
// is known at all.
func hasVector(m grype.Match) bool {
	for _, c := range attackVectors(m) {
		if c.Vector != "" {
			return true
		}
	}
	return false
}

// attackVectors returns the CVSS entries rule 5 judges the attack vector by: those of the finding's
// own record when it has at least one non-empty vector, else those of its related records (NVD), as
// for ALAS and ELSA advisories and many Debian records, which carry none. The own vectors mean one
// of two things: RHEL, SUSE, GitHub and Bitnami score the flaw themselves, while for Fedora, Alpine,
// Echo, Debian and Alma they are usually a copy of NVD's primary score (nvd@nist.gov), so there the
// rule prefers NVD's primary score over the secondary ones of CNAs and CISA ADP. For CVE-2025-69720
// in ncurses, Debian's AV:L is NVD's primary score; the AV:N that no longer counts is CISA ADP's.
func attackVectors(m grype.Match) []grype.Cvss {
	for _, c := range m.Vulnerability.Cvss {
		if c.Vector != "" {
			return m.Vulnerability.Cvss
		}
	}
	var related []grype.Cvss
	for _, r := range m.RelatedVulnerabilities {
		related = append(related, r.Cvss...)
	}
	return related
}

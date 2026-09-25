package policy

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

type fakeExploits map[string][]string

func (f fakeExploits) Lookup(cve string) []string { return f[cve] }

func TestCVEIDsCollectsEveryCVEOnce(t *testing.T) {
	m := grype.Match{
		Vulnerability: grype.Vulnerability{
			ID:             "ELSA-2099-0001",
			EPSS:           []grype.EPSS{{CVE: "CVE-2099-0002"}, {CVE: "CVE-2099-0001"}},
			KnownExploited: []grype.KnownExploited{{CVE: "CVE-2099-0003"}},
			CWEs:           []grype.CWE{{CVE: "cve-2099-0001", CWE: "CWE-787"}},
		},
		RelatedVulnerabilities: []grype.RelatedVulnerability{{ID: "CVE-2099-0001"}, {ID: "GHSA-xxxx-yyyy-zzzz"}},
	}
	assert.Equal(t, []string{"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"}, cveIDs(m))
}

func TestCVEIDsTrimsAndUppercases(t *testing.T) {
	m := grype.Match{Vulnerability: grype.Vulnerability{EPSS: []grype.EPSS{{CVE: " cve-2099-0005 "}}}}
	assert.Equal(t, []string{"CVE-2099-0005"}, cveIDs(m))
}

func TestExploitIDsAcrossCVEsAreSortedAndUnique(t *testing.T) {
	lookup := fakeExploits{"CVE-2021-44228": {"50592", "50590"}, "CVE-2021-45046": {"50592", "51183"}}
	assert.Equal(t, []string{"50590", "50592", "51183"}, exploitIDs([]string{"CVE-2021-44228", "CVE-2021-45046"}, lookup))
}

func TestExploitIDsSortsNumericallyNotLexically(t *testing.T) {
	lookup := fakeExploits{"CVE-2099-0001": {"10000"}, "CVE-2099-0002": {"9999"}}
	assert.Equal(t, []string{"9999", "10000"}, exploitIDs([]string{"CVE-2099-0001", "CVE-2099-0002"}, lookup))
}

func TestFirstPoCFindsExploitLinksOnly(t *testing.T) {
	m := grype.Match{
		Vulnerability: grype.Vulnerability{URLs: []string{
			"https://github.com/advisories/GHSA-v98v-ff95-f3cp",
			"https://github.com/n8n-io/n8n/security/advisories/GHSA-v98v-ff95-f3cp",
		}},
		RelatedVulnerabilities: []grype.RelatedVulnerability{{URLs: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2025-15467",
			"https://github.com/guiimoraes/CVE-2025-15467",
		}}},
	}
	assert.Equal(t, "https://github.com/guiimoraes/CVE-2025-15467", firstPoC(m))

	commit := grype.Match{Vulnerability: grype.Vulnerability{URLs: []string{"https://github.com/torvalds/linux/commit/abc"}}}
	assert.Equal(t, "", firstPoC(commit))

	edb := grype.Match{Vulnerability: grype.Vulnerability{URLs: []string{"https://www.exploit-db.com/exploits/52134"}}}
	assert.Equal(t, "https://www.exploit-db.com/exploits/52134", firstPoC(edb))
}

func TestFirstPoCPrefersVulnerabilityURLs(t *testing.T) {
	m := grype.Match{
		Vulnerability:          grype.Vulnerability{URLs: []string{"https://www.exploit-db.com/exploits/1111"}},
		RelatedVulnerabilities: []grype.RelatedVulnerability{{URLs: []string{"https://www.exploit-db.com/exploits/2222"}}},
	}
	assert.Equal(t, "https://www.exploit-db.com/exploits/1111", firstPoC(m))
}

func TestNetworkReachable(t *testing.T) {
	cvssOf := func(vectors ...string) []grype.Cvss {
		var c []grype.Cvss
		for _, v := range vectors {
			c = append(c, grype.Cvss{Vector: v})
		}
		return c
	}
	withVectors := func(vectors ...string) grype.Match {
		return grype.Match{Vulnerability: grype.Vulnerability{Cvss: cvssOf(vectors...)}}
	}
	assert.True(t, networkReachable(withVectors("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")))
	assert.True(t, networkReachable(withVectors("AV:N/AC:L/Au:N/C:P/I:P/A:P")), "CVSS v2")
	assert.False(t, networkReachable(withVectors("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")))
	assert.False(t, networkReachable(withVectors("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:N")),
		"environmental MAV:N is not the base vector")

	related := grype.Match{RelatedVulnerabilities: []grype.RelatedVulnerability{{
		Cvss: []grype.Cvss{{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}}}
	assert.True(t, networkReachable(related), "without own vectors, as for ALAS and ELSA, the vectors of related records count")

	// With at least one vector of its own, the finding's record alone decides.
	const (
		network = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		local   = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
	)
	withRelated := func(own []grype.Cvss, relatedVectors ...string) grype.Match {
		return grype.Match{
			Vulnerability:          grype.Vulnerability{Cvss: own},
			RelatedVulnerabilities: []grype.RelatedVulnerability{{Cvss: cvssOf(relatedVectors...)}},
		}
	}
	ncurses := withRelated(cvssOf(local), local, network, local) // CVE-2025-69720: Debian AV:L; NVD two AV:L, one AV:N
	assert.False(t, networkReachable(ncurses), "an AV:N of a related record does not override the own AV:L")
	assert.True(t, hasVector(ncurses), "the attack vector is known: local")
	assert.True(t, networkReachable(withRelated(cvssOf(network), local)), "the own AV:N counts")

	scoreOnly := []grype.Cvss{{Metrics: grype.Metrics{BaseScore: 7.5}}}
	assert.True(t, networkReachable(withRelated(scoreOnly, network)), "an own score without a vector leaves it to the related records")
	assert.False(t, hasVector(grype.Match{Vulnerability: grype.Vulnerability{Cvss: scoreOnly}}), "no vector anywhere: unknown")
}

func TestMalware(t *testing.T) {
	github := facts{vuln: grype.Vulnerability{Description: "Malware in monorepo-symlink-test"}}
	ok, source := github.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	openssf := facts{vuln: grype.Vulnerability{Description: "Malicious code in 0x000testqwe (PyPI)"}}
	ok, source = openssf.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	oldNpm := facts{vuln: grype.Vulnerability{Description: "Malicious Package in flatmap-stream"}}
	ok, source = oldNpm.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	embedded := facts{vuln: grype.Vulnerability{Description: "Embedded Malicious Code in node-ipc"}}
	ok, source = embedded.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	npmHijack := facts{vuln: grype.Vulnerability{Description: "Embedded malware in ua-parser-js"}}
	ok, source = npmHijack.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	xz := facts{vuln: grype.Vulnerability{CWEs: []grype.CWE{{CVE: "CVE-2024-3094", CWE: "CWE-506"}}}}
	ok, source = xz.malware()
	assert.True(t, ok)
	assert.Equal(t, "cwe", source)

	injection := facts{vuln: grype.Vulnerability{Description: "This issue may allow an attacker to inject malicious code into the command"}}
	ok, _ = injection.malware()
	assert.False(t, ok, "wording about malicious input is not malware")

	realFlaw := facts{vuln: grype.Vulnerability{Description: "Malicious PDF can inject JavaScript into PDF Viewer"}}
	ok, _ = realFlaw.malware()
	assert.False(t, ok, "a real flaw whose title starts with Malicious is not a malware advisory")

	notAPrefix := facts{vuln: grype.Vulnerability{Description: "Detects Malware in uploaded files"}}
	ok, _ = notAPrefix.malware()
	assert.False(t, ok, "the wording must open the description, not just appear in it")
}

// TestMalwareKnownAdvisories covers advisories whose titles match none of malwarePrefixes: they are
// only caught through knownMalwareAdvisories, looked up by the finding's own vulnerability id
// (f.vuln.ID), and only for GitHub advisory findings (Namespace "github:...").
func TestMalwareKnownAdvisories(t *testing.T) {
	restClient := facts{vuln: grype.Vulnerability{
		ID: "GHSA-333g-rpr4-7hxq", Namespace: "github:language:ruby", Description: "rest-client Gem Contains Malicious Code",
	}}
	ok, source := restClient.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	// With SCANNER_GRYPE_BY_CVE=true grype reports the CVE id as the finding's own vulnerability id
	// instead of the GHSA id, but keeps the github: namespace; knownMalwareAdvisories carries that
	// CVE alias too, so the same f.vuln.ID lookup still matches.
	byCVE := grype.Match{Vulnerability: grype.Vulnerability{
		ID: "CVE-2019-15224", Namespace: "github:language:ruby", Description: "rest-client Gem Contains Malicious Code",
	}}
	f := collectFacts(byCVE, nil)
	ok, source = f.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	// Pin the namespace guard: the very same id and description, without the github: namespace,
	// must not be flagged.
	noNamespace := grype.Match{Vulnerability: grype.Vulnerability{
		ID: "CVE-2019-15224", Description: "rest-client Gem Contains Malicious Code",
	}}
	f = collectFacts(noNamespace, nil)
	ok, _ = f.malware()
	assert.False(t, ok, "the map is only consulted for github: namespace findings")

	notListed := facts{vuln: grype.Vulnerability{
		ID: "GHSA-qqqq-qqqq-qqqq", Namespace: "github:language:ruby", Description: "An ordinary vulnerability in some package",
	}}
	ok, _ = notListed.malware()
	assert.False(t, ok, "a GHSA id absent from knownMalwareAdvisories is not malware")

	// The real case the reviewer reproduced with grype: Ubuntu's ruby-activesupport finding on
	// 18.10 is reported under the CVE id alone, in the ubuntu: namespace, and that same CVE
	// (GHSA-2j55-pcw5-x4h2's alias) is a map key for an unrelated GitHub advisory.
	ubuntu := facts{vuln: grype.Vulnerability{
		ID:          "CVE-2018-3779",
		Namespace:   "ubuntu:distro:ubuntu:18.10",
		Description: "An ordinary vulnerability in ruby-activesupport",
	}}
	ok, _ = ubuntu.malware()
	assert.False(t, ok, "a distro finding is keyed by the CVE id itself and must not be flagged even though the same CVE is a map key")
}

func TestMalwareRustSecWording(t *testing.T) {
	removedFor := facts{vuln: grype.Vulnerability{Description: "`sha-rust` was removed from crates.io for malicious code"}}
	ok, source := removedFor.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	removedDueTo := facts{vuln: grype.Vulnerability{Description: "`time-sync` was removed from crates.io due to malicious code"}}
	ok, source = removedDueTo.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	authorRequest := facts{vuln: grype.Vulnerability{Description: "`foo` was removed from crates.io at the author's request"}}
	ok, _ = authorRequest.malware()
	assert.False(t, ok, "removal for an ordinary reason is not malware")
}

func TestKnownMalwareAdvisoriesKeysAreWellFormed(t *testing.T) {
	ghsaID := regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	cveID := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	for k := range knownMalwareAdvisories {
		assert.True(t, ghsaID.MatchString(k) || cveID.MatchString(k), "malformed key %q", k)
	}
}

func TestKnownMalwareAdvisoriesCount(t *testing.T) {
	assert.Equal(t, 77, len(knownMalwareAdvisories), "62 GHSA ids of the tail plus 15 CVE aliases")
}

package policy

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

var thresholds = Thresholds{Critical: 70, High: 30, Medium: 10}

func TestEvaluate(t *testing.T) {
	lookup := fakeExploits{
		"CVE-2021-44228": {"50590", "50592", "51183"},
		"CVE-2025-24813": {"52134"},
		"CVE-2099-0001":  {"40001"},
		"CVE-2099-0005":  {"40005"},
		"CVE-2099-0006":  {"40006"},
		"CVE-2099-0041":  {"40041"},
	}
	tests := []struct {
		name     string
		match    grype.Match
		severity harbor.Severity
		reason   string
	}{
		{
			name: "rule 1: KEV, ransomware, Exploit-DB",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-jfh8-c2jp-5v3q", Severity: "Critical", Risk: 100,
				KnownExploited: []grype.KnownExploited{{CVE: "CVE-2021-44228", DateAdded: "2021-12-10", KnownRansomwareCampaignUse: "Known"}},
				EPSS:           []grype.EPSS{{CVE: "CVE-2021-44228", Score: 0.99999}},
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: есть в каталоге KEV с 2021-12-10, используется вымогателями; есть эксплойт в Exploit-DB (50590, 50592, 51183); риск grype 100.0.",
		},
		{
			name: "rule 1: KEV without known ransomware use",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-83qj-6fr2-vhqg", Severity: "Critical", Risk: 98.7,
				KnownExploited: []grype.KnownExploited{{CVE: "CVE-2025-24813", DateAdded: "2025-04-01", KnownRansomwareCampaignUse: "Unknown"}},
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: есть в каталоге KEV с 2025-04-01; есть эксплойт в Exploit-DB (52134); риск grype 98.7.",
		},
		{
			name: "rule 1: several KEV entries, the earliest date trimmed to the day, lower-case known",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "ALAS2-2099-0010", Severity: "Critical", Risk: 94.5,
				KnownExploited: []grype.KnownExploited{
					{CVE: "CVE-2099-0011", DateAdded: "2022-03-01", KnownRansomwareCampaignUse: "Unknown"},
					{CVE: "CVE-2099-0010", DateAdded: "2021-12-10T00:00:00Z", KnownRansomwareCampaignUse: "Unknown"},
					{CVE: "CVE-2099-0012", DateAdded: "2023-01-15", KnownRansomwareCampaignUse: "known"},
				},
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: есть в каталоге KEV с 2021-12-10, используется вымогателями; риск grype 94.5.",
		},
		{
			name: "rule 1: KEV without a date and without exploits",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0020", Severity: "High", Risk: 78.75,
				KnownExploited: []grype.KnownExploited{{CVE: "CVE-2099-0020"}},
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: есть в каталоге KEV; риск grype 78.8.",
		},
		{
			name: "rule 1 with rule 2: a KEV package that GitHub marks as malware",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-9999-9999-9998", Severity: "Critical", Risk: 94.5, Description: "Malware in some-hijacked-package",
				KnownExploited: []grype.KnownExploited{{CVE: "CVE-2099-0040", DateAdded: "2026-05-12"}},
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: есть в каталоге KEV с 2026-05-12; пакет помечен как вредоносный (бюллетень GitHub о вредоносном пакете), проверьте, откуда он в образе; риск grype 94.5.",
		},
		{
			name: "rule 1 with rule 2: embedded malicious code in KEV comes before the exploit",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0041", Severity: "Critical", Risk: 94.5,
				KnownExploited: []grype.KnownExploited{{CVE: "CVE-2099-0041", DateAdded: "2025-06-02"}},
				CWEs:           []grype.CWE{{CVE: "CVE-2099-0041", CWE: "CWE-506"}},
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: есть в каталоге KEV с 2025-06-02; встроенный вредоносный код (CWE-506); есть эксплойт в Exploit-DB (40041); риск grype 94.5.",
		},
		{
			name: "rule 2: GitHub malware advisory",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-2jcg-qqmg-46q6", Severity: "Critical", Description: "Malware in monorepo-symlink-test",
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: пакет помечен как вредоносный (бюллетень GitHub о вредоносном пакете), проверьте, откуда он в образе.",
		},
		{
			name: "rule 2: OpenSSF malicious package imported by GitHub",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-9999-9999-9999", Severity: "Critical", Description: "Malicious code in 0x000testqwe (PyPI)",
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: пакет помечен как вредоносный (бюллетень GitHub о вредоносном пакете), проверьте, откуда он в образе.",
		},
		{
			name: "rule 2: embedded malicious code",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2024-3094", Severity: "Critical", Risk: 76.4,
				EPSS: []grype.EPSS{{CVE: "CVE-2024-3094", Score: 0.81}},
				CWEs: []grype.CWE{{CVE: "CVE-2024-3094", CWE: "CWE-506"}},
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: встроенный вредоносный код (CWE-506).",
		},
		{
			name: "rule 3: risk from 70 is Critical",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-v4pr-fm98-w9pg", Severity: "Critical", Risk: 74.5,
				EPSS: []grype.EPSS{{CVE: "CVE-2026-21858", Score: 0.784}},
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: риск grype 74.5, порог Critical от 70 (EPSS 78.4%, критичность grype Critical); эксплойтов не найдено; в KEV нет.",
		},
		{
			name: "rule 3: risk from 30 is High",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2023-45288", Severity: "High", Risk: 69.0,
				EPSS: []grype.EPSS{{CVE: "CVE-2023-45288", Score: 0.92}},
			}},
			severity: harbor.SevHigh,
			reason:   "High: риск grype 69.0, порог High от 30 (EPSS 92%, критичность grype High); эксплойтов не найдено; в KEV нет.",
		},
		{
			name: "rule 3: the risk is compared as shown, 29.96 is 30.0",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0004", Severity: "Medium", Risk: 29.96,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0004", Score: 0.5992}},
			}},
			severity: harbor.SevHigh,
			reason:   "High: риск grype 30.0, порог High от 30 (EPSS 59.9%, критичность grype Medium); эксплойтов не найдено; в KEV нет.",
		},
		{
			name: "rule 3 with a PoC that does not change a High level",
			match: grype.Match{
				Vulnerability: grype.Vulnerability{
					ID: "CVE-2025-15467", Severity: "Critical", Risk: 49.3,
					EPSS: []grype.EPSS{{CVE: "CVE-2025-15467", Score: 0.524}},
				},
				RelatedVulnerabilities: []grype.RelatedVulnerability{{ID: "CVE-2025-15467", URLs: []string{"https://github.com/guiimoraes/CVE-2025-15467"}}},
			},
			severity: harbor.SevHigh,
			reason:   "High: риск grype 49.3, порог High от 30 (EPSS 52.4%, критичность grype Critical); есть PoC (github.com/guiimoraes/CVE-2025-15467); в KEV нет.",
		},
		{
			name: "rule 3: risk from 10 is Medium",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-62r4-hw23-cc8v", Severity: "Critical", Risk: 12.4,
				EPSS: []grype.EPSS{{CVE: "CVE-2025-68668", Score: 0.132}},
			}},
			severity: harbor.SevMedium,
			reason:   "Medium: риск grype 12.4, порог Medium от 10 (EPSS 13.2%, критичность grype Critical); эксплойтов не найдено; в KEV нет.",
		},
		{
			name: "rule 3: risk below 10 is Low",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-v364-rw7m-3263", Severity: "Critical", Risk: 5.1,
				EPSS: []grype.EPSS{{CVE: "CVE-2026-21877", Score: 0.054}},
			}},
			severity: harbor.SevLow,
			reason:   "Low: риск grype 5.1, ниже порога Medium (EPSS 5.4%, критичность grype Critical); эксплойтов не найдено; в KEV нет.",
		},
		{
			name: "rule 3 for an advisory with several CVEs uses the highest EPSS",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "ALAS2-2099-0001", Severity: "High", Risk: 1.5,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-1000", Score: 0.02}, {CVE: "CVE-2099-1001", Score: 0.60}},
			}},
			severity: harbor.SevHigh,
			reason:   "High: риск 45.0 по максимальному EPSS бюллетеня (CVE-2099-1001, 60%), grype показывает 1.5; порог High от 30 (критичность grype High); эксплойтов не найдено; в KEV нет.",
		},
		{
			name:     "rule 4: no EPSS, Critical is capped at High",
			match:    grype.Match{Vulnerability: grype.Vulnerability{ID: "GHSA-r277-6w6q-xmqw", Severity: "Critical"}},
			severity: harbor.SevHigh,
			reason:   "High: EPSS нет, взята критичность grype Critical, понижена до High: без EPSS и KEV Critical не ставим; эксплойтов не найдено; в KEV нет.",
		},
		{
			name:     "rule 4: no EPSS, High stays High",
			match:    grype.Match{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0102", Severity: "High"}},
			severity: harbor.SevHigh,
			reason:   "High: EPSS нет, взята критичность grype High; эксплойтов не найдено; в KEV нет.",
		},
		{
			name:     "rule 4: no EPSS, Medium stays Medium",
			match:    grype.Match{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0103", Severity: "Medium"}},
			severity: harbor.SevMedium,
			reason:   "Medium: EPSS нет, взята критичность grype Medium; эксплойтов не найдено; в KEV нет.",
		},
		{
			name: "rule 4 with a PoC that does not change a High level",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0105", Severity: "High",
				URLs: []string{"https://packetstormsecurity.com/files/170000/Example-Exploit.html"},
			}},
			severity: harbor.SevHigh,
			reason:   "High: EPSS нет, взята критичность grype High; есть PoC (packetstormsecurity.com/files/170000/Example-Exploit.html); в KEV нет.",
		},
		{
			name:     "rule 4: no EPSS, Negligible becomes Low",
			match:    grype.Match{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0100", Severity: "Negligible"}},
			severity: harbor.SevLow,
			reason:   "Low: EPSS нет, взята критичность grype Negligible, в Harbor это Low; эксплойтов не найдено; в KEV нет.",
		},
		{
			name:     "rule 4: no EPSS and no severity",
			match:    grype.Match{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0101"}},
			severity: harbor.SevUnknown,
			reason:   "Unknown: EPSS нет, критичность grype неизвестна; эксплойтов не найдено; в KEV нет.",
		},
		{
			name: "rule 5: a network exploit for a serious flaw raises to High",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0001", Severity: "High", Risk: 1.4,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0001", Score: 0.0185}},
				Cvss: []grype.Cvss{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Metrics: grype.Metrics{BaseScore: 8.8}}},
			}},
			severity: harbor.SevHigh,
			reason:   "High: есть эксплойт в Exploit-DB (40001), уязвимость доступна по сети, критичность grype High; без эксплойта было бы Low (риск grype 1.4); в KEV нет.",
		},
		{
			name: "rule 5: a network exploit for a serious flaw raises Medium to High",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0005", Severity: "High", Risk: 12.4,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0005", Score: 0.1434}},
				Cvss: []grype.Cvss{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Metrics: grype.Metrics{BaseScore: 9.8}}},
			}},
			severity: harbor.SevHigh,
			reason:   "High: есть эксплойт в Exploit-DB (40005), уязвимость доступна по сети, критичность grype High; без эксплойта было бы Medium (риск grype 12.4); в KEV нет.",
		},
		{
			name: "rule 5: a local exploit raises to Medium",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0002", Severity: "High", Risk: 0.8,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0002", Score: 0.01}},
				Cvss: []grype.Cvss{{Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", Metrics: grype.Metrics{BaseScore: 7.8}}},
				URLs: []string{"https://www.exploit-db.com/exploits/40002"},
			}},
			severity: harbor.SevMedium,
			reason:   "Medium: есть PoC (exploit-db.com/exploits/40002), но вектор атаки не сетевой; без эксплойта было бы Low (риск grype 0.8); в KEV нет.",
		},
		{
			name: "rule 5: an exploit for a Medium flaw raises to Medium only",
			match: grype.Match{
				Vulnerability: grype.Vulnerability{
					ID: "CVE-2025-11187", Severity: "Medium", Risk: 2.9,
					EPSS: []grype.EPSS{{CVE: "CVE-2025-11187", Score: 0.051}},
					Cvss: []grype.Cvss{
						{Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Metrics: grype.Metrics{BaseScore: 6.1}},
						{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", Metrics: grype.Metrics{BaseScore: 5.9}},
					},
				},
				RelatedVulnerabilities: []grype.RelatedVulnerability{{ID: "CVE-2025-11187", URLs: []string{"https://github.com/metadust/CVE-2025-11187"}}},
			},
			severity: harbor.SevMedium,
			reason:   "Medium: есть PoC (github.com/metadust/CVE-2025-11187), но критичность grype Medium; без эксплойта было бы Low (риск grype 2.9); в KEV нет.",
		},
		{
			name: "rule 5 after rule 4, without any CVSS vector",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-aaaa-bbbb-cccc", Severity: "Low",
				URLs: []string{"https://github.com/someone/project-poc"},
			}},
			severity: harbor.SevMedium,
			reason:   "Medium: есть PoC (github.com/someone/project-poc), но вектор атаки неизвестен; без эксплойта было бы Low (EPSS нет); в KEV нет.",
		},
		{
			name: "rule 5 after rule 4 with an unknown severity",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID:   "CVE-2099-0104",
				URLs: []string{"https://github.com/someone/CVE-2099-0104"},
			}},
			severity: harbor.SevMedium,
			reason:   "Medium: есть PoC (github.com/someone/CVE-2099-0104), но вектор атаки неизвестен; без эксплойта было бы Unknown (EPSS нет); в KEV нет.",
		},
		{
			name: "rule 5: an exploit does not change a Medium level",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0003", Severity: "Medium", Risk: 12.4,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0003", Score: 0.132}},
				URLs: []string{"https://github.com/someone/CVE-2099-0003"},
			}},
			severity: harbor.SevMedium,
			reason:   "Medium: риск grype 12.4, порог Medium от 10 (EPSS 13.2%, критичность grype Medium); есть PoC (github.com/someone/CVE-2099-0003); в KEV нет.",
		},
		{
			name: "rule 5 after a rescaled ladder keeps grype's number",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "ALAS2-2099-0003", Severity: "Critical", Risk: 0.094,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-2000", Score: 0.001}, {CVE: "CVE-2099-0006", Score: 0.05}},
				Cvss: []grype.Cvss{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Metrics: grype.Metrics{BaseScore: 9.8}}},
			}},
			severity: harbor.SevHigh,
			reason:   "High: есть эксплойт в Exploit-DB (40006), уязвимость доступна по сети, критичность grype Critical; без эксплойта было бы Low (риск 4.7 по максимальному EPSS, grype показывает <0.1); в KEV нет.",
		},
		{
			name: "rule 5: a Packet Storm vendor advisory copy is not a PoC",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0400", Severity: "High", Risk: 1.2,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0400", Score: 0.016}},
				Cvss: []grype.Cvss{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Metrics: grype.Metrics{BaseScore: 9.8}}},
				URLs: []string{"https://packetstormsecurity.com/files/153799/Kernel-Live-Patch-Security-Notice-LSN-0053-1.html"},
			}},
			severity: harbor.SevLow,
			reason:   "Low: риск grype 1.2, ниже порога Medium (EPSS 1.6%, критичность grype High); эксплойтов не найдено; в KEV нет.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Evaluate(tt.match, lookup, thresholds, time.Time{})
			assert.Equal(t, tt.severity, res.Severity)
			assert.Equal(t, tt.reason, res.Reason)
		})
	}
}

// A PoC link is added to Links only when there are no Exploit-DB ids (see resultLinks): with
// Exploit-DB ids present, a PoC URL among the vulnerability's own URLs must not also show up.
func TestEvaluateLinksExploitDBPages(t *testing.T) {
	lookup := fakeExploits{"CVE-2099-0200": {"1", "2", "3", "4", "5", "6", "7"}}
	m := grype.Match{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0200", Severity: "High", Risk: 40,
		EPSS: []grype.EPSS{{CVE: "CVE-2099-0200", Score: 0.5}},
		URLs: []string{"https://github.com/someone/CVE-2099-0200"}}}

	res := Evaluate(m, lookup, thresholds, time.Time{})

	assert.Equal(t, []string{
		"https://www.exploit-db.com/exploits/1",
		"https://www.exploit-db.com/exploits/2",
		"https://www.exploit-db.com/exploits/3",
		"https://www.exploit-db.com/exploits/4",
		"https://www.exploit-db.com/exploits/5",
	}, res.Links)
	assert.Contains(t, res.Reason, "есть эксплойт в Exploit-DB (1, 2, 3 и ещё 4)")
}

// When there is no Exploit-DB id, exploitFact instead names a PoC link (a related record's URL,
// here — see facts.firstPoC); that link must be in Links too, or the mention in Reason has nothing
// to click through to in Harbor.
func TestEvaluateLinksPoC(t *testing.T) {
	m := grype.Match{
		Vulnerability: grype.Vulnerability{
			ID: "CVE-2025-15467", Severity: "Critical", Risk: 49.3,
			EPSS: []grype.EPSS{{CVE: "CVE-2025-15467", Score: 0.524}},
		},
		RelatedVulnerabilities: []grype.RelatedVulnerability{{ID: "CVE-2025-15467", URLs: []string{"https://github.com/guiimoraes/CVE-2025-15467"}}},
	}

	res := Evaluate(m, nil, thresholds, time.Time{})

	assert.Contains(t, res.Reason, "есть PoC (")
	assert.Equal(t, []string{"https://github.com/guiimoraes/CVE-2025-15467"}, res.Links)
}

// The date comes from asOf's own zone, not from converting it to UTC or any other zone: 01:30 on
// 2026-09-26 in Moscow's fixed UTC+3 zone is 22:30 on 2026-09-25 in UTC — a different date — and
// it is the MSK date, 2026-09-26, that must appear.
func TestEvaluateDatesTheExplanation(t *testing.T) {
	asOf := time.Date(2026, 9, 26, 1, 30, 0, 0, time.FixedZone("MSK", 3*3600))
	m := grype.Match{Vulnerability: grype.Vulnerability{
		ID: "CVE-2023-45288", Severity: "High", Risk: 69.0,
		EPSS: []grype.EPSS{{CVE: "CVE-2023-45288", Score: 0.92}},
	}}

	res := Evaluate(m, nil, thresholds, asOf)

	assert.True(t, strings.HasPrefix(res.Reason, "High на 2026-09-26: "), res.Reason)
}

// The ladder compares the risk as the text shows it, with one decimal.
func TestLadderThresholds(t *testing.T) {
	cases := map[float64]harbor.Severity{
		69.94: harbor.SevHigh, 69.96: harbor.SevCritical, 70: harbor.SevCritical,
		29.94: harbor.SevMedium, 29.96: harbor.SevHigh, 30: harbor.SevHigh,
		9.94: harbor.SevLow, 9.96: harbor.SevMedium, 10: harbor.SevMedium,
		0: harbor.SevLow,
	}
	for risk, want := range cases {
		m := grype.Match{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0300", Severity: "Medium", Risk: risk,
			EPSS: []grype.EPSS{{CVE: "CVE-2099-0300", Score: 0.1}}}}
		assert.Equal(t, want, Evaluate(m, nil, thresholds, time.Time{}).Severity, "risk %v", risk)
	}
}

// Harbor shows the explanation in front of the description; the spec caps it at 300 characters.
// Checked on two of the longest texts, both with a PoC link cut to 80 characters and a dated
// explanation (the date adds 14 runes, " на YYYY-MM-DD"): a rescaled ladder with odd thresholds,
// and a KEV record used by ransomware that is also malware.
func TestReasonStaysWithin300Characters(t *testing.T) {
	longPoC := "https://github.com/someone/" + strings.Repeat("a", 90) + "-poc"
	asOf := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	odd := Thresholds{Critical: 33.333333333333336, High: 22.22222222222222, Medium: 11.11111111111111}
	ladder := Evaluate(grype.Match{Vulnerability: grype.Vulnerability{
		ID: "ALAS2-2099-0002", Severity: "Critical", Risk: 0.1,
		EPSS: []grype.EPSS{{CVE: "CVE-2099-1000000", Score: 0.001}, {CVE: "CVE-2099-1000001", Score: 0.99999}},
		URLs: []string{longPoC},
	}}, nil, odd, asOf)
	assert.Equal(t, harbor.SevCritical, ladder.Severity)
	assert.Contains(t, ladder.Reason, "по максимальному EPSS бюллетеня")
	assert.Contains(t, ladder.Reason, "есть PoC (")
	assert.LessOrEqual(t, utf8.RuneCountInString(ladder.Reason), 300, ladder.Reason)

	kevMalware := Evaluate(grype.Match{Vulnerability: grype.Vulnerability{
		ID: "GHSA-9999-9999-9996", Severity: "Critical", Risk: 100, Description: "Malware in some-hijacked-package",
		KnownExploited: []grype.KnownExploited{{CVE: "CVE-2099-1000002", DateAdded: "2099-12-31", KnownRansomwareCampaignUse: "Known"}},
		URLs:           []string{longPoC},
	}}, nil, thresholds, asOf)
	assert.Equal(t, harbor.SevCritical, kevMalware.Severity)
	assert.Contains(t, kevMalware.Reason, "используется вымогателями; пакет помечен как вредоносный")
	assert.Contains(t, kevMalware.Reason, "есть PoC (")
	assert.LessOrEqual(t, utf8.RuneCountInString(kevMalware.Reason), 300, kevMalware.Reason)
}

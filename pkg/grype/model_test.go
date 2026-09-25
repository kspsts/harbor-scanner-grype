package grype

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A trimmed match in the layout of `grype -o json` v0.117.0: relatedVulnerabilities sits next to
// vulnerability; knownExploited, epss, cwes and risk sit inside it.
const matchJSON = `{
  "vulnerability": {
    "id": "GHSA-83qj-6fr2-vhqg",
    "severity": "Critical",
    "description": "Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT",
    "urls": ["https://github.com/advisories/GHSA-83qj-6fr2-vhqg"],
    "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "metrics": {"baseScore": 9.8}}],
    "knownExploited": [{"cve": "CVE-2025-24813", "dateAdded": "2025-04-01", "knownRansomwareCampaignUse": "Unknown"}],
    "epss": [{"cve": "CVE-2025-24813", "epss": 0.99927, "percentile": 0.99999, "date": "2026-09-21"}],
    "cwes": [{"cve": "CVE-2025-24813", "cwe": "CWE-502"}],
    "fix": {"versions": ["10.1.35"], "state": "fixed"},
    "risk": 98.7
  },
  "relatedVulnerabilities": [{
    "id": "CVE-2025-24813",
    "urls": ["https://github.com/absholi7ly/POC-CVE-2025-24813/blob/main/README.md"],
    "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "metrics": {"baseScore": 9.8}}]
  }],
  "artifact": {"name": "tomcat-embed-core", "version": "10.1.30", "type": "java-archive"}
}`

func TestMatchCarriesPolicyInputs(t *testing.T) {
	var m Match
	require.NoError(t, json.Unmarshal([]byte(matchJSON), &m))

	v := m.Vulnerability
	assert.Empty(t, v.RelatedVulnerabilities, "grype puts related records on the match, not inside the vulnerability")
	assert.Equal(t, 98.7, v.Risk)
	assert.Equal(t, []KnownExploited{{CVE: "CVE-2025-24813", DateAdded: "2025-04-01", KnownRansomwareCampaignUse: "Unknown"}}, v.KnownExploited)
	require.Len(t, v.EPSS, 1)
	assert.Equal(t, "CVE-2025-24813", v.EPSS[0].CVE)
	assert.Equal(t, 0.99927, v.EPSS[0].Score)
	assert.Equal(t, []CWE{{CVE: "CVE-2025-24813", CWE: "CWE-502"}}, v.CWEs)

	require.Len(t, m.RelatedVulnerabilities, 1)
	related := m.RelatedVulnerabilities[0]
	assert.Equal(t, "CVE-2025-24813", related.ID)
	assert.Equal(t, []string{"https://github.com/absholi7ly/POC-CVE-2025-24813/blob/main/README.md"}, related.URLs)
	require.Len(t, related.Cvss, 1)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", related.Cvss[0].Vector)
	assert.Equal(t, "tomcat-embed-core", m.Artifact.Name)
}

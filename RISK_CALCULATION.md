# Risk Calculation Feature

## Overview

This document describes the new risk calculation feature that has been added to the Harbor Scanner Grype adapter. The feature calculates vulnerability risk using the formula:

**Risk = EPSS × (CVSS/10)**

Where:
- **EPSS** (Exploit Prediction Scoring System) - probability of exploitation (0.0-1.0)
- **CVSS** (Common Vulnerability Scoring System) - severity score (0.0-10.0)

## Configuration

### Risk Configuration File

The risk calculation is configured via the `risk-config.yaml` file:

```yaml
# Risk calculation configuration
# Formula: Risk = EPSS * (CVSS/10)
# Risk percentage thresholds for severity levels

risk:
  # Calculation mode: "formula", "cvss" or "policy"
  mode: "formula"

  # Risk percentage thresholds (0-100%)
  thresholds:
    critical: 75.0  # Risk >= 75% = Critical
    high: 50.0      # Risk >= 50% = High  
    medium: 25.0    # Risk >= 25% = Medium
    low: 10.0       # Risk >= 10% = Low
    # Below 10% = Unknown

  # Default values when EPSS or CVSS data is missing
  defaults:
    epss: 0.1       # Default EPSS score (10% probability)
    cvss: 5.0       # Default CVSS score (medium severity)

  # Enable/disable risk calculation
  enabled: true
```

The mode is required when risk is enabled and is case-insensitive: with `enabled: true`, a missing or unknown `mode` stops the start, and `"Formula"` works as `"formula"`.

### Default Thresholds

The system comes with the following default risk thresholds:

- **Critical**: ≥ 75%
- **High**: ≥ 50%
- **Medium**: ≥ 25%
- **Low**: ≥ 10%
- **Unknown**: < 10%

## How It Works

### 1. Data Sources

The system uses data from Grype's vulnerability database:
- **EPSS scores** from the Exploit Prediction Scoring System
- **CVSS scores** from the Common Vulnerability Scoring System (v2.0, v3.0, v3.1)

### 2. Risk Calculation Process

1. **Extract EPSS Score**: Get EPSS score from vulnerability data, use default if missing
2. **Extract CVSS Score**: Get CVSS score (prefer v3.x over v2.0), use default if missing
3. **Calculate Risk**: Apply formula `Risk = EPSS × (CVSS/10)`
4. **Convert to Percentage**: Multiply by 100 to get percentage
5. **Map to Severity**: Compare against configured thresholds

### 3. Severity Mapping

The calculated risk percentage is mapped to Harbor severity levels:

```go
if riskPercentage >= config.Thresholds.Critical {
    return harbor.SevCritical
} else if riskPercentage >= config.Thresholds.High {
    return harbor.SevHigh
} else if riskPercentage >= config.Thresholds.Medium {
    return harbor.SevMedium
} else if riskPercentage >= config.Thresholds.Low {
    return harbor.SevLow
}
return harbor.SevUnknown
```

## Examples

### Example 1: Critical Risk
- EPSS: 0.9 (90% probability)
- CVSS: 9.5 (very high severity)
- Risk = 0.9 × (9.5/10) = 0.855 = 85.5%
- Result: **Critical** (≥ 75%)

### Example 2: High Risk
- EPSS: 0.6 (60% probability)
- CVSS: 8.0 (high severity)
- Risk = 0.6 × (8.0/10) = 0.48 = 48%
- Result: **High** (≥ 50%)

### Example 3: Medium Risk
- EPSS: 0.3 (30% probability)
- CVSS: 7.0 (medium-high severity)
- Risk = 0.3 × (7.0/10) = 0.21 = 21%
- Result: **Medium** (≥ 25%)

### Example 4: Low Risk
- EPSS: 0.2 (20% probability)
- CVSS: 5.0 (medium severity)
- Risk = 0.2 × (5.0/10) = 0.1 = 10%
- Result: **Low** (≥ 10%)

### Example 5: Unknown Risk
- EPSS: 0.05 (5% probability)
- CVSS: 3.0 (low severity)
- Risk = 0.05 × (3.0/10) = 0.015 = 1.5%
- Result: **Unknown** (< 10%)

## Configuration Customization

### Customizing Thresholds

You can customize the risk thresholds by modifying the `risk-config.yaml` file:

```yaml
risk:
  thresholds:
    critical: 80.0  # More strict - only 80%+ is Critical
    high: 60.0      # More strict - only 60%+ is High
    medium: 30.0    # More strict - only 30%+ is Medium
    low: 15.0       # More strict - only 15%+ is Low
```

### Disabling Risk Calculation

To disable risk calculation and use Grype's original severity mapping:

```yaml
risk:
  enabled: false
```

### Custom Default Values

Adjust default values for missing data:

```yaml
risk:
  defaults:
    epss: 0.2       # Higher default EPSS (20% probability)
    cvss: 6.0       # Higher default CVSS (medium-high severity)
```

## Deployment

### Docker Build

The risk configuration file is automatically included in the Docker image:

```dockerfile
COPY risk-config.yaml /app/risk-config.yaml
```

### File Locations

The system looks for the configuration file in the following order:
1. `/app/risk-config.yaml` (production)
2. `risk-config.yaml` (development)

Without either file the built-in defaults apply (`cvss` mode, risk enabled); a file that cannot be read or parsed stops the start.

## Testing

The feature includes comprehensive tests covering:
- Risk calculation with various EPSS/CVSS combinations
- Threshold mapping
- Default value handling
- Missing data scenarios

Run tests with:
```bash
go test ./pkg/scan -v
```

## Benefits

1. **More Accurate Risk Assessment**: Combines exploit probability (EPSS) with severity (CVSS)
2. **Configurable Thresholds**: Organizations can adjust risk levels to their needs
3. **Fallback Handling**: Graceful handling of missing EPSS/CVSS data
4. **Backward Compatibility**: Can be disabled to use original Grype severity mapping
5. **Real-time Calculation**: Risk is calculated during each scan

## Monitoring

The system logs risk calculation details when debug mode is enabled:

```bash
docker run -e SCANNER_GRYPE_DEBUG_MODE=true harbor-scanner-grype:latest
```

This will show detailed information about EPSS/CVSS scores and calculated risk percentages.

## Policy mode (`SCANNER_RISK_MODE=policy`)

Levels come from five rules, checked in this order for every grype finding (vulnerability + package):

1. **KEV** — the CVE is in the CISA Known Exploited Vulnerabilities catalogue: **Critical**.
2. **Malicious package** — **Critical** when the description starts with one of GitHub's malware-advisory
   wordings ("Malware in …", "Malicious code in …" for OpenSSF malicious-packages, "Malicious Package in …",
   "Embedded Malicious Code in …", "Embedded malware in …"), when it is a RustSec "… removed from crates.io …
   malicious code" advisory, when the finding is itself a GitHub advisory (namespace `github:…`) whose id is
   on the list of older malware advisories with other titles (`pkg/policy/malware_advisories.go`), or when
   the CVE has CWE-506 (embedded malicious code). A distro finding that only shares a CVE number with a
   listed advisory (for example Ubuntu's `rails` package and CVE-2018-3779) is not flagged.
3. **Risk ladder** — grype's own risk score (the RISK column of `grype` output, 0–100), compared as grype
   shows it (one decimal; "<0.1" counts as 0): from `SCANNER_POLICY_CRITICAL` (70) Critical, from
   `SCANNER_POLICY_HIGH` (30) High, from `SCANNER_POLICY_MEDIUM` (10) Medium, below that Low. For advisories
   that bundle several CVEs (ALAS, ELSA) grype uses the EPSS of the first CVE; the policy uses the highest
   one instead and shows both numbers.
4. **No EPSS** — grype's severity, capped at High: without EPSS or KEV there is no data about attacks.
   Negligible becomes Low, no severity stays Unknown.
5. **Public exploit** — an Exploit-DB entry for one of the finding's CVEs, or a proof-of-concept link among
   its URLs, raises levels below High: to **High** when the flaw is reachable over the network and grype
   rates it High or Critical, otherwise to **Medium**. The attack vector is taken from the finding's own
   CVSS, or from the related NVD records when it has none. Packet Storm copies of vendor advisories and
   index pages of Packet Storm and Exploit-DB do not count as exploits.

The mode needs grype's JSON with the `risk` field (tested with grype 0.117.0); a report whose findings have EPSS but no risk logs a warning.

The reason is written in front of the vulnerability description in Harbor, with the date of the
assessment, for example:

    High на 2026-09-25: риск grype 69.0, порог High от 30 (EPSS 92%, критичность grype High); эксплойтов не найдено; в KEV нет. — An attacker may cause…

Links to the Exploit-DB exploits found (up to five), or to the proof of concept the reason names, are added
to the vulnerability links.

### Harbor keeps the first description

Harbor stores one record per CVE, package and version for each scanner registration. Later scans change the
record's level (Harbor 2.14 and newer also the fixed version, CVSS and status, and only when the level or
status changed), but never its description or links. The reason therefore describes the assessment on its date; if the level changes later, Harbor shows
the new level next to the old reason.

After changing `SCANNER_POLICY_*` or the mode, re-register the scanner to get fresh reasons. Harbor refuses a
second registration with the same URL, so either:

- register the adapter under another address of the same service (a second DNS name, a network alias or a second published port), make
  it the default scanner, run "Scan all" and delete the old registration; or
- make another scanner the default for the switch, delete the adapter's registration (Harbor deletes its
  records too), register the adapter again at the same address, make it the default and run "Scan all".

### Settings

| Variable | Default | Meaning |
|---|---|---|
| `SCANNER_RISK_ENABLED` | from `risk-config.yaml` (`true`) | `false` shows grype's own severity |
| `SCANNER_RISK_MODE` | from `risk-config.yaml` (`formula` in the image, `cvss` without the file) | `policy`, `formula` or `cvss`, in any case; with risk enabled, a missing mode or any other value stops the start |
| `SCANNER_POLICY_CRITICAL`, `_HIGH`, `_MEDIUM` | 70, 30, 10 | risk thresholds of the ladder: Critical > High > Medium > 0, at most 100, one decimal |
| `SCANNER_EXPLOITDB_FILE` | `/home/scanner/.cache/exploitdb/files_exploits.csv` | Exploit-DB list |
| `SCANNER_EXPLOITDB_MAX_AGE` | `336h` | older lists are reported in the log; `0` turns the warning off |

A blank `SCANNER_POLICY_*`, `SCANNER_EXPLOITDB_FILE` or `SCANNER_EXPLOITDB_MAX_AGE` (for example
`SCANNER_POLICY_HIGH=` in `.env`) stops the start: delete the line to get the default. Blank `SCANNER_RISK_*`
variables count as unset.

The Exploit-DB list is re-read within a minute after the nightly job replaces it. Without the list, exploits
are found only through vulnerability links.

### Known limitations

- The list of malware advisories with non-standard titles is a snapshot of the grype database of
  2026-09-15; GitHub keeps publishing such advisories, so refresh it now and then (see the comment in
  `pkg/policy/malware_advisories.go`).
- The proof-of-concept pattern looks at the address only: a repository with "poc" inside a word counts,
  and a gist without a `#file-cve-…` fragment in its link, or a file deep inside a repository, does not.
- For an advisory with several CVEs the exploit and the network vector may belong to different CVEs.

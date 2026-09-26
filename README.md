# Harbor Scanner Adapter for Grype

A [Harbor](https://goharbor.io/) pluggable scanner that scans container images with
[Grype](https://github.com/anchore/grype) 0.117.0 and [Syft](https://github.com/anchore/syft) 1.51.1.
It implements the Harbor Scanner Adapter API v1.1: vulnerability reports and SBOMs (SPDX, CycloneDX).

## Features

- **Severity policy** (`SCANNER_RISK_MODE=policy`). Each finding gets its Harbor level from five
  rules: CISA KEV, malicious packages, grype's risk score, missing EPSS data and public exploits.
  The reason and the date of the assessment are written in front of the vulnerability description
  in Harbor. See [Severity policy](#severity-policy).
- **Exploit-DB.** The list of public exploits is refreshed nightly, and links to the exploits found
  are added to the vulnerability.
- **One report row per package.** A CVE found in `libcrypto3`, `libssl3` and `openssl` shows up as
  three rows, each with its own package, in every mode.
- **API key.** `SCANNER_API_KEY` is required, and Harbor sends it with every request. The probes and
  `/metrics` stay open.
- **Registry credentials under control.** Harbor's Basic credentials are used as sent. The adapter's
  own account (a Harbor robot) goes only to the hosts listed in `SCANNER_REGISTRY_TRUSTED_HOSTS`.
  Passwords, tokens and authorization headers are never logged.
- **Reliable queue.** Jobs sit in Redis lists:
  - an interrupted scan is requeued on the next start;
  - scans that Harbor has stopped waiting for are skipped;
  - a shutdown lets running scans finish.
- **Offline-friendly.** Scans never download anything. The vulnerability DB and the Exploit-DB list
  are updated by a nightly cron job, through `HTTPS_PROXY` if it is set, or imported by hand.
- **Legacy modes.** `formula` (EPSS × CVSS) and `cvss` are still available, and so is grype's own
  severity (`SCANNER_RISK_ENABLED=false`).

## Severity policy

The rules are checked in this order for every finding (vulnerability + package):

1. **KEV.** The CVE is in the CISA Known Exploited Vulnerabilities catalogue → **Critical**.
2. **Malicious package** → **Critical**. This covers:
   - GitHub malware advisories (all their wordings);
   - RustSec "removed from crates.io for malicious code";
   - a list of older malware advisories with non-standard titles;
   - CWE-506.
3. **Risk ladder.** grype's own risk score (the RISK column, 0–100) is compared with the thresholds:
   from 70 **Critical**, from 30 **High**, from 10 **Medium**, otherwise **Low**. For advisories that
   bundle several CVEs (ALAS, ELSA), the highest EPSS is used.
4. **No EPSS.** grype's severity is used, but never above **High**.
5. **Public exploit.** An Exploit-DB entry or a proof-of-concept link raises lower levels:
   - to **High** when the flaw is reachable over the network and grype rates it High or Critical;
   - otherwise to **Medium**.

Example of what Harbor shows:

    High на 2026-09-25: риск grype 69.0, порог High от 30 (EPSS 92%, критичность grype High); эксплойтов не найдено; в KEV нет. — An attacker may cause…

Details, limitations and all settings are in [RISK_CALCULATION.md](RISK_CALCULATION.md).

> Harbor keeps a finding's description from its first scan; later scans only update the level. After
> changing the thresholds or the mode, register the scanner in Harbor again to get fresh reasons (see
> RISK_CALCULATION.md, "Harbor keeps the first description").

## Installation

### Requirements

- An amd64 Linux server with Docker and Docker Compose v2.
- Harbor installed with its own docker compose. The adapter joins Harbor's `harbor_harbor` network.
- About 5 GB of disk for the image and volumes, and memory for the parallel scans.
- Internet access, directly or through `HTTPS_PROXY`, for the nightly updates. Without it, import the
  vulnerability DB by hand.

### Option A: release bundle (no build on the server)

The bundle contains:
- `harbor-scanner-grype-amd64.tar.gz`, the image;
- `grype-db-*.tar.zst`, the offline vulnerability DB;
- `docker-compose.yml`, `.env.example`, `deploy.sh`, `INSTALL.md` and `SHA256SUMS`.

```bash
sha256sum -c SHA256SUMS
docker load -i harbor-scanner-grype-amd64.tar.gz
./deploy.sh        # the first run creates .env from .env.example and stops
vi .env            # set SCANNER_API_KEY and the registry settings, see Configuration
./deploy.sh
```

### Option B: build from source

The build downloads Go modules, grype, syft (checksums are verified) and the Exploit-DB list. If a
`grype-db.tar.zst` lies next to the `Dockerfile`, it is imported instead of downloading the
vulnerability DB.

```bash
git clone -b feature/policy-mode https://github.com/kspsts/harbor-scanner-grype.git
cd harbor-scanner-grype
docker compose build
cp .env.example .env && vi .env
./deploy.sh
```

`deploy.sh` replaces containers named `grype-adapter` and `grype-redis` left from an earlier
deployment. To roll back, load the old image and start the old compose file.

### Vulnerability database

grype refuses to scan with a database older than `GRYPE_DB_MAX_ALLOWED_BUILT_AGE` (5 days by
default). A cron job updates it nightly (`GRYPE_DB_UPDATE_SCHEDULE`, in `TZ`). To update right away:

```bash
docker exec grype-adapter update-grype-db.sh
```

Without internet access, download a fresh archive on another machine (`grype db list` shows the
links) and import it:

```bash
docker cp grype-db.tar.zst grype-adapter:/tmp/grype-db.tar.zst
docker exec -u scanner grype-adapter grype db import /tmp/grype-db.tar.zst
docker exec grype-adapter rm /tmp/grype-db.tar.zst
```

### Register the scanner in Harbor

In Harbor, go to Interrogation Services → Scanners → New Scanner and fill in:
- **Endpoint:** `http://grype-adapter:8090`
- **Authorization:** `Bearer`
- **Credentials:** the value of `SCANNER_API_KEY`

Then run a scan on a test project before making the scanner the default.

## Configuration

All settings live in `.env`. [.env.example](.env.example) documents every variable. The main ones:

| Variable | Default | Meaning |
|---|---|---|
| `SCANNER_API_KEY` | — (required) | Key Harbor sends as `Bearer`; at least 16 characters, e.g. `openssl rand -hex 32` |
| `TZ` | `UTC` | Time zone of the update schedule and of the date in the reasons |
| `SCANNER_REGISTRY_HOST_MAP` | see `.env.example` | `host=target` pairs: registry host from Harbor's request → host[:port] the adapter connects to |
| `SCANNER_EXTRA_HOSTS` | empty | `host=ip` pairs added to the container's `/etc/hosts` |
| `SCANNER_REGISTRY_USERNAME`, `_PASSWORD` | empty | Robot account (pull only) used when Harbor sends a Bearer token or nothing |
| `SCANNER_REGISTRY_TRUSTED_HOSTS` | empty | The only registry hosts the account above is sent to |
| `SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY` | `true` | As in the previous image. To verify certificates, mount your CA, set `SSL_CERT_FILE` and set this to `false` |
| `SCANNER_REGISTRY_INSECURE_USE_HTTP` | `true` | Allow plain HTTP registries |
| `SCANNER_RISK_ENABLED` | `true` | `false` shows grype's own severity |
| `SCANNER_RISK_MODE` | `policy` | `policy`, `formula` or `cvss` |
| `SCANNER_POLICY_CRITICAL`, `_HIGH`, `_MEDIUM` | `70`, `30`, `10` | Risk thresholds of the ladder |
| `SCANNER_EXPLOITDB_URL`, `SCANNER_EXPLOITDB_MAX_AGE` | GitLab, `336h` | Exploit-DB source, and the age after which a stale list is logged |
| `SCANNER_GRYPE_TIMEOUT` | `15m` | A longer scan is stopped and reported as failed |
| `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` | `5` | Parallel scans; no point in exceeding Harbor's `max_job_workers` |
| `SCANNER_LOG_LEVEL`, `SCANNER_LOG_FORMAT` | `info`, `text` | `json` for log collectors |
| `HTTPS_PROXY` | empty | Proxy for the nightly updates |

The adapter refuses to start on invalid settings, for example a missing API key, invalid thresholds or
an unknown mode. A blank value such as `SCANNER_POLICY_HIGH=` is an error: delete the line to get the
default.

## API

| Endpoint | Key | Description |
|---|---|---|
| `GET /api/v1/metadata` | yes | Scanner info, DB date, Exploit-DB date and size, active settings |
| `POST /api/v1/scan` | yes | Queue a scan request from Harbor |
| `GET /api/v1/scan/{id}/report` | yes | Vulnerability report or SBOM |
| `GET /probe/healthy`, `GET /probe/ready` | no | Liveness and readiness |
| `GET /metrics` | no | Prometheus metrics |

The key is accepted as `Authorization: Bearer <key>` or `X-ScannerAdapter-API-Key: <key>`.

## Logs

```bash
docker logs -f grype-adapter
```

- **Scans:** each scan logs its start, result (number of vulnerabilities, duration), skip or failure.
- **Nightly job:** the DB and Exploit-DB updates go to the same log.
- **Start-up warnings:** the adapter warns when registry certificate checks are off, or when an
  account is set but no trusted hosts are.

## Development

Go 1.22.

```bash
go test ./...
go vet ./...
# The queue and store tests need a Redis; they are skipped without one:
docker run -d --name test-redis -p 16380:6379 redis:7-alpine
SCANNER_TEST_REDIS_URL=redis://localhost:16380/15 go test ./... -race
```

The policy tests include real grype 0.117.0 reports (`pkg/policy/testdata`). Regenerate them when
upgrading grype, because the risk formula is copied from that version.

Design and plans: `docs/superpowers/specs` and `docs/superpowers/plans`.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Harbor](https://goharbor.io/) - Container registry platform
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner
- [Harbor Scanner Trivy](https://github.com/aquasecurity/harbor-scanner-trivy) - Reference implementation

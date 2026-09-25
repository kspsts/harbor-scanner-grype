# План 1. Режим `policy`: пять правил, Exploit-DB, пояснения

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Новый режим `SCANNER_RISK_MODE=policy`. Он выставляет уровень находки по пяти правилам и пишет причину в начало описания уязвимости в Harbor.

**Architecture:** Правила собраны в чистом пакете `pkg/policy`: на вход находка grype, индекс Exploit-DB и пороги; на выход уровень, пояснение и ссылки. Пакет `pkg/exploitdb` читает `files_exploits.csv` и перечитывает его после ночного обновления. `pkg/scan/transformer.go` строит по строке отчёта на каждую находку grype и в режиме `policy` зовёт `policy.Evaluate`.

**Tech Stack:** Go 1.22 (через `GOTOOLCHAIN=go1.22.12`), testify, caarlos0/env v6, JSON grype 0.117.0, Exploit-DB `files_exploits.csv`.

**Спецификация:** `docs/superpowers/specs/2026-09-25-policy-mode-design.md`, разделы 3–6 и 9. Сборка, паритет, безопасность и очередь — в планах 2 и 3.

**Окружение.** Все команды выполняются из корня репозитория `/Users/kp/harbor-scanner-grype-src`. Локальный Go — 1.21, а `go.mod` требует 1.22, поэтому в начале сессии нужно выполнить `export GOTOOLCHAIN=go1.22.12` (тулчейн уже скачан). Коммиты — в ветку `feature/policy-mode`, каждый заканчивается строкой `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Файлы

| Файл | Что в нём |
|---|---|
| `pkg/policy/policy.go` | `Thresholds`, `ExploitLookup`, `Result`, `Evaluate` и сами правила |
| `pkg/policy/risk.go` | множитель критичности grype и оценка риска с пересчётом для бюллетеней |
| `pkg/policy/facts.go` | факты находки: CVE, эксплойты, PoC, сетевой вектор, вредоносный код |
| `pkg/policy/reason.go` | текст пояснения и форматирование чисел |
| `pkg/policy/*_test.go`, `pkg/policy/testdata/` | тесты, реальные JSON grype |
| `pkg/exploitdb/index.go`, `pkg/exploitdb/watcher.go` | индекс Exploit-DB и перечитывание файла |
| `pkg/exploitdb/*_test.go`, `pkg/exploitdb/testdata/files_exploits.csv` | тесты |
| `pkg/grype/model.go`, `pkg/grype/model_test.go` | поля `risk`, `knownExploited`, `cwes`, `relatedVulnerabilities` |
| `pkg/etc/config.go`, `pkg/etc/config_test.go` | настройки `SCANNER_POLICY_*`, `SCANNER_EXPLOITDB_*`, переопределение `SCANNER_RISK_*` |
| `pkg/scan/transformer.go`, `pkg/scan/transformer_test.go`, `pkg/scan/transformer_policy_test.go` | строка отчёта на каждую находку, режим `policy` |
| `main.go` | подключение индекса и порогов |
| `RISK_CALCULATION.md` | описание режима |

---

### Task 1: Вернуть тестам зелёный цвет

Сейчас тесты main не проходят: `pkg/scan` не компилируется (в тестах старая форма `etc.RiskConfig`), в `pkg/etc` падают `TestLogLevel` и `TestGrypeConfigDefaults`.

**Files:**
- Modify: `pkg/etc/config_test.go`
- Modify: `pkg/scan/transformer_test.go`

- [ ] **Step 1: Убедиться, что тесты падают**

Run: `go test ./... 2>&1 | tail -20`
Expected: `vet: pkg/scan/transformer_test.go:16:3: unknown field Mode in struct literal of type etc.RiskConfig`, `--- FAIL: TestLogLevel`, `--- FAIL: TestGrypeConfigDefaults`.

- [ ] **Step 2: Исправить импорты и `TestLogLevel` в `pkg/etc/config_test.go`**

Блок импортов заменить на:

```go
import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
```

Функцию `TestLogLevel` заменить целиком:

```go
func TestLogLevel(t *testing.T) {
	tests := []struct {
		envValue string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo}, // default
	}

	for _, test := range tests {
		if test.envValue != "" {
			t.Setenv("SCANNER_LOG_LEVEL", test.envValue)
		} else {
			os.Unsetenv("SCANNER_LOG_LEVEL")
		}
		assert.Equal(t, test.expected, LogLevel())
	}
}
```

- [ ] **Step 3: Исправить `TestGrypeConfigDefaults`**

Значения по умолчанию задаются тегами `envDefault` и появляются только после `env.Parse`. Первые строки функции:

```go
func TestGrypeConfigDefaults(t *testing.T) {
	config := Grype{}
	
	// Test default values
```

заменить на:

```go
func TestGrypeConfigDefaults(t *testing.T) {
	var config Grype
	require.NoError(t, env.Parse(&config))

	// Test default values
```

- [ ] **Step 4: Исправить литералы `etc.RiskConfig` в `pkg/scan/transformer_test.go`**

Все пять литералов открываются строкой `\tconfig := etc.RiskConfig{` и закрываются первой следующей строкой `\t}`. Скрипт оборачивает их в `RiskConfigData`:

```bash
python3 - <<'EOF'
import pathlib
p = pathlib.Path("pkg/scan/transformer_test.go")
out, inside = [], False
for line in p.read_text().split("\n"):
    if line == "\tconfig := etc.RiskConfig{":
        out.append("\tconfig := etc.RiskConfig{Risk: etc.RiskConfigData{")
        inside = True
        continue
    if inside and line == "\t}":
        out.append("\t}}")
        inside = False
        continue
    out.append(line)
p.write_text("\n".join(out))
EOF
grep -c "etc.RiskConfig{Risk: etc.RiskConfigData{" pkg/scan/transformer_test.go
```

Expected: `5`

- [ ] **Step 5: Прогнать тесты**

Run: `go test ./...`
Expected: `ok` для `pkg/etc`, `pkg/grype`, `pkg/scan`, остальные пакеты `[no test files]`.

- [ ] **Step 6: Commit**

```bash
gofmt -w pkg/etc/config_test.go pkg/scan/transformer_test.go
git add pkg/etc/config_test.go pkg/scan/transformer_test.go
git commit -m "test: make the existing test suite pass

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Поля grype, нужные правилам

В JSON grype 0.117.0 `relatedVulnerabilities` лежит рядом с `vulnerability`, а `knownExploited`, `epss` (с полем `cve`), `cwes` и `risk` — внутри неё. Сейчас модель их не читает.

**Files:**
- Modify: `pkg/grype/model.go`
- Create: `pkg/grype/model_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/grype/model_test.go`

```go
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
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/grype/`
Expected: FAIL, `v.Risk undefined`, `undefined: KnownExploited`, `m.RelatedVulnerabilities undefined`.

- [ ] **Step 3: Дополнить модель** `pkg/grype/model.go`

`Match` заменить на:

```go
type Match struct {
	Vulnerability          Vulnerability          `json:"vulnerability"`
	RelatedVulnerabilities []RelatedVulnerability `json:"relatedVulnerabilities,omitempty"`
	Artifact               Artifact               `json:"artifact"`
}
```

В `Vulnerability` после строки с полем `EPSS` добавить:

```go
	KnownExploited         []KnownExploited       `json:"knownExploited,omitempty"`
	CWEs                   []CWE                  `json:"cwes,omitempty"`
	Risk                   float64                `json:"risk"`
```

`EPSS` заменить на:

```go
// EPSS represents Exploit Prediction Scoring System data
type EPSS struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"epss"`       // EPSS score (0.0-1.0)
	Percentile float64 `json:"percentile"` // EPSS percentile
	Date       string  `json:"date"`       // Date of EPSS data
}
```

В конец файла добавить:

```go
// KnownExploited is an entry of the CISA KEV catalogue that grype attaches to a vulnerability.
type KnownExploited struct {
	CVE                        string `json:"cve"`
	DateAdded                  string `json:"dateAdded,omitempty"` // YYYY-MM-DD
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// CWE is a weakness class assigned to one of the vulnerability's CVEs.
type CWE struct {
	CVE string `json:"cve"`
	CWE string `json:"cwe"`
}
```

- [ ] **Step 4: Прогнать тесты**

Run: `go test ./...`
Expected: все `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/grype
git add pkg/grype/model.go pkg/grype/model_test.go
git commit -m "feat(grype): read risk, KEV, CWEs and related vulnerabilities from grype JSON

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Индекс Exploit-DB

**Files:**
- Create: `pkg/exploitdb/index.go`
- Create: `pkg/exploitdb/index_test.go`
- Create: `pkg/exploitdb/testdata/files_exploits.csv`

- [ ] **Step 1: Тестовые данные** `pkg/exploitdb/testdata/files_exploits.csv`

Формат как в репозитории Exploit-DB. Третья строка проверяет кавычки внутри поля и код в нижнем регистре.

```csv
id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url
50590,exploits/java/remote/50590.py,"Apache Log4j2 2.14.1 - Information Disclosure",2021-12-14,leonjza,remote,java,,2021-12-14,2021-12-14,0,CVE-2021-44228,,,,,
50592,exploits/java/remote/50592.py,"Apache Log4j 2 - Remote Code Execution (RCE)",2021-12-15,kozmer,remote,java,,2021-12-15,2021-12-15,0,CVE-2021-44228;CVE-2021-45046,,,,,
9,exploits/linux/local/9.c,"Linux Kernel - Local Privilege Escalation, with ""quotes""",2003-04-01,foo,local,linux,,2003-04-01,2003-04-01,1,cve-2003-0127;OSVDB-1,,,,,
52134,exploits/multiple/webapps/52134.py,"Apache Tomcat - Remote Code Execution",2025-03-20,bar,webapps,multiple,,2025-03-20,2025-03-20,0,CVE-2025-24813,,,,,
```

- [ ] **Step 2: Написать падающий тест** `pkg/exploitdb/index_test.go`

```go
package exploitdb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMapsCVEsToExploitIDs(t *testing.T) {
	f, err := os.Open("testdata/files_exploits.csv")
	require.NoError(t, err)
	defer f.Close()

	idx, err := Parse(f)
	require.NoError(t, err)

	assert.Equal(t, []string{"50590", "50592"}, idx.Lookup("CVE-2021-44228"))
	assert.Equal(t, []string{"50592"}, idx.Lookup("CVE-2021-45046"))
	assert.Equal(t, []string{"9"}, idx.Lookup("CVE-2003-0127"), "codes are matched case-insensitively")
	assert.Equal(t, []string{"52134"}, idx.Lookup("cve-2025-24813"), "lookups are case-insensitive")
	assert.Nil(t, idx.Lookup("CVE-2099-0001"))
	assert.Equal(t, 4, idx.Len())
}

func TestParseSortsIDsNumerically(t *testing.T) {
	idx, err := Parse(strings.NewReader("id,codes\n1000,CVE-2020-0001\n999,CVE-2020-0001\n10000,CVE-2020-0001\n"))
	require.NoError(t, err)
	assert.Equal(t, []string{"999", "1000", "10000"}, idx.Lookup("CVE-2020-0001"))
}

func TestParseRejectsOtherFiles(t *testing.T) {
	_, err := Parse(strings.NewReader("name,value\nfoo,bar\n"))
	assert.ErrorContains(t, err, "not an Exploit-DB list")
}

func TestLoadReturnsModificationTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "files_exploits.csv")
	require.NoError(t, os.WriteFile(path, []byte("id,codes\n1,CVE-2020-0001\n"), 0o644))
	stamp := time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(path, stamp, stamp))

	idx, modTime, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"1"}, idx.Lookup("CVE-2020-0001"))
	assert.True(t, modTime.Equal(stamp))
}

func TestNilIndexLookup(t *testing.T) {
	var idx *Index
	assert.Nil(t, idx.Lookup("CVE-2021-44228"))
	assert.Equal(t, 0, idx.Len())
}
```

- [ ] **Step 3: Убедиться, что тест не компилируется**

Run: `go test ./pkg/exploitdb/`
Expected: FAIL, `undefined: Parse`.

- [ ] **Step 4: Реализация** `pkg/exploitdb/index.go`

```go
// Package exploitdb reads the list of public exploits published by Exploit-DB
// (files_exploits.csv from https://gitlab.com/exploit-database/exploitdb).
package exploitdb

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Index maps CVE ids to the ids of Exploit-DB exploits that reference them.
type Index struct {
	byCVE map[string][]string
}

// Lookup returns the Exploit-DB ids for a CVE, sorted numerically, or nil.
func (i *Index) Lookup(cve string) []string {
	if i == nil {
		return nil
	}
	return i.byCVE[strings.ToUpper(strings.TrimSpace(cve))]
}

// Len returns the number of CVEs that have at least one exploit.
func (i *Index) Len() int {
	if i == nil {
		return 0
	}
	return len(i.byCVE)
}

// Parse reads files_exploits.csv. Only the "id" and "codes" columns are used; codes is a
// semicolon-separated list such as "CVE-2021-44228;OSVDB-1".
func Parse(r io.Reader) (*Index, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}
	idCol, codesCol := -1, -1
	for i, name := range header {
		switch strings.TrimSpace(name) {
		case "id":
			idCol = i
		case "codes":
			codesCol = i
		}
	}
	if idCol < 0 || codesCol < 0 {
		return nil, errors.New(`not an Exploit-DB list: no "id" and "codes" columns`)
	}

	byCVE := make(map[string][]string)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading record: %w", err)
		}
		if len(record) <= idCol || len(record) <= codesCol {
			continue
		}
		id := strings.TrimSpace(record[idCol])
		for _, code := range strings.Split(record[codesCol], ";") {
			code = strings.ToUpper(strings.TrimSpace(code))
			if strings.HasPrefix(code, "CVE-") {
				byCVE[code] = appendUnique(byCVE[code], id)
			}
		}
	}
	for _, ids := range byCVE {
		sortNumeric(ids)
	}
	return &Index{byCVE: byCVE}, nil
}

// Load parses the list at path and returns it with the file's modification time.
func Load(path string) (*Index, time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	idx, err := Parse(f)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", path, err)
	}
	return idx, info.ModTime(), nil
}

func appendUnique(ids []string, id string) []string {
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}

func sortNumeric(ids []string) {
	sort.Slice(ids, func(a, b int) bool {
		x, errX := strconv.Atoi(ids[a])
		y, errY := strconv.Atoi(ids[b])
		if errX != nil || errY != nil {
			return ids[a] < ids[b]
		}
		return x < y
	})
}
```

- [ ] **Step 5: Прогнать тесты**

Run: `go test ./pkg/exploitdb/`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
gofmt -w pkg/exploitdb
git add pkg/exploitdb
git commit -m "feat(exploitdb): index Exploit-DB exploits by CVE

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Перечитывание файла Exploit-DB

Ночной cron (план 2) подменяет файл. Коннектор замечает новую версию по времени изменения, проверяя его не чаще раза в минуту. Если новый файл битый, работает прежний список.

**Files:**
- Create: `pkg/exploitdb/watcher.go`
- Create: `pkg/exploitdb/watcher_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/exploitdb/watcher_test.go`

```go
package exploitdb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func writeList(t *testing.T, path, body string, modTime time.Time) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	require.NoError(t, os.Chtimes(path, modTime, modTime))
}

func TestWatcherReloadsChangedFileAfterInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "files_exploits.csv")
	start := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	writeList(t, path, "id,codes\n1,CVE-2020-0001\n", start)
	clock := &fakeClock{t: start}
	w := newWatcher(path, time.Minute, 0, clock.now)

	assert.Equal(t, []string{"1"}, w.Lookup("CVE-2020-0001"))

	writeList(t, path, "id,codes\n2,CVE-2020-0001\n", start.Add(time.Hour))
	clock.t = start.Add(30 * time.Second)
	assert.Equal(t, []string{"1"}, w.Lookup("CVE-2020-0001"), "not re-checked within the interval")

	clock.t = start.Add(2 * time.Minute)
	assert.Equal(t, []string{"2"}, w.Lookup("CVE-2020-0001"), "re-read after the interval")
}

func TestWatcherPicksUpFileCreatedLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "files_exploits.csv")
	start := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: start}
	w := newWatcher(path, time.Minute, 0, clock.now)

	assert.Nil(t, w.Lookup("CVE-2020-0001"))

	writeList(t, path, "id,codes\n7,CVE-2020-0001\n", start)
	clock.t = start.Add(time.Minute)
	assert.Equal(t, []string{"7"}, w.Lookup("CVE-2020-0001"))
}

func TestWatcherKeepsPreviousListWhenNewOneIsBroken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "files_exploits.csv")
	start := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	writeList(t, path, "id,codes\n1,CVE-2020-0001\n", start)
	clock := &fakeClock{t: start}
	w := newWatcher(path, time.Minute, 0, clock.now)

	writeList(t, path, "<html>proxy error</html>\n", start.Add(time.Hour))
	clock.t = start.Add(time.Minute)
	assert.Equal(t, []string{"1"}, w.Lookup("CVE-2020-0001"))
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/exploitdb/`
Expected: FAIL, `undefined: newWatcher`.

- [ ] **Step 3: Реализация** `pkg/exploitdb/watcher.go`

```go
package exploitdb

import (
	"log/slog"
	"os"
	"sync"
	"time"
)

// Watcher answers lookups from the Exploit-DB list on disk and re-reads the file after the
// nightly update replaces it. The modification time is checked at most once per interval.
type Watcher struct {
	path     string
	interval time.Duration
	maxAge   time.Duration
	now      func() time.Time

	mu            sync.Mutex
	index         *Index
	modTime       time.Time
	failedModTime time.Time
	checked       time.Time
	reportMissing bool
}

// NewWatcher loads the list at path. A missing or broken file is logged, not fatal:
// the policy then finds exploits only through the vulnerability links.
func NewWatcher(path string, interval, maxAge time.Duration) *Watcher {
	return newWatcher(path, interval, maxAge, time.Now)
}

func newWatcher(path string, interval, maxAge time.Duration, now func() time.Time) *Watcher {
	w := &Watcher{path: path, interval: interval, maxAge: maxAge, now: now, reportMissing: true}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.refresh()
	return w
}

// Lookup returns the Exploit-DB ids for a CVE.
func (w *Watcher) Lookup(cve string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.now().Sub(w.checked) >= w.interval {
		w.refresh()
	}
	return w.index.Lookup(cve)
}

// refresh re-reads the file when its modification time changed. The caller holds mu.
func (w *Watcher) refresh() {
	w.checked = w.now()
	info, err := os.Stat(w.path)
	if err != nil {
		if w.reportMissing {
			slog.Warn("Exploit-DB list not found; exploits are taken from vulnerability links only",
				slog.String("path", w.path), slog.String("err", err.Error()))
			w.reportMissing = false
		}
		return
	}
	w.reportMissing = true

	modTime := info.ModTime()
	if (w.index != nil && modTime.Equal(w.modTime)) || modTime.Equal(w.failedModTime) {
		return
	}
	index, modTime, err := Load(w.path)
	if err != nil {
		w.failedModTime = info.ModTime()
		slog.Error("Failed to read the Exploit-DB list; keeping the previous one",
			slog.String("path", w.path), slog.String("err", err.Error()))
		return
	}
	w.index, w.modTime = index, modTime
	slog.Info("Loaded Exploit-DB list", slog.String("path", w.path), slog.Int("cves", index.Len()),
		slog.String("updated", modTime.UTC().Format(time.RFC3339)))
	if age := w.now().Sub(modTime); w.maxAge > 0 && age > w.maxAge {
		slog.Warn("Exploit-DB list is older than SCANNER_EXPLOITDB_MAX_AGE; check the nightly update",
			slog.String("path", w.path), slog.String("age", age.Round(time.Hour).String()))
	}
}
```

- [ ] **Step 4: Прогнать тесты**

Run: `go test ./pkg/exploitdb/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/exploitdb
git add pkg/exploitdb
git commit -m "feat(exploitdb): reload the list after the nightly update replaces it

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Риск — множитель критичности grype и пересчёт для бюллетеней

**Files:**
- Create: `pkg/policy/risk.go`
- Create: `pkg/policy/risk_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/policy/risk_test.go`

```go
package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

func cvss(scores ...float64) []grype.Cvss {
	var out []grype.Cvss
	for _, s := range scores {
		out = append(out, grype.Cvss{Version: "3.1", Metrics: grype.Metrics{BaseScore: s}})
	}
	return out
}

func TestSeverityFactorMatchesGrype(t *testing.T) {
	assert.InDelta(t, 0.94, severityFactor("Critical", cvss(9.8)), 1e-9)
	assert.InDelta(t, 0.75, severityFactor("High", nil), 1e-9)
	assert.InDelta(t, 0.5, severityFactor("", cvss(5.0, 0)), 1e-9, "unknown severity counts as 5, zero scores are skipped")
	assert.InDelta(t, 0.175, severityFactor("Negligible", cvss(2.0, 4.0)), 1e-9)
}

// Rows of `grype` output for an n8n image on Alpine: EPSS × factor × 100 is the RISK column.
func TestSeverityFactorReproducesGrypeRiskColumn(t *testing.T) {
	assert.InDelta(t, 49.3, 0.524*severityFactor("Critical", cvss(9.8))*100, 0.05)  // CVE-2025-15467
	assert.InDelta(t, 74.5, 0.784*severityFactor("Critical", cvss(10.0))*100, 0.05) // GHSA-v4pr-fm98-w9pg
}

func TestEstimateRiskUsesGrypeValue(t *testing.T) {
	v := grype.Vulnerability{Severity: "High", Risk: 69.0,
		EPSS: []grype.EPSS{{CVE: "CVE-2023-45288", Score: 0.92}}}
	est := estimateRisk(v)
	assert.Equal(t, 69.0, est.value)
	assert.False(t, est.rescaled)
	assert.Equal(t, "CVE-2023-45288", est.epss.CVE)
}

func TestEstimateRiskKeepsGrypeValueWhenFirstEPSSIsHighest(t *testing.T) {
	v := grype.Vulnerability{Severity: "High", Risk: 45.0,
		EPSS: []grype.EPSS{{CVE: "CVE-2099-1001", Score: 0.60}, {CVE: "CVE-2099-1000", Score: 0.02}}}
	est := estimateRisk(v)
	assert.Equal(t, 45.0, est.value)
	assert.False(t, est.rescaled)
}

func TestEstimateRiskRescalesAdvisoriesToHighestEPSS(t *testing.T) {
	// An Amazon advisory without CVSS: grype multiplies the first EPSS (2%) by 0.75.
	v := grype.Vulnerability{ID: "ALAS2-2099-0001", Severity: "High", Risk: 1.5,
		EPSS: []grype.EPSS{{CVE: "CVE-2099-1000", Score: 0.02}, {CVE: "CVE-2099-1001", Score: 0.60}}}
	est := estimateRisk(v)
	assert.InDelta(t, 45.0, est.value, 1e-9)
	assert.True(t, est.rescaled)
	assert.Equal(t, 1.5, est.grype)
	assert.Equal(t, "CVE-2099-1001", est.epss.CVE)
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/policy/`
Expected: FAIL, `undefined: severityFactor`.

- [ ] **Step 3: Реализация** `pkg/policy/risk.go`

```go
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
	grype    float64    // the risk grype reported
	rescaled bool       // value uses the highest EPSS of the record instead of the first
	epss     grype.EPSS // the EPSS entry value is based on
}

// estimateRisk returns grype's risk. When the record carries EPSS for several CVEs and the first
// one, which grype uses, is not the highest, it applies grype's formula to the highest EPSS:
// Amazon and Oracle advisories bundle many CVEs and grype would take whichever comes first.
func estimateRisk(v grype.Vulnerability) riskEstimate {
	est := riskEstimate{value: v.Risk, grype: v.Risk}
	if len(v.EPSS) == 0 {
		return est
	}
	est.epss = v.EPSS[0]
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
```

- [ ] **Step 4: Прогнать тесты**

Run: `go test ./pkg/policy/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/policy
git add pkg/policy
git commit -m "feat(policy): grype risk with rescaling for multi-CVE advisories

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Факты находки

**Files:**
- Create: `pkg/policy/facts.go`
- Create: `pkg/policy/facts_test.go`
- Create: `pkg/policy/policy.go` (пока только интерфейс `ExploitLookup`; остальное — в Task 8)

- [ ] **Step 1: Написать падающий тест** `pkg/policy/facts_test.go`

```go
package policy

import (
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

func TestExploitIDsAcrossCVEsAreSortedAndUnique(t *testing.T) {
	lookup := fakeExploits{"CVE-2021-44228": {"50592", "50590"}, "CVE-2021-45046": {"50592", "51183"}}
	assert.Equal(t, []string{"50590", "50592", "51183"}, exploitIDs([]string{"CVE-2021-44228", "CVE-2021-45046"}, lookup))
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

func TestNetworkReachable(t *testing.T) {
	withVectors := func(vectors ...string) grype.Match {
		var c []grype.Cvss
		for _, v := range vectors {
			c = append(c, grype.Cvss{Vector: v})
		}
		return grype.Match{Vulnerability: grype.Vulnerability{Cvss: c}}
	}
	assert.True(t, networkReachable(withVectors("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")))
	assert.True(t, networkReachable(withVectors("AV:N/AC:L/Au:N/C:P/I:P/A:P")), "CVSS v2")
	assert.False(t, networkReachable(withVectors("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")))
	assert.False(t, networkReachable(withVectors("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:N")),
		"environmental MAV:N is not the base vector")

	related := grype.Match{RelatedVulnerabilities: []grype.RelatedVulnerability{{
		Cvss: []grype.Cvss{{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}}}
	assert.True(t, networkReachable(related), "vectors of related CVEs count")
}

func TestMalware(t *testing.T) {
	github := facts{vuln: grype.Vulnerability{Description: "Malware in monorepo-symlink-test"}}
	ok, source := github.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	xz := facts{vuln: grype.Vulnerability{CWEs: []grype.CWE{{CVE: "CVE-2024-3094", CWE: "CWE-506"}}}}
	ok, source = xz.malware()
	assert.True(t, ok)
	assert.Equal(t, "cwe", source)

	injection := facts{vuln: grype.Vulnerability{Description: "This issue may allow an attacker to inject malicious code into the command"}}
	ok, _ = injection.malware()
	assert.False(t, ok, "wording about malicious input is not malware")
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/policy/`
Expected: FAIL, `undefined: cveIDs`.

- [ ] **Step 3: Заготовка** `pkg/policy/policy.go`

```go
// Package policy decides the Harbor level of a grype finding and explains the decision.
package policy

// ExploitLookup returns the ids of Exploit-DB exploits for a CVE.
type ExploitLookup interface {
	Lookup(cve string) []string
}
```

- [ ] **Step 4: Реализация** `pkg/policy/facts.go`

```go
package policy

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

// pocPattern marks links to public exploits or proof-of-concept code, as in tools/rescore.py.
var pocPattern = regexp.MustCompile(`(?i)exploit-db\.com|packetstormsecurity\.com/files|rapid7\.com/db/modules|metasploit|0day\.today|seebug\.org|github\.com/[^/]+/[^/]*(poc|exploit|cve-\d{4}-\d+)`)

// networkVector matches the base attack vector "network" in CVSS v2, v3 and v4 vectors,
// but not the environmental MAV:N.
var networkVector = regexp.MustCompile(`(^|/)AV:N(/|$)`)

// facts are what the rules look at, collected from one grype match.
type facts struct {
	vuln     grype.Vulnerability
	cves     []string
	exploits []string // Exploit-DB ids
	poc      string   // first link to a proof of concept
	network  bool     // some CVSS vector has AV:N
	vectors  bool     // there is at least one CVSS vector
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

// malware reports whether the finding is a malicious package rather than a flaw: GitHub publishes
// such advisories as "Malware in <package>", and CWE-506 is embedded malicious code.
func (f facts) malware() (bool, string) {
	if strings.HasPrefix(f.vuln.Description, "Malware in ") {
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

func firstPoC(m grype.Match) string {
	for _, u := range m.Vulnerability.URLs {
		if pocPattern.MatchString(u) {
			return u
		}
	}
	for _, r := range m.RelatedVulnerabilities {
		for _, u := range r.URLs {
			if pocPattern.MatchString(u) {
				return u
			}
		}
	}
	return ""
}

func networkReachable(m grype.Match) bool {
	for _, c := range allCvss(m) {
		if networkVector.MatchString(c.Vector) {
			return true
		}
	}
	return false
}

func hasVector(m grype.Match) bool {
	for _, c := range allCvss(m) {
		if c.Vector != "" {
			return true
		}
	}
	return false
}

func allCvss(m grype.Match) []grype.Cvss {
	out := append([]grype.Cvss(nil), m.Vulnerability.Cvss...)
	for _, r := range m.RelatedVulnerabilities {
		out = append(out, r.Cvss...)
	}
	return out
}
```

- [ ] **Step 5: Прогнать тесты**

Run: `go test ./pkg/policy/`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
gofmt -w pkg/policy
git add pkg/policy
git commit -m "feat(policy): collect CVEs, exploits, PoC links and attack vector of a finding

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Текст пояснения

**Files:**
- Create: `pkg/policy/reason.go`
- Create: `pkg/policy/reason_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/policy/reason_test.go`

```go
package policy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

func TestReasonString(t *testing.T) {
	r := reason{level: harbor.SevHigh, main: "риск grype 69.0, порог High от 30", facts: []string{"эксплойтов не найдено", "в KEV нет"}}
	assert.Equal(t, "High: риск grype 69.0, порог High от 30; эксплойтов не найдено; в KEV нет.", r.String())

	malware := reason{level: harbor.SevCritical, main: "встроенный вредоносный код (CWE-506)"}
	assert.Equal(t, "Critical: встроенный вредоносный код (CWE-506).", malware.String())
}

func TestFormatPercent(t *testing.T) {
	assert.Equal(t, "92%", formatPercent(0.92))
	assert.Equal(t, "52.4%", formatPercent(0.524))
	assert.Equal(t, "5.1%", formatPercent(0.051))
	assert.Equal(t, "<0.1%", formatPercent(0.0003))
	assert.Equal(t, "0%", formatPercent(0))
}

func TestFormatRisk(t *testing.T) {
	assert.Equal(t, "69.0", formatRisk(69.0))
	assert.Equal(t, "2.9", formatRisk(2.88))
	assert.Equal(t, "<0.1", formatRisk(0.03))
	assert.Equal(t, "0.0", formatRisk(0))
}

func TestFormatThreshold(t *testing.T) {
	assert.Equal(t, "70", formatThreshold(70))
	assert.Equal(t, "12.5", formatThreshold(12.5))
}

func TestExploitFact(t *testing.T) {
	assert.Equal(t, "есть эксплойт в Exploit-DB (52134)",
		exploitFact(facts{exploits: []string{"52134"}, poc: "https://github.com/x/cve-2025-1"}), "Exploit-DB comes first")
	assert.Equal(t, "есть эксплойт в Exploit-DB (1, 2, 3 и ещё 2)", exploitFact(facts{exploits: []string{"1", "2", "3", "4", "5"}}))
	assert.Equal(t, "есть PoC (github.com/guiimoraes/CVE-2025-15467)", exploitFact(facts{poc: "https://github.com/guiimoraes/CVE-2025-15467"}))
	assert.Equal(t, "эксплойтов не найдено", exploitFact(facts{}))
}

func TestShortURL(t *testing.T) {
	assert.Equal(t, "exploit-db.com/exploits/52134", shortURL("https://www.exploit-db.com/exploits/52134"))
	long := shortURL("https://github.com/someone/" + strings.Repeat("a", 100))
	assert.Len(t, long, 80)
	assert.True(t, strings.HasSuffix(long, "..."))
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/policy/`
Expected: FAIL, `undefined: reason`.

- [ ] **Step 3: Реализация** `pkg/policy/reason.go`

```go
package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

// reason is the explanation put in front of the vulnerability description in Harbor:
// "<level>: <main reason>; <fact>; <fact>." Harbor shows it as one paragraph.
type reason struct {
	level harbor.Severity
	main  string
	facts []string
}

func (r reason) String() string {
	s := r.level.String() + ": " + r.main
	for _, f := range r.facts {
		s += "; " + f
	}
	return s + "."
}

// formatPercent renders an EPSS probability (0–1) as a percentage: 0.92 → "92%", 0.524 → "52.4%".
func formatPercent(p float64) string {
	v := p * 100
	if v > 0 && v < 0.05 {
		return "<0.1%"
	}
	return strings.TrimSuffix(strconv.FormatFloat(v, 'f', 1, 64), ".0") + "%"
}

// formatRisk renders a grype risk (0–100) the way grype prints it: one decimal, "<0.1" for tiny values.
func formatRisk(r float64) string {
	if r > 0 && r < 0.05 {
		return "<0.1"
	}
	return strconv.FormatFloat(r, 'f', 1, 64)
}

func formatThreshold(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// exploitFact names the exploits of a finding: Exploit-DB ids first, at most three, else the PoC link.
func exploitFact(f facts) string {
	switch {
	case len(f.exploits) > 0:
		return "есть эксплойт в Exploit-DB (" + listIDs(f.exploits, 3) + ")"
	case f.poc != "":
		return "есть PoC (" + shortURL(f.poc) + ")"
	default:
		return "эксплойтов не найдено"
	}
}

func listIDs(ids []string, max int) string {
	if len(ids) <= max {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:max], ", ") + fmt.Sprintf(" и ещё %d", len(ids)-max)
}

// shortURL drops the scheme and "www." and caps the length so the link fits in one line.
func shortURL(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	u = strings.TrimPrefix(u, "www.")
	if len(u) > 80 {
		u = u[:77] + "..."
	}
	return u
}
```

- [ ] **Step 4: Прогнать тесты**

Run: `go test ./pkg/policy/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/policy
git add pkg/policy
git commit -m "feat(policy): explanation text and number formatting

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Пять правил — `Evaluate`

**Files:**
- Modify: `pkg/policy/policy.go`
- Create: `pkg/policy/policy_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/policy/policy_test.go`

```go
package policy

import (
	"testing"

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
			name: "rule 2: GitHub malware advisory",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "GHSA-2jcg-qqmg-46q6", Severity: "Critical", Description: "Malware in monorepo-symlink-test",
			}},
			severity: harbor.SevCritical,
			reason:   "Critical: пакет помечен как вредоносный (бюллетень GitHub «Malware in»), проверьте, откуда он в образе.",
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
			reason:   "High: EPSS нет, взята критичность grype Critical, понижена до High: без данных об атаках Critical не ставим; эксплойтов не найдено; в KEV нет.",
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
			name: "rule 5: a local exploit raises to Medium",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0002", Severity: "High", Risk: 0.8,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0002", Score: 0.01}},
				Cvss: []grype.Cvss{{Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", Metrics: grype.Metrics{BaseScore: 7.8}}},
				URLs: []string{"https://www.exploit-db.com/exploits/40002"},
			}},
			severity: harbor.SevMedium,
			reason:   "Medium: есть PoC (exploit-db.com/exploits/40002), но уязвимость локальная; без эксплойта было бы Low (риск grype 0.8); в KEV нет.",
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
			name: "rule 5: an exploit does not change a Medium level",
			match: grype.Match{Vulnerability: grype.Vulnerability{
				ID: "CVE-2099-0003", Severity: "Medium", Risk: 12.4,
				EPSS: []grype.EPSS{{CVE: "CVE-2099-0003", Score: 0.132}},
				URLs: []string{"https://github.com/someone/CVE-2099-0003"},
			}},
			severity: harbor.SevMedium,
			reason:   "Medium: риск grype 12.4, порог Medium от 10 (EPSS 13.2%, критичность grype Medium); есть PoC (github.com/someone/CVE-2099-0003); в KEV нет.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Evaluate(tt.match, lookup, thresholds)
			assert.Equal(t, tt.severity, res.Severity)
			assert.Equal(t, tt.reason, res.Reason)
		})
	}
}

func TestEvaluateLinksExploitDBPages(t *testing.T) {
	lookup := fakeExploits{"CVE-2099-0200": {"1", "2", "3", "4", "5", "6", "7"}}
	m := grype.Match{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0200", Severity: "High", Risk: 40,
		EPSS: []grype.EPSS{{CVE: "CVE-2099-0200", Score: 0.5}}}}

	res := Evaluate(m, lookup, thresholds)

	assert.Equal(t, []string{
		"https://www.exploit-db.com/exploits/1",
		"https://www.exploit-db.com/exploits/2",
		"https://www.exploit-db.com/exploits/3",
		"https://www.exploit-db.com/exploits/4",
		"https://www.exploit-db.com/exploits/5",
	}, res.Links)
	assert.Contains(t, res.Reason, "есть эксплойт в Exploit-DB (1, 2, 3 и ещё 4)")
}

func TestLadderThresholds(t *testing.T) {
	cases := map[float64]harbor.Severity{
		69.99: harbor.SevHigh, 70: harbor.SevCritical,
		29.99: harbor.SevMedium, 30: harbor.SevHigh,
		9.99: harbor.SevLow, 10: harbor.SevMedium,
		0: harbor.SevLow,
	}
	for risk, want := range cases {
		m := grype.Match{Vulnerability: grype.Vulnerability{ID: "CVE-2099-0300", Severity: "Medium", Risk: risk,
			EPSS: []grype.EPSS{{CVE: "CVE-2099-0300", Score: 0.1}}}}
		assert.Equal(t, want, Evaluate(m, nil, thresholds).Severity, "risk %v", risk)
	}
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/policy/`
Expected: FAIL, `undefined: Thresholds`, `undefined: Evaluate`.

- [ ] **Step 3: Реализация — заменить `pkg/policy/policy.go` целиком**

```go
// Package policy decides the Harbor level of a grype finding and explains the decision.
package policy

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

// Thresholds are grype risk scores (0–100) from which the ladder gives a level.
type Thresholds struct {
	Critical float64
	High     float64
	Medium   float64
}

// ExploitLookup returns the ids of Exploit-DB exploits for a CVE.
type ExploitLookup interface {
	Lookup(cve string) []string
}

// Result is the level of one finding, the explanation shown in Harbor and links to exploits.
type Result struct {
	Severity harbor.Severity
	Reason   string
	Links    []string
}

const maxExploitLinks = 5

// Evaluate gives one grype match its Harbor level:
//  1. listed in the CISA KEV catalogue → Critical;
//  2. a malicious package or embedded malicious code → Critical;
//  3. otherwise the grype risk ladder when EPSS is known,
//  4. or grype's own severity capped at High when it is not;
//  5. a public exploit then raises levels below High.
func Evaluate(m grype.Match, lookup ExploitLookup, t Thresholds) Result {
	f := collectFacts(m, lookup)
	var r reason
	if len(f.vuln.KnownExploited) > 0 {
		r = kevRule(f)
	} else if ok, source := f.malware(); ok {
		r = malwareRule(source)
	} else {
		r = exploitRule(f, baseRule(f, t))
	}
	return Result{Severity: r.level, Reason: r.String(), Links: exploitLinks(f.exploits)}
}

func kevRule(f facts) reason {
	added, ransomware := "", false
	for _, k := range f.vuln.KnownExploited {
		date := k.DateAdded
		if len(date) > 10 {
			date = date[:10]
		}
		if date != "" && (added == "" || date < added) {
			added = date
		}
		if strings.EqualFold(k.KnownRansomwareCampaignUse, "known") {
			ransomware = true
		}
	}
	main := "есть в каталоге KEV"
	if added != "" {
		main += " с " + added
	}
	if ransomware {
		main += ", используется вымогателями"
	}
	r := reason{level: harbor.SevCritical, main: main}
	if f.hasExploit() {
		r.facts = append(r.facts, exploitFact(f))
	}
	r.facts = append(r.facts, "риск grype "+formatRisk(f.vuln.Risk))
	return r
}

func malwareRule(source string) reason {
	if source == "github" {
		return reason{level: harbor.SevCritical,
			main: "пакет помечен как вредоносный (бюллетень GitHub «Malware in»), проверьте, откуда он в образе"}
	}
	return reason{level: harbor.SevCritical, main: "встроенный вредоносный код (CWE-506)"}
}

// base is the level from rule 3 or 4 and what it rests on, for "без эксплойта было бы …".
type base struct {
	reason
	basis string
}

func baseRule(f facts, t Thresholds) base {
	if len(f.vuln.EPSS) == 0 {
		return noEPSSRule(f)
	}
	return ladderRule(f, t)
}

// ladderRule is rule 3: grype risk compared with the thresholds.
func ladderRule(f facts, t Thresholds) base {
	est := estimateRisk(f.vuln)
	level, threshold := harbor.SevLow, "ниже порога Medium"
	switch {
	case est.value >= t.Critical:
		level, threshold = harbor.SevCritical, "порог Critical от "+formatThreshold(t.Critical)
	case est.value >= t.High:
		level, threshold = harbor.SevHigh, "порог High от "+formatThreshold(t.High)
	case est.value >= t.Medium:
		level, threshold = harbor.SevMedium, "порог Medium от "+formatThreshold(t.Medium)
	}
	sev := grypeSeverity(f.vuln.Severity)
	if est.rescaled {
		main := fmt.Sprintf("риск %s по максимальному EPSS бюллетеня (%s, %s), grype показывает %s; %s (критичность grype %s)",
			formatRisk(est.value), est.epss.CVE, formatPercent(est.epss.Score), formatRisk(est.grype), threshold, sev)
		return base{reason: reason{level: level, main: main}, basis: "риск " + formatRisk(est.value)}
	}
	main := fmt.Sprintf("риск grype %s, %s (EPSS %s, критичность grype %s)",
		formatRisk(est.value), threshold, formatPercent(est.epss.Score), sev)
	return base{reason: reason{level: level, main: main}, basis: "риск grype " + formatRisk(est.value)}
}

// noEPSSRule is rule 4: without EPSS there is no data about attacks, so grype's own
// severity is used but never above High.
func noEPSSRule(f facts) base {
	sev := grypeSeverity(f.vuln.Severity)
	b := base{basis: "EPSS нет"}
	switch strings.ToLower(f.vuln.Severity) {
	case "critical":
		b.reason = reason{level: harbor.SevHigh,
			main: "EPSS нет, взята критичность grype " + sev + ", понижена до High: без данных об атаках Critical не ставим"}
	case "high":
		b.reason = reason{level: harbor.SevHigh, main: "EPSS нет, взята критичность grype " + sev}
	case "medium":
		b.reason = reason{level: harbor.SevMedium, main: "EPSS нет, взята критичность grype " + sev}
	case "low":
		b.reason = reason{level: harbor.SevLow, main: "EPSS нет, взята критичность grype " + sev}
	case "negligible":
		b.reason = reason{level: harbor.SevLow, main: "EPSS нет, взята критичность grype " + sev + ", в Harbor это Low"}
	default:
		b.reason = reason{level: harbor.SevUnknown, main: "EPSS нет, критичность grype неизвестна"}
	}
	return b
}

// exploitRule is rule 5 and adds the facts the level did not already mention.
func exploitRule(f facts, b base) reason {
	r := b.reason
	switch {
	case !f.hasExploit() || r.level >= harbor.SevHigh:
		r.facts = append(r.facts, exploitFact(f))
	case f.network && isSerious(f.vuln.Severity):
		r = reason{level: harbor.SevHigh, main: fmt.Sprintf("%s, уязвимость доступна по сети, критичность grype %s",
			exploitFact(f), grypeSeverity(f.vuln.Severity))}
		r.facts = append(r.facts, wouldBe(b))
	case r.level < harbor.SevMedium:
		r = reason{level: harbor.SevMedium, main: exploitFact(f) + ", " + weakExploit(f)}
		r.facts = append(r.facts, wouldBe(b))
	default: // already Medium: the exploit is worth mentioning, not raising
		r.facts = append(r.facts, exploitFact(f))
	}
	r.facts = append(r.facts, "в KEV нет")
	return r
}

func wouldBe(b base) string {
	return fmt.Sprintf("без эксплойта было бы %s (%s)", b.level, b.basis)
}

// weakExploit says why an exploit raises the level only to Medium.
func weakExploit(f facts) string {
	switch {
	case f.network:
		return "но критичность grype " + grypeSeverity(f.vuln.Severity)
	case f.vectors:
		return "но уязвимость локальная"
	default:
		return "но вектор атаки неизвестен"
	}
}

func isSerious(severity string) bool {
	switch strings.ToLower(severity) {
	case "high", "critical":
		return true
	}
	return false
}

// grypeSeverity is grype's own severity as it prints it, "Unknown" when empty.
func grypeSeverity(severity string) string {
	if severity == "" {
		return "Unknown"
	}
	return severity
}

func exploitLinks(ids []string) []string {
	var links []string
	for _, id := range ids {
		if len(links) == maxExploitLinks {
			break
		}
		links = append(links, "https://www.exploit-db.com/exploits/"+id)
	}
	return links
}
```

- [ ] **Step 4: Прогнать тесты**

Run: `go test ./pkg/policy/ -v -run 'TestEvaluate|TestLadder' 2>&1 | tail -30`
Expected: все подтесты `PASS`, в конце `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/policy
git add pkg/policy
git commit -m "feat(policy): five rules with explanations for Harbor

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Настройки режима

Режим включается переменными `SCANNER_RISK_*`, как в образе из комплекта: они перекрывают `risk-config.yaml`. Пороги лесенки и файл Exploit-DB задаются через `SCANNER_POLICY_*` и `SCANNER_EXPLOITDB_*`.

**Files:**
- Modify: `pkg/etc/config.go`
- Modify: `pkg/etc/config_test.go`

- [ ] **Step 1: Дописать падающие тесты** в конец `pkg/etc/config_test.go`

```go
func TestPolicyDefaults(t *testing.T) {
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, Policy{
		Critical:        70,
		High:            30,
		Medium:          10,
		ExploitDBFile:   "/home/scanner/.cache/exploitdb/files_exploits.csv",
		ExploitDBMaxAge: 336 * time.Hour,
	}, config.Policy)
}

func TestRiskEnvOverridesFile(t *testing.T) {
	t.Setenv("SCANNER_RISK_ENABLED", "true")
	t.Setenv("SCANNER_RISK_MODE", "policy")
	t.Setenv("SCANNER_RISK_HIGH", "60")
	t.Setenv("SCANNER_POLICY_HIGH", "25")

	config, err := GetConfig()
	require.NoError(t, err)
	assert.True(t, config.Risk.Risk.Enabled)
	assert.Equal(t, "policy", config.Risk.Risk.Mode)
	assert.Equal(t, 60.0, config.Risk.Risk.Thresholds.High)
	assert.Equal(t, 25.0, config.Policy.High)
}

func TestRiskModeMustBeKnown(t *testing.T) {
	t.Setenv("SCANNER_RISK_MODE", "magic")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_RISK_MODE")
}

func TestPolicyThresholdsMustBeOrdered(t *testing.T) {
	t.Setenv("SCANNER_POLICY_HIGH", "80")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_POLICY_CRITICAL")
}
```

- [ ] **Step 2: Убедиться, что тесты не компилируются**

Run: `go test ./pkg/etc/`
Expected: FAIL, `undefined: Policy`.

- [ ] **Step 3: Реализация в `pkg/etc/config.go`**

В импорты добавить `"fmt"` и `"strconv"`.

В `Config` после поля `Risk RiskConfig` добавить `Policy Policy`.

После типа `RedisPool` добавить:

```go
// Policy configures SCANNER_RISK_MODE=policy.
type Policy struct {
	Critical        float64       `env:"SCANNER_POLICY_CRITICAL" envDefault:"70"`
	High            float64       `env:"SCANNER_POLICY_HIGH" envDefault:"30"`
	Medium          float64       `env:"SCANNER_POLICY_MEDIUM" envDefault:"10"`
	ExploitDBFile   string        `env:"SCANNER_EXPLOITDB_FILE" envDefault:"/home/scanner/.cache/exploitdb/files_exploits.csv"`
	ExploitDBMaxAge time.Duration `env:"SCANNER_EXPLOITDB_MAX_AGE" envDefault:"336h"`
}

func (p Policy) validate() error {
	if !(p.Critical > p.High && p.High > p.Medium && p.Medium > 0) {
		return fmt.Errorf("SCANNER_POLICY_CRITICAL > SCANNER_POLICY_HIGH > SCANNER_POLICY_MEDIUM > 0 is required, got %v, %v, %v",
			p.Critical, p.High, p.Medium)
	}
	return nil
}
```

В `GetConfig` перед `return cfg, nil` вставить:

```go
	if err := applyRiskEnv(&cfg.Risk.Risk); err != nil {
		return cfg, err
	}
	if err := cfg.Policy.validate(); err != nil {
		return cfg, err
	}
```

После функции `LoadRiskConfig` добавить:

```go
// applyRiskEnv lets SCANNER_RISK_* variables override risk-config.yaml, as the deployed image does.
func applyRiskEnv(r *RiskConfigData) error {
	if v := strings.TrimSpace(os.Getenv("SCANNER_RISK_ENABLED")); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("SCANNER_RISK_ENABLED: %w", err)
		}
		r.Enabled = enabled
	}
	if v := strings.TrimSpace(os.Getenv("SCANNER_RISK_MODE")); v != "" {
		r.Mode = strings.ToLower(v)
	}
	numbers := []struct {
		name string
		dst  *float64
	}{
		{"SCANNER_RISK_CRITICAL", &r.Thresholds.Critical},
		{"SCANNER_RISK_HIGH", &r.Thresholds.High},
		{"SCANNER_RISK_MEDIUM", &r.Thresholds.Medium},
		{"SCANNER_RISK_LOW", &r.Thresholds.Low},
		{"SCANNER_RISK_CVSS_CRITICAL", &r.CVSSThresholds.Critical},
		{"SCANNER_RISK_CVSS_HIGH", &r.CVSSThresholds.High},
		{"SCANNER_RISK_CVSS_MEDIUM", &r.CVSSThresholds.Medium},
		{"SCANNER_RISK_CVSS_LOW", &r.CVSSThresholds.Low},
		{"SCANNER_RISK_DEFAULT_EPSS", &r.Defaults.EPSS},
		{"SCANNER_RISK_DEFAULT_CVSS", &r.Defaults.CVSS},
	}
	for _, n := range numbers {
		v := strings.TrimSpace(os.Getenv(n.name))
		if v == "" {
			continue
		}
		x, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("%s: %w", n.name, err)
		}
		*n.dst = x
	}
	switch r.Mode {
	case "formula", "cvss", "policy":
		return nil
	}
	return fmt.Errorf("SCANNER_RISK_MODE: unknown mode %q, expected formula, cvss or policy", r.Mode)
}
```

- [ ] **Step 4: Прогнать тесты**

Run: `go test ./pkg/etc/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/etc
git add pkg/etc
git commit -m "feat(config): policy thresholds, Exploit-DB file and SCANNER_RISK_* overrides

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Отчёт — строка на каждую находку и режим `policy`

Сейчас для каждой уязвимости берётся пакет первой находки с тем же ID, поэтому у CVE в libcrypto3, libssl3 и openssl все строки получают libcrypto3. Новый цикл идёт по `report.Matches`.

**Files:**
- Modify: `pkg/scan/transformer.go`
- Modify: `pkg/scan/transformer_test.go` (последний тест)
- Create: `pkg/scan/transformer_policy_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/scan/transformer_policy_test.go`

```go
package scan

import (
	"testing"

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

func policyTransformer(exploits policy.ExploitLookup) Transformer {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{Enabled: true, Mode: "policy"}}
	return NewTransformer(&SystemClock{}, config, policyThresholds, exploits)
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
	report := grype.Report{Matches: []grype.Match{
		{
			Vulnerability: grype.Vulnerability{
				ID: "GHSA-83qj-6fr2-vhqg", Severity: "Critical", Risk: 98.7,
				Description:    "Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT",
				URLs:           []string{"https://github.com/advisories/GHSA-83qj-6fr2-vhqg"},
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
	assert.Equal(t, "Critical: есть в каталоге KEV с 2025-04-01; есть эксплойт в Exploit-DB (52134); риск grype 98.7."+
		" — Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT", tomcat.Description)
	assert.Equal(t, []string{"https://github.com/advisories/GHSA-83qj-6fr2-vhqg", "https://www.exploit-db.com/exploits/52134"}, tomcat.Links)

	assert.Equal(t, harbor.SevHigh, golang.Severity)
	assert.Equal(t, "High: риск grype 69.0, порог High от 30 (EPSS 92%, критичность grype High); эксплойтов не найдено; в KEV нет."+
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
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/scan/`
Expected: FAIL, `too many arguments in call to NewTransformer`.

- [ ] **Step 3: Реализация в `pkg/scan/transformer.go`**

Импорты заменить на:

```go
import (
	"fmt"
	"slices"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/policy"
)
```

Тип `transformer` и `NewTransformer` заменить на:

```go
type transformer struct {
	clock      Clock
	config     etc.RiskConfig
	thresholds policy.Thresholds
	exploits   policy.ExploitLookup
}

// NewTransformer builds Harbor reports from grype output. exploits may be nil: the policy then
// finds exploits only through vulnerability links.
func NewTransformer(clock Clock, config etc.RiskConfig, thresholds policy.Thresholds, exploits policy.ExploitLookup) Transformer {
	return &transformer{
		clock:      clock,
		config:     config,
		thresholds: thresholds,
		exploits:   exploits,
	}
}
```

Метод `Transform` заменить целиком (со строки `func (t *transformer) Transform(` до закрывающей скобки перед `func mapGrypeSeverityToHarbor`):

```go
func (t *transformer) Transform(mediaType api.MediaType, request harbor.ScanRequest, report grype.Report) *harbor.ScanReport {
	scanReport := &harbor.ScanReport{
		GeneratedAt: t.clock.Now(),
		Artifact:    request.Artifact,
		Scanner:     harbor.GetScannerMetadata(),
	}

	if mediaType == api.MediaTypeSPDX || mediaType == api.MediaTypeCycloneDX {
		scanReport.MediaType = mediaType
		scanReport.SBOM = report.SBOM
		return scanReport
	}

	// One Harbor item per grype match: a CVE found in libcrypto3, libssl3 and openssl is three
	// items, each with its own package.
	var vulnerabilities []harbor.VulnerabilityItem
	var maxSeverity harbor.Severity
	for _, match := range report.Matches {
		item := t.toItem(match)
		if item.Severity > maxSeverity {
			maxSeverity = item.Severity
		}
		vulnerabilities = append(vulnerabilities, item)
	}

	scanReport.Vulnerabilities = vulnerabilities
	scanReport.Severity = maxSeverity
	return scanReport
}

func (t *transformer) toItem(match grype.Match) harbor.VulnerabilityItem {
	vuln := match.Vulnerability
	item := harbor.VulnerabilityItem{
		ID:          vuln.ID,
		Pkg:         match.Artifact.Name,
		Version:     match.Artifact.Version,
		Description: vuln.Description,
		Links:       vuln.URLs,
	}
	if len(vuln.Fix.Versions) > 0 {
		item.FixVersion = vuln.Fix.Versions[0]
	}

	switch {
	case !t.config.Risk.Enabled:
		item.Severity = mapGrypeSeverityToHarbor(vuln.Severity)
	case t.config.Risk.Mode == "policy":
		res := policy.Evaluate(match, t.exploits, t.thresholds)
		item.Severity = res.Severity
		item.Description = withReason(res.Reason, vuln.Description)
		item.Links = appendMissing(vuln.URLs, res.Links)
	default:
		severity, info := t.calculateSeverityWithInfo(vuln)
		item.Severity = severity
		item.Description = vuln.Description + info
	}

	if len(vuln.Cvss) > 0 {
		cvss := vuln.Cvss[0] // Use first CVSS entry
		item.PreferredCVSS = &harbor.CVSSDetails{
			VectorV2: cvss.Vector,
			VectorV3: cvss.Vector,
		}
		if cvss.Version == "2.0" {
			score := float32(cvss.Metrics.BaseScore)
			item.PreferredCVSS.ScoreV2 = &score
		} else if cvss.Version == "3.0" || cvss.Version == "3.1" {
			score := float32(cvss.Metrics.BaseScore)
			item.PreferredCVSS.ScoreV3 = &score
		}
	}
	return item
}

// withReason puts the explanation in front of the description; Harbor shows both as one paragraph.
func withReason(reason, description string) string {
	if description == "" {
		return reason
	}
	return reason + " — " + description
}

func appendMissing(links, extra []string) []string {
	out := append([]string(nil), links...)
	for _, link := range extra {
		if !slices.Contains(out, link) {
			out = append(out, link)
		}
	}
	return out
}
```

`fmt` остаётся нужен для старых режимов (`calculateRiskBasedSeverityWithInfo`).

- [ ] **Step 4: Обновить последний тест в `pkg/scan/transformer_test.go`**

Функцию `TestTransformWithRiskCalculation` заменить целиком:

```go
func TestTransformWithRiskCalculation(t *testing.T) {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{
		Mode:    "formula",
		Enabled: true,
		Thresholds: etc.RiskThresholds{
			Critical: 75.0,
			High:     50.0,
			Medium:   25.0,
			Low:      10.0,
		},
		Defaults: etc.RiskDefaults{
			EPSS: 0.1,
			CVSS: 5.0,
		},
	}}

	transformer := NewTransformer(&SystemClock{}, config, policy.Thresholds{}, nil)

	request := harbor.ScanRequest{
		Artifact: harbor.Artifact{
			Repository: "test/repo",
			Digest:     "sha256:1234567890",
		},
	}

	report := grype.Report{
		Matches: []grype.Match{{
			Vulnerability: grype.Vulnerability{
				ID: "CVE-2023-1234",
				EPSS: []grype.EPSS{
					{Score: 0.9}, // 90% EPSS
				},
				Cvss: []grype.Cvss{
					{
						Version: "3.1",
						Metrics: grype.Metrics{
							BaseScore: 9.0, // High CVSS
						},
					},
				},
			},
			Artifact: grype.Artifact{Name: "libssl3", Version: "3.0.11"},
		}},
	}

	// Use any MediaType that's not SPDX or CycloneDX to trigger vulnerability processing
	result := transformer.Transform("application/vnd.security.vulnerability.report", request, report)

	assert.NotNil(t, result)
	assert.Equal(t, harbor.SevCritical, result.Severity)
	assert.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, harbor.SevCritical, result.Vulnerabilities[0].Severity)
	assert.Equal(t, "libssl3", result.Vulnerabilities[0].Pkg)
}
```

В импорты `pkg/scan/transformer_test.go` добавить `"github.com/aquasecurity/harbor-scanner-grype/pkg/policy"`.

- [ ] **Step 5: Прогнать тесты**

Run: `go test ./pkg/...`
Expected: все `ok`. Сборка `main.go` пока падает: это следующая задача.

- [ ] **Step 6: Commit**

```bash
gofmt -w pkg/scan
git add pkg/scan
git commit -m "feat(scan): one report item per grype match and the policy mode

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Подключение в `main.go`

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Убедиться, что сборка падает**

Run: `go build ./...`
Expected: FAIL, `not enough arguments in call to scan.NewTransformer`.

- [ ] **Step 2: Реализация**

В импорты `main.go` добавить `"time"`, `"github.com/aquasecurity/harbor-scanner-grype/pkg/exploitdb"` и `"github.com/aquasecurity/harbor-scanner-grype/pkg/policy"`.

Строки

```go
	// Create transformer
	transformer := scan.NewTransformer(&scan.SystemClock{}, config.Risk)
```

заменить на:

```go
	// Create transformer. The Exploit-DB list is only read in the policy mode.
	var exploits policy.ExploitLookup
	if config.Risk.Risk.Enabled && config.Risk.Risk.Mode == "policy" {
		exploits = exploitdb.NewWatcher(config.Policy.ExploitDBFile, time.Minute, config.Policy.ExploitDBMaxAge)
		slog.Info("Severity policy enabled",
			slog.Float64("critical_from", config.Policy.Critical),
			slog.Float64("high_from", config.Policy.High),
			slog.Float64("medium_from", config.Policy.Medium))
	}
	transformer := scan.NewTransformer(&scan.SystemClock{}, config.Risk, policy.Thresholds{
		Critical: config.Policy.Critical,
		High:     config.Policy.High,
		Medium:   config.Policy.Medium,
	}, exploits)
```

- [ ] **Step 3: Проверить сборку, vet и тесты**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: сборка и vet без вывода, тесты `ok`.

- [ ] **Step 4: Commit**

```bash
gofmt -w main.go
git add main.go
git commit -m "feat: wire the Exploit-DB list and policy thresholds

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Проверка на настоящих отчётах grype

Нужно убедиться, что множитель критичности совпадает с grype на реальных данных и что каждая реальная находка получает внятное пояснение. Отчёты делает grype 0.117.0 из образа комплекта со своей базой, без сети, по локальным образам `redis:7-alpine` (Alpine) и `redis:7` (Debian).

**Files:**
- Create: `pkg/policy/testdata/grype-redis-7-alpine.json`
- Create: `pkg/policy/testdata/grype-redis-7.json`
- Create: `pkg/policy/realdata_test.go`

- [ ] **Step 1: Загрузить образ из комплекта**

Run: `docker load -i /Users/kp/harbor-scanner-grype/harbor-scanner-grype-amd64.tar.gz`
Expected: `Loaded image: ant1freeze/harbor-scanner-grype:latest`

- [ ] **Step 2: Получить отчёты grype**

```bash
FIX=$(mktemp -d)
for img in redis:7-alpine redis:7; do
  name=$(echo "$img" | tr ':/' '--')
  docker save "$img" -o "$FIX/$name.tar"
  docker run --rm --platform linux/amd64 --network none -e GRYPE_DB_VALIDATE_AGE=false \
    -v "$FIX":/in:ro --entrypoint grype ant1freeze/harbor-scanner-grype:latest \
    "docker-archive:/in/$name.tar" -o json > "$FIX/grype-$name.json"
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1], len(d['matches']), 'matches')" "$FIX/grype-$name.json"
done
echo "$FIX"
```

Expected: у каждого отчёта ненулевое число находок.

- [ ] **Step 3: Сократить отчёты до полей, которые читает коннектор**

```bash
python3 - "$FIX" <<'EOF'
import json, pathlib, sys
src = pathlib.Path(sys.argv[1])
dst = pathlib.Path("pkg/policy/testdata"); dst.mkdir(parents=True, exist_ok=True)
def cvss(items):
    return [{"version": c.get("version"), "vector": c.get("vector"),
             "metrics": {"baseScore": (c.get("metrics") or {}).get("baseScore", 0)}} for c in items or []]
for f in sorted(src.glob("grype-*.json")):
    doc = json.loads(f.read_text())
    out = []
    for m in doc["matches"]:
        v = m["vulnerability"]
        out.append({
            "vulnerability": {k: v.get(k) for k in ("id", "severity", "urls", "epss", "knownExploited", "cwes", "fix", "risk") if v.get(k) is not None}
                             | {"description": (v.get("description") or "")[:200], "cvss": cvss(v.get("cvss"))},
            "relatedVulnerabilities": [{"id": r.get("id"), "urls": r.get("urls") or [], "cvss": cvss(r.get("cvss"))}
                                       for r in m.get("relatedVulnerabilities") or []],
            "artifact": {k: m["artifact"].get(k) for k in ("name", "version", "type")},
        })
    (dst / f.name).write_text(json.dumps({"matches": out}, ensure_ascii=False, indent=1))
    print(dst / f.name, len(out))
EOF
ls -la pkg/policy/testdata/
```

Expected: два файла `grype-redis-7-alpine.json` и `grype-redis-7.json` по несколько сотен КБ или меньше.

- [ ] **Step 4: Написать тест** `pkg/policy/realdata_test.go`

```go
package policy

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

func realMatches(t *testing.T) []grype.Match {
	t.Helper()
	files, err := filepath.Glob("testdata/grype-*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files, "run Task 12 of the plan to create the fixtures")
	var all []grype.Match
	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		var doc struct {
			Matches []grype.Match `json:"matches"`
		}
		require.NoError(t, json.Unmarshal(data, &doc), file)
		all = append(all, doc.Matches...)
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

func TestEvaluateExplainsEveryRealFinding(t *testing.T) {
	for _, m := range realMatches(t) {
		res := Evaluate(m, nil, Thresholds{Critical: 70, High: 30, Medium: 10})
		assert.True(t, strings.HasPrefix(res.Reason, res.Severity.String()+": "), res.Reason)
		assert.True(t, strings.HasSuffix(res.Reason, "."), res.Reason)
		assert.LessOrEqual(t, utf8.RuneCountInString(res.Reason), 300, res.Reason)
	}
}
```

- [ ] **Step 5: Прогнать тест**

Run: `go test ./pkg/policy/ -run 'Real' -v 2>&1 | tail -10`
Expected: `PASS` для обоих тестов. Если `TestSeverityFactorAgreesWithGrypeOnRealScans` падает, остановиться и разобрать расхождение: пересчёт для бюллетеней в этом случае неверен.

- [ ] **Step 6: Посмотреть распределение уровней на реальных данных**

```bash
cat > /tmp/levels_test.go <<'EOF'
package policy

import (
	"fmt"
	"testing"
)

func TestPrintLevels(t *testing.T) {
	counts := map[string]int{}
	for _, m := range realMatches(t) {
		res := Evaluate(m, nil, Thresholds{Critical: 70, High: 30, Medium: 10})
		counts[res.Severity.String()]++
		if res.Severity.String() == "Critical" || res.Severity.String() == "High" {
			fmt.Println(m.Vulnerability.ID, m.Artifact.Name, "|", res.Reason)
		}
	}
	fmt.Println(counts)
}
EOF
cp /tmp/levels_test.go pkg/policy/levels_test.go
go test ./pkg/policy/ -run TestPrintLevels -v 2>&1 | tail -40
rm pkg/policy/levels_test.go
```

Expected: распределение, где Low больше всего, а у находок High и Critical осмысленные пояснения. Вывод сохранить для отчёта пользователю.

- [ ] **Step 7: Commit**

```bash
gofmt -w pkg/policy
git add pkg/policy/testdata pkg/policy/realdata_test.go
git commit -m "test(policy): check the rules on real grype reports

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 13: Документация режима

**Files:**
- Modify: `RISK_CALCULATION.md`

- [ ] **Step 1: Добавить раздел в конец `RISK_CALCULATION.md`**

```markdown
## Policy mode (`SCANNER_RISK_MODE=policy`)

Levels come from five rules, checked in this order for every grype finding (vulnerability + package):

1. **KEV** — the CVE is in the CISA Known Exploited Vulnerabilities catalogue: **Critical**.
2. **Malicious code** — a GitHub "Malware in …" advisory or CWE-506: **Critical**.
3. **Risk ladder** — grype's own risk score (the RISK column of `grype` output, 0–100):
   from `SCANNER_POLICY_CRITICAL` (70) Critical, from `SCANNER_POLICY_HIGH` (30) High,
   from `SCANNER_POLICY_MEDIUM` (10) Medium, below that Low. For advisories that bundle several CVEs
   (ALAS, ELSA) grype uses the EPSS of the first CVE; the policy uses the highest one instead.
4. **No EPSS** — grype's severity, capped at High (no data about attacks, so never Critical).
5. **Public exploit** (Exploit-DB or a proof-of-concept link) raises levels below High: to High when the
   flaw is reachable over the network and grype rates it High or Critical, otherwise to at least Medium.

The reason is written in front of the vulnerability description in Harbor, for example:

    High: риск grype 69.0, порог High от 30 (EPSS 92%, критичность grype High); эксплойтов не найдено; в KEV нет. — An attacker may cause…

Links to the Exploit-DB exploits found are added to the vulnerability links.

| Variable | Default | Meaning |
|---|---|---|
| `SCANNER_RISK_ENABLED` | from `risk-config.yaml` | `false` shows grype's own severity |
| `SCANNER_RISK_MODE` | from `risk-config.yaml` | `policy`, `formula` or `cvss` |
| `SCANNER_POLICY_CRITICAL`, `_HIGH`, `_MEDIUM` | 70, 30, 10 | risk thresholds of the ladder |
| `SCANNER_EXPLOITDB_FILE` | `/home/scanner/.cache/exploitdb/files_exploits.csv` | Exploit-DB list |
| `SCANNER_EXPLOITDB_MAX_AGE` | `336h` | older lists are reported in the log |

The Exploit-DB list is re-read within a minute after the nightly job replaces it. Without the list,
exploits are found only through vulnerability links.
```

- [ ] **Step 2: Финальная проверка**

Run: `gofmt -l . ; go vet ./... && go test ./...`
Expected: `gofmt -l` ничего не выводит, vet без замечаний, все тесты `ok`.

- [ ] **Step 3: Commit**

```bash
git add RISK_CALCULATION.md
git commit -m "docs: describe the policy mode

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Что дальше

- **План 2 — сборка, паритет с образом из комплекта и безопасность.** Двухэтапный Dockerfile, скрипты из образа, ночная загрузка Exploit-DB и копия в образе, переменные из раздела 2.3 спецификации, подмена адреса реестра, `SCANNER_LOG_FORMAT`, ключ API, учётные данные реестра, метаданные с датой базы, `docker-compose.yml`, `env.example`.
- **План 3 — надёжная очередь.** Списки Redis вместо Pub/Sub, возврат прерванных заданий, отметка ожидания Harbor, сроки хранения, отдельные временные каталоги, таймаут, события сканов в логе.

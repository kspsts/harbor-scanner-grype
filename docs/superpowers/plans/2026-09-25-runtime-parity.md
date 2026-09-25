# План 2. Сборка, паритет с образом из комплекта и безопасность

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Коннектор из репозитория собирается из исходников, ведёт себя как образ из комплекта (адреса реестра, TLS, логи, таймауты, временные файлы, cron базы) и закрывает найденные дыры: ключ API, учётные данные реестра, пароли в логах.

**Architecture:** Настройки из раздела 2.3 спецификации — в `pkg/etc`. Подмена адреса реестра — в `harbor.ScanRequest.GetImageRef`. Выбор учётных данных — в `scan.controller`. Запуск grype и syft переписан в `pkg/grype/wrapper.go`: таймаут, свой временный каталог, отчёт только из stdout, настройки реестра через переменные окружения, в логах без секретов. Ключ API — middleware на `/api/v1`. Сборка — двухэтапный Dockerfile, скрипты перенесены из образа комплекта.

**Tech Stack:** Go 1.22 (`GOTOOLCHAIN=go1.22.12`), testify, caarlos0/env v6, gorilla/mux, busybox sh, Docker BuildKit.

**Спецификация:** `docs/superpowers/specs/2026-09-25-policy-mode-design.md`, разделы 2.1–2.4, 2.6, 7, 8, 10.

**Зависит от плана 1**, он выполнен целиком. Очередь (раздел 2.5) — план 3.

**Окружение.** Команды выполняются из `/Users/kp/harbor-scanner-grype-src`. Каждую команду go/gofmt предварять `GOTOOLCHAIN=go1.22.12`. Коммиты — в `feature/policy-mode`, с последней строкой `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. `gofmt -w` — только по изменённым файлам: в репозитории есть неотформатированные файлы, к задаче не относящиеся.

## Файлы

| Файл | Что меняется |
|---|---|
| `pkg/etc/config.go`, `pkg/etc/config_test.go` | `Registry`, `HostMap`, `API.Key`, `Grype.TmpDir`, значения по умолчанию, `LogFormat` |
| `pkg/etc/log.go`, `pkg/etc/log_test.go` | обработчик логов text/json |
| `pkg/harbor/model.go`, `pkg/harbor/model_test.go` | `GetImageRef(hostMap)` |
| `pkg/scan/controller.go`, `pkg/scan/controller_test.go` | выбор учётных данных, без секретов в логах |
| `pkg/grype/wrapper.go`, `pkg/grype/wrapper_test.go`, `pkg/grype/testdata/fake-scanner.sh` | запуск grype и syft, `DBStatus`, `RemoveStaleTempDirs` |
| `pkg/http/api/v1/handler.go`, `pkg/http/api/v1/handler_test.go` | ключ API, дата базы в метаданных |
| `main.go` | подключение |
| `Dockerfile`, `.dockerignore`, `.gitignore`, `start.sh`, `update-grype-db.sh`, `update-exploitdb.sh`, `test/update-exploitdb_test.sh` | сборка и скрипты |
| `docker-compose.yml`, `.env.example`, `deploy.sh`, `INSTALL.md` | установка |

---

### Task 1: Настройки реестра, логов, таймаутов и ключ API

**Files:**
- Modify: `pkg/etc/config.go`
- Modify: `pkg/etc/config_test.go`

- [ ] **Step 1: Дописать и поправить тесты** в `pkg/etc/config_test.go`

Все тесты, которые вызывают `GetConfig()` (`TestGetConfig`, `TestPolicyDefaults`, `TestRiskEnvOverridesFile`, `TestRiskModeMustBeKnown`, `TestPolicyThresholdsMustBeOrdered`), первой строкой получают `t.Setenv("SCANNER_API_KEY", "test-key")`.

В `TestGrypeConfigDefaults` строку `assert.Equal(t, 5*time.Minute, config.Timeout)` заменить на:

```go
	assert.Equal(t, 15*time.Minute, config.Timeout)
	assert.Equal(t, "/tmp/scanner", config.TmpDir)
```

В конец файла добавить:

```go
func TestRegistryDefaults(t *testing.T) {
	t.Setenv("SCANNER_API_KEY", "test-key")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.True(t, config.Registry.InsecureUseHTTP)
	assert.True(t, config.Registry.InsecureSkipTLSVerify)
	assert.Empty(t, config.Registry.HostMap)
	assert.Empty(t, config.Registry.TrustedHosts)
	assert.Equal(t, 5*time.Second, config.RedisPool.ReadTimeout)
}

func TestHostMap(t *testing.T) {
	t.Setenv("SCANNER_API_KEY", "test-key")
	t.Setenv("SCANNER_REGISTRY_HOST_MAP", "localhost=nginx:8080, Harbor.Corp.Local=harbor.corp.local:443")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, HostMap{"localhost": "nginx:8080", "harbor.corp.local": "harbor.corp.local:443"}, config.Registry.HostMap)
}

func TestHostMapRejectsMalformedPairs(t *testing.T) {
	t.Setenv("SCANNER_API_KEY", "test-key")
	t.Setenv("SCANNER_REGISTRY_HOST_MAP", "localhost")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_REGISTRY_HOST_MAP")
}

func TestTrustedHosts(t *testing.T) {
	t.Setenv("SCANNER_API_KEY", "test-key")
	t.Setenv("SCANNER_REGISTRY_TRUSTED_HOSTS", "harbor.corp.local, core")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.True(t, config.Registry.Trusted("HARBOR.corp.local"))
	assert.True(t, config.Registry.Trusted("core"))
	assert.False(t, config.Registry.Trusted("evil.example.com"))
	assert.False(t, config.Registry.Trusted(""))
}

func TestAPIKeyIsRequired(t *testing.T) {
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_API_KEY")
}

func TestLogFormat(t *testing.T) {
	t.Setenv("SCANNER_LOG_FORMAT", "JSON")
	assert.Equal(t, "json", LogFormat())
	t.Setenv("SCANNER_LOG_FORMAT", "")
	assert.Equal(t, "text", LogFormat())
}
```

- [ ] **Step 2: Убедиться, что тесты не компилируются**

Run: `go test ./pkg/etc/`
Expected: FAIL, `config.Registry undefined`, `undefined: HostMap`, `undefined: LogFormat`.

- [ ] **Step 3: Реализация в `pkg/etc/config.go`**

В импорты добавить `"errors"` (если его нет).

В `Config` после `RedisPool RedisPool` добавить поле `Registry Registry`.

В `Grype` значение по умолчанию таймаута поменять на `envDefault:"15m"` и после поля `Timeout` добавить:

```go
	TmpDir         string        `env:"SCANNER_GRYPE_TMP_DIR" envDefault:"/tmp/scanner"`
```

В `API` после `MetricsEnabled` добавить:

```go
	Key            string        `env:"SCANNER_API_KEY"`
```

В `RedisPool` у `ConnectionTimeout`, `ReadTimeout` и `WriteTimeout` поставить `envDefault:"5s"`.

После типа `RedisPool` добавить:

```go
// Registry configures how the scanner reaches the registry named in Harbor's scan request.
type Registry struct {
	HostMap               HostMap  `env:"SCANNER_REGISTRY_HOST_MAP"`
	InsecureUseHTTP       bool     `env:"SCANNER_REGISTRY_INSECURE_USE_HTTP" envDefault:"true"`
	InsecureSkipTLSVerify bool     `env:"SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY" envDefault:"true"`
	Username              string   `env:"SCANNER_REGISTRY_USERNAME"`
	Password              string   `env:"SCANNER_REGISTRY_PASSWORD"`
	TrustedHosts          []string `env:"SCANNER_REGISTRY_TRUSTED_HOSTS" envSeparator:","`
}

// Trusted reports whether the configured account may be sent to host.
func (r Registry) Trusted(host string) bool {
	if host == "" {
		return false
	}
	for _, trusted := range r.TrustedHosts {
		if strings.EqualFold(strings.TrimSpace(trusted), host) {
			return true
		}
	}
	return false
}

// HostMap maps a registry host from Harbor's scan request to the host[:port] the scanner connects
// to instead, from "host=target" pairs such as "localhost=nginx:8080,harbor.corp.local=harbor.corp.local:443".
type HostMap map[string]string

// UnmarshalText parses SCANNER_REGISTRY_HOST_MAP. Hosts are matched case-insensitively.
func (m *HostMap) UnmarshalText(text []byte) error {
	parsed := HostMap{}
	for _, pair := range strings.Split(string(text), ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		host, target, ok := strings.Cut(pair, "=")
		host, target = strings.TrimSpace(host), strings.TrimSpace(target)
		if !ok || host == "" || target == "" {
			return fmt.Errorf("SCANNER_REGISTRY_HOST_MAP: %q is not host=target", pair)
		}
		parsed[strings.ToLower(host)] = target
	}
	*m = parsed
	return nil
}
```

После функции `LogLevel` добавить:

```go
// LogFormat is "json" or "text", from SCANNER_LOG_FORMAT; text is the default.
func LogFormat() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SCANNER_LOG_FORMAT")), "json") {
		return "json"
	}
	return "text"
}
```

В `GetConfig` сразу после успешного `env.Parse(&cfg)` добавить:

```go
	if strings.TrimSpace(cfg.API.Key) == "" {
		return cfg, errors.New("SCANNER_API_KEY is required: set the same key in Harbor's scanner registration (Authorization: Bearer or API Key)")
	}
```

- [ ] **Step 4: Прогнать тесты**

Run: `go test ./pkg/etc/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/etc/config.go pkg/etc/config_test.go
git add pkg/etc/config.go pkg/etc/config_test.go
git commit -m "feat(config): registry access, API key, 15m timeout and temp dir as in the deployed image

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Формат логов

**Files:**
- Create: `pkg/etc/log.go`
- Create: `pkg/etc/log_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/etc/log_test.go`

```go
package etc

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTextLogs(t *testing.T) {
	t.Setenv("SCANNER_LOG_FORMAT", "text")
	var buf bytes.Buffer
	slog.New(NewLogHandler(&buf)).Info("Scan finished", slog.Int("vulnerabilities", 3))
	line := buf.String()
	assert.True(t, strings.HasPrefix(line, "time="), line)
	assert.Contains(t, line, `level=INFO msg="Scan finished" vulnerabilities=3`)
}

func TestJSONLogs(t *testing.T) {
	t.Setenv("SCANNER_LOG_FORMAT", "json")
	var buf bytes.Buffer
	slog.New(NewLogHandler(&buf)).Info("Scan finished", slog.Int("vulnerabilities", 3))
	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "Scan finished", entry["msg"])
	assert.Equal(t, float64(3), entry["vulnerabilities"])
}

func TestLogLevelFiltersDebug(t *testing.T) {
	t.Setenv("SCANNER_LOG_LEVEL", "info")
	var buf bytes.Buffer
	slog.New(NewLogHandler(&buf)).Debug("noise")
	assert.Empty(t, buf.String())
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/etc/`
Expected: FAIL, `undefined: NewLogHandler`.

- [ ] **Step 3: Реализация** `pkg/etc/log.go`

```go
package etc

import (
	"io"
	"log/slog"
)

// NewLogHandler returns the log handler for SCANNER_LOG_FORMAT and SCANNER_LOG_LEVEL: readable
// key=value lines with a timestamp, or one JSON object per line for log collectors.
func NewLogHandler(w io.Writer) slog.Handler {
	opts := &slog.HandlerOptions{Level: LogLevel()}
	if LogFormat() == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}
```

- [ ] **Step 4: Прогнать тесты**

Run: `go test ./pkg/etc/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/etc/log.go pkg/etc/log_test.go
git add pkg/etc/log.go pkg/etc/log_test.go
git commit -m "feat(log): SCANNER_LOG_FORMAT text or json

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Подмена адреса реестра

Сейчас подмена `localhost` на `nginx:8080` и `harbor.corp.local` зашита в `GetImageRef`, а ещё он печатает отладку через `fmt.Printf`. Правило из спецификации (2.4): хост из запроса Harbor сравнивается без учёта регистра, порт при этом не сравнивается; цель без порта сохраняет порт из запроса.

**Files:**
- Modify: `pkg/harbor/model.go`
- Create: `pkg/harbor/model_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/harbor/model_test.go`

```go
package harbor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func request(url string) ScanRequest {
	return ScanRequest{
		Registry: Registry{URL: url},
		Artifact: Artifact{Repository: "library/nginx", Digest: "sha256:abc"},
	}
}

func TestGetImageRef(t *testing.T) {
	hostMap := map[string]string{
		"localhost":         "nginx:8080",
		"harbor.corp.local": "harbor.corp.local:443",
		"core":              "registry",
	}
	tests := []struct {
		url    string
		ref    string
		nonSSL bool
	}{
		{"https://harbor.example.com", "harbor.example.com:443/library/nginx@sha256:abc", false},
		{"http://harbor.example.com", "harbor.example.com:80/library/nginx@sha256:abc", true},
		{"https://harbor.example.com:8443", "harbor.example.com:8443/library/nginx@sha256:abc", false},
		{"http://localhost", "nginx:8080/library/nginx@sha256:abc", true},
		{"https://Harbor.Corp.Local", "harbor.corp.local:443/library/nginx@sha256:abc", false},
		{"http://core:8080", "registry:8080/library/nginx@sha256:abc", true},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			ref, nonSSL, err := request(tt.url).GetImageRef(hostMap)
			require.NoError(t, err)
			assert.Equal(t, tt.ref, ref)
			assert.Equal(t, tt.nonSSL, nonSSL)
		})
	}
}

func TestGetImageRefWithoutMap(t *testing.T) {
	ref, _, err := request("http://localhost").GetImageRef(nil)
	require.NoError(t, err)
	assert.Equal(t, "localhost:80/library/nginx@sha256:abc", ref, "nothing is rewritten unless configured")
}

func TestGetImageRefRejectsBadURL(t *testing.T) {
	_, _, err := request("http://[::1").GetImageRef(nil)
	assert.ErrorContains(t, err, "parsing registry URL")
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/harbor/`
Expected: FAIL, `too many arguments in call to request(tt.url).GetImageRef`.

- [ ] **Step 3: Реализация**

В `pkg/harbor/model.go` в импорты добавить `"net"` и `"strings"` (если их нет). Функцию `GetImageRef` заменить целиком:

```go
// GetImageRef returns the reference grype and syft pull, host:port/repository@digest, and whether the
// registry speaks plain HTTP. hostMap (SCANNER_REGISTRY_HOST_MAP) replaces the registry host from
// Harbor's request with a host[:port] the scanner can reach; a target without a port keeps the port.
func (c ScanRequest) GetImageRef(hostMap map[string]string) (imageRef string, nonSSL bool, err error) {
	registryURL, err := url.Parse(c.Registry.URL)
	if err != nil {
		return "", false, fmt.Errorf("parsing registry URL: %w", err)
	}

	host, port := registryURL.Hostname(), registryURL.Port()
	if port == "" {
		switch registryURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	if target, ok := hostMap[strings.ToLower(host)]; ok {
		if targetHost, targetPort, splitErr := net.SplitHostPort(target); splitErr == nil {
			host, port = targetHost, targetPort
		} else {
			host = target
		}
	}

	if port == "" {
		imageRef = fmt.Sprintf("%s/%s@%s", host, c.Artifact.Repository, c.Artifact.Digest)
	} else {
		imageRef = fmt.Sprintf("%s:%s/%s@%s", host, port, c.Artifact.Repository, c.Artifact.Digest)
	}
	return imageRef, registryURL.Scheme == "http", nil
}
```

Если после замены `os` в импортах `pkg/harbor/model.go` не используется, убрать его (`go build` подскажет).

Единственный вызов — `pkg/scan/controller.go`: временно поменять `req.GetImageRef()` на `req.GetImageRef(nil)`. Настоящая карта приходит в Task 4.

- [ ] **Step 4: Прогнать тесты**

Run: `go build ./... && go test ./...`
Expected: сборка без ошибок, тесты `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/harbor/model.go pkg/harbor/model_test.go pkg/scan/controller.go
git add pkg/harbor/model.go pkg/harbor/model_test.go pkg/scan/controller.go
git commit -m "feat(harbor): SCANNER_REGISTRY_HOST_MAP instead of hard-coded registry hosts

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Учётные данные реестра

Правило из раздела 8 спецификации. Basic от Harbor используется как есть. Bearer или пустое значение — своя учётка, но только для хостов из `SCANNER_REGISTRY_TRUSTED_HOSTS`. Иначе Bearer передаётся grype как токен, а без учётных данных — анонимно. В лог не пишутся ни заголовок, ни пароль, ни токен.

**Files:**
- Modify: `pkg/scan/controller.go`
- Create: `pkg/scan/controller_test.go`
- Modify: `main.go` (вызов `NewController`)

- [ ] **Step 1: Написать падающий тест** `pkg/scan/controller_test.go`

```go
package scan

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func scanRequest(url, authorization string) harbor.ScanRequest {
	return harbor.ScanRequest{Registry: harbor.Registry{URL: url, Authorization: authorization}}
}

func TestRegistryAuth(t *testing.T) {
	registry := etc.Registry{Username: "robot$scanner", Password: "account-secret", TrustedHosts: []string{"harbor.corp.local"}}
	c := &controller{registry: registry}
	account := grype.BasicAuth{Username: "robot$scanner", Password: "account-secret"}

	tests := []struct {
		name string
		req  harbor.ScanRequest
		want grype.RegistryAuth
	}{
		{"Basic from Harbor is used as is", scanRequest("https://harbor.corp.local", basic("robot$harbor+scan", "p:a:ss")),
			grype.BasicAuth{Username: "robot$harbor+scan", Password: "p:a:ss"}},
		{"Bearer for a trusted host gets the account", scanRequest("https://harbor.corp.local", "Bearer harbor-token"), account},
		{"no credentials for a trusted host gets the account", scanRequest("https://HARBOR.corp.local", ""), account},
		{"Bearer for another host stays a token", scanRequest("https://evil.example.com", "Bearer harbor-token"),
			grype.BearerAuth{Token: "harbor-token"}},
		{"no credentials for another host stays anonymous", scanRequest("https://evil.example.com", ""), grype.NoAuth{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.registryAuth(tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRegistryAuthWithoutAccount(t *testing.T) {
	c := &controller{registry: etc.Registry{TrustedHosts: []string{"harbor.corp.local"}}}
	got, err := c.registryAuth(scanRequest("https://harbor.corp.local", ""))
	require.NoError(t, err)
	assert.Equal(t, grype.NoAuth{}, got)
}

func TestRegistryAuthRejectsUnknownScheme(t *testing.T) {
	c := &controller{}
	_, err := c.registryAuth(scanRequest("https://harbor.corp.local", "Digest abc"))
	assert.ErrorContains(t, err, "unrecognized authorization type")
}

func TestRegistryAuthDoesNotLogSecrets(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	c := &controller{registry: etc.Registry{Username: "robot$scanner", Password: "account-secret", TrustedHosts: []string{"harbor.corp.local"}}}
	_, _ = c.registryAuth(scanRequest("https://harbor.corp.local", basic("robot$harbor+scan", "harbor-secret")))
	_, _ = c.registryAuth(scanRequest("https://harbor.corp.local", "Bearer harbor-token"))
	_, _ = c.registryAuth(scanRequest("https://other.example.com", "Bearer harbor-token"))

	for _, secret := range []string{"harbor-secret", "account-secret", "harbor-token", basic("robot$harbor+scan", "harbor-secret")} {
		assert.NotContains(t, buf.String(), secret)
	}
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/scan/`
Expected: FAIL, `unknown field registry in struct literal of type controller`.

- [ ] **Step 3: Реализация в `pkg/scan/controller.go`**

В импорты добавить `"net/url"` и `"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"`.

Тип `controller` и `NewController` заменить на:

```go
type controller struct {
	store       persistence.Store
	wrapper     grype.Wrapper
	transformer Transformer
	registry    etc.Registry
}

func NewController(store persistence.Store, wrapper grype.Wrapper, transformer Transformer, registry etc.Registry) Controller {
	return &controller{
		store:       store,
		wrapper:     wrapper,
		transformer: transformer,
		registry:    registry,
	}
}
```

В методе `scan` вызов `slog.Info("Received scan request from Harbor", …)` заменить на вариант без заголовка авторизации:

```go
	slog.Info("Received scan request from Harbor",
		slog.String("registry_url", req.Registry.URL),
		slog.String("artifact_repository", req.Artifact.Repository),
		slog.String("artifact_digest", req.Artifact.Digest),
		slog.String("artifact_mime_type", req.Artifact.MimeType),
		slog.Int("capabilities_count", len(req.Capabilities)),
	)
```

Там же `req.GetImageRef(nil)` заменить на `req.GetImageRef(c.registry.HostMap)`, а `auth, err := c.ToRegistryAuth(req.Registry.Authorization)` — на `auth, err := c.registryAuth(*req)`.

Методы `ToRegistryAuth` и `decodeBasicAuth` удалить и вместо них добавить:

```go
// registryAuth picks the credentials for the registry in Harbor's scan request. Harbor's Basic
// credentials are used as they are. When Harbor sends a Bearer token or nothing, the configured
// account is used, but only for SCANNER_REGISTRY_TRUSTED_HOSTS; any other host gets the token as it
// is, or no credentials. Secrets never reach the log.
func (c *controller) registryAuth(req harbor.ScanRequest) (grype.RegistryAuth, error) {
	host := ""
	if u, err := url.Parse(req.Registry.URL); err == nil {
		host = u.Hostname()
	}
	kind, value, _ := strings.Cut(strings.TrimSpace(req.Registry.Authorization), " ")
	useAccount := c.registry.Username != "" && c.registry.Trusted(host)

	var auth grype.RegistryAuth
	var source string
	switch {
	case strings.EqualFold(kind, "Basic"):
		decoded, err := decodeBasicAuth(value)
		if err != nil {
			return nil, err
		}
		auth, source = decoded, "Harbor (Basic)"
	case (kind == "" || strings.EqualFold(kind, "Bearer")) && useAccount:
		auth, source = grype.BasicAuth{Username: c.registry.Username, Password: c.registry.Password}, "SCANNER_REGISTRY_USERNAME"
	case strings.EqualFold(kind, "Bearer"):
		auth, source = grype.BearerAuth{Token: strings.TrimSpace(value)}, "Harbor (Bearer)"
	case kind == "":
		auth, source = grype.NoAuth{}, "none"
	default:
		return nil, xerrors.Errorf("unrecognized authorization type %q", kind)
	}
	slog.Debug("Registry credentials", slog.String("registry", host), slog.String("source", source))
	return auth, nil
}

func decodeBasicAuth(value string) (grype.RegistryAuth, error) {
	creds, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, xerrors.Errorf("decoding Basic credentials: %w", err)
	}
	user, pass, ok := strings.Cut(string(creds), ":")
	if !ok {
		return nil, xerrors.New("Basic credentials are not user:password")
	}
	return grype.BasicAuth{Username: user, Password: pass}, nil
}
```

В `main.go` вызов `scan.NewController(store, grypeWrapper, transformer)` заменить на `scan.NewController(store, grypeWrapper, transformer, config.Registry)`.

- [ ] **Step 4: Прогнать тесты**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: без ошибок, тесты `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/scan/controller.go pkg/scan/controller_test.go main.go
git add pkg/scan/controller.go pkg/scan/controller_test.go main.go
git commit -m "fix(scan): send the configured registry account only to trusted hosts, never log secrets

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Запуск grype и syft

Сейчас `wrapper.go`:
- пишет в лог все переменные окружения, включая пароль к реестру, и весь вывод grype;
- склеивает stdout со stderr и вырезает JSON между первой `{` и последней `}`;
- всегда выключает TLS к реестру;
- пытается звать `docker pull`, которого в образе нет;
- не ограничивает время скана.

Новый запуск:
- таймаут `SCANNER_GRYPE_TIMEOUT`;
- свой каталог в `SCANNER_GRYPE_TMP_DIR` (он передаётся как `TMPDIR`);
- отчёт только из stdout;
- настройки реестра из `etc.Registry`;
- в лог — только инструмент и аргументы.

С `--fail-on` grype 0.117 при найденных уязвимостях выходит с кодом 2 и полным отчётом в stdout; это не ошибка.

**Files:**
- Modify: `pkg/grype/wrapper.go` (переписать)
- Modify: `pkg/grype/wrapper_test.go` (переписать)
- Create: `pkg/grype/testdata/fake-scanner.sh`

- [ ] **Step 1: Поддельный сканер** `pkg/grype/testdata/fake-scanner.sh`

```sh
#!/bin/sh
# Stands in for grype and syft in tests: records its arguments and environment,
# then behaves as FAKE_MODE says.
printf '%s\n' "$@" > "$FAKE_LOG.args"
env > "$FAKE_LOG.env"
case "$FAKE_MODE" in
report)
	echo '{"matches":[{"vulnerability":{"id":"CVE-2024-0001","severity":"High","risk":12.5},"artifact":{"name":"openssl","version":"3.0.1"}}]}'
	;;
report-exit2)
	echo '{"matches":[]}'
	echo "[0002] ERROR discovered vulnerabilities at or above the severity threshold" >&2
	exit 2
	;;
fail)
	echo "[0001] ERROR unauthorized: authentication required" >&2
	exit 1
	;;
sleep)
	sleep 5
	;;
tmpdir)
	echo "{\"tmp\":\"$TMPDIR\"}"
	;;
dbstatus)
	echo '{"schemaVersion":"v6.1.9","from":"manual import","built":"2026-09-15T06:31:36Z","path":"/db","valid":false,"error":"the vulnerability database was built 1 week ago (max allowed age is 5 days)"}'
	exit 1
	;;
esac
```

Run: `chmod +x pkg/grype/testdata/fake-scanner.sh`

- [ ] **Step 2: Написать падающие тесты — заменить `pkg/grype/wrapper_test.go` целиком**

```go
package grype

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/ext"
)

// fakeAmbassador runs testdata/fake-scanner.sh in place of grype and syft.
type fakeAmbassador struct {
	ext.Ambassador
	mode string
	log  string
}

func (f fakeAmbassador) LookPath(string) (string, error) {
	return filepath.Abs("testdata/fake-scanner.sh")
}

func (f fakeAmbassador) Environ() []string {
	return []string{"PATH=/usr/bin:/bin", "FAKE_MODE=" + f.mode, "FAKE_LOG=" + f.log}
}

func newTestWrapper(t *testing.T, mode string, registry etc.Registry) (*wrapper, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "call")
	w := &wrapper{
		config:     etc.Grype{Timeout: 3 * time.Second, TmpDir: filepath.Join(dir, "tmp"), Severity: "Unknown,Low,Medium,High,Critical"},
		registry:   registry,
		ambassador: fakeAmbassador{mode: mode, log: log},
	}
	return w, log
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

var harborRef = ImageRef{Name: "harbor.corp.local:443/library/nginx@sha256:abc", Auth: BasicAuth{Username: "robot$scan", Password: "s3cr3t"}}

func TestScanParsesReportAndPassesRegistrySettings(t *testing.T) {
	w, log := newTestWrapper(t, "report", etc.Registry{InsecureUseHTTP: false, InsecureSkipTLSVerify: true})

	report, err := w.Scan(harborRef, ScanOption{Format: FormatJSON})

	require.NoError(t, err)
	require.Len(t, report.Matches, 1)
	assert.Equal(t, "CVE-2024-0001", report.Matches[0].Vulnerability.ID)
	assert.Equal(t, 12.5, report.Matches[0].Vulnerability.Risk)

	args := readLines(t, log+".args")
	assert.Equal(t, []string{"harbor.corp.local:443/library/nginx@sha256:abc", "--output", "json", "--fail-on", "negligible"}, args)

	env := readLines(t, log+".env")
	assert.Contains(t, env, "GRYPE_REGISTRY_INSECURE_USE_HTTP=false")
	assert.Contains(t, env, "GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true")
	assert.Contains(t, env, "GRYPE_REGISTRY_AUTH_AUTHORITY=harbor.corp.local:443")
	assert.Contains(t, env, "GRYPE_REGISTRY_AUTH_USERNAME=robot$scan")
	assert.Contains(t, env, "GRYPE_REGISTRY_AUTH_PASSWORD=s3cr3t")
}

func TestScanAcceptsExitCode2WithReport(t *testing.T) {
	w, _ := newTestWrapper(t, "report-exit2", etc.Registry{})
	_, err := w.Scan(harborRef, ScanOption{Format: FormatJSON})
	assert.NoError(t, err, "--fail-on makes grype exit with 2 when it finds vulnerabilities")
}

func TestScanFailureCarriesStderr(t *testing.T) {
	w, _ := newTestWrapper(t, "fail", etc.Registry{})
	_, err := w.Scan(harborRef, ScanOption{Format: FormatJSON})
	assert.ErrorContains(t, err, "unauthorized: authentication required")
}

func TestScanTimesOut(t *testing.T) {
	w, _ := newTestWrapper(t, "sleep", etc.Registry{})
	w.config.Timeout = 200 * time.Millisecond
	started := time.Now()
	_, err := w.Scan(harborRef, ScanOption{Format: FormatJSON})
	assert.ErrorContains(t, err, "scan timed out after 200ms")
	assert.Less(t, time.Since(started), 3*time.Second)
}

func TestEachRunHasItsOwnTempDirRemovedAfterwards(t *testing.T) {
	w, _ := newTestWrapper(t, "tmpdir", etc.Registry{})
	sbom, err := w.ScanSBOM(harborRef, ScanOption{Format: FormatSPDX})
	require.NoError(t, err)

	tmp := sbom.(map[string]any)["tmp"].(string)
	assert.True(t, strings.HasPrefix(tmp, filepath.Join(w.config.TmpDir, "scan-")), tmp)
	_, statErr := os.Stat(tmp)
	assert.True(t, os.IsNotExist(statErr), "the temp dir is removed after the run")
}

func TestSBOMUsesSyftSettingsAndBearerToken(t *testing.T) {
	w, log := newTestWrapper(t, "tmpdir", etc.Registry{InsecureUseHTTP: false, InsecureSkipTLSVerify: false})
	ref := ImageRef{Name: "registry:8080/library/nginx@sha256:abc", Auth: BearerAuth{Token: "harbor-token"}, NonSSL: true}

	_, err := w.ScanSBOM(ref, ScanOption{Format: FormatCycloneDX})
	require.NoError(t, err)

	assert.Equal(t, []string{"registry:8080/library/nginx@sha256:abc", "--output", "cyclonedx"}, readLines(t, log+".args"))
	env := readLines(t, log+".env")
	assert.Contains(t, env, "SYFT_REGISTRY_INSECURE_USE_HTTP=true", "a plain-HTTP registry from Harbor's request needs HTTP")
	assert.Contains(t, env, "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=false")
	assert.Contains(t, env, "SYFT_REGISTRY_AUTH_AUTHORITY=registry:8080")
	assert.Contains(t, env, "SYFT_REGISTRY_AUTH_TOKEN=harbor-token")
}

func TestDBStatusReadsInvalidDatabase(t *testing.T) {
	w, log := newTestWrapper(t, "dbstatus", etc.Registry{})
	status, err := w.DBStatus()
	require.NoError(t, err)
	assert.Equal(t, []string{"db", "status", "-o", "json"}, readLines(t, log+".args"))
	assert.Equal(t, "v6.1.9", status.SchemaVersion)
	assert.Equal(t, time.Date(2026, 9, 15, 6, 31, 36, 0, time.UTC), status.Built)
	assert.False(t, status.Valid)
	assert.Contains(t, status.Error, "max allowed age")
}

func TestRemoveStaleTempDirs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scan-123", "layers"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keep-me"), 0o700))

	RemoveStaleTempDirs(dir)

	_, err := os.Stat(filepath.Join(dir, "scan-123"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(dir, "keep-me"))
	assert.NoError(t, err)
}
```

- [ ] **Step 3: Убедиться, что тесты падают**

Run: `go test ./pkg/grype/`
Expected: FAIL, `unknown field registry in struct literal of type wrapper`, `undefined: RemoveStaleTempDirs`.

- [ ] **Step 4: Реализация — заменить `pkg/grype/wrapper.go` целиком**

```go
package grype

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/ext"
)

type Format string

const (
	grypeCmd = "grype"
	syftCmd  = "syft"

	FormatJSON      Format = "json"
	FormatSPDX      Format = "spdx-json"
	FormatCycloneDX Format = "cyclonedx"

	// tempDirPrefix names the per-run directories inside SCANNER_GRYPE_TMP_DIR.
	tempDirPrefix = "scan-"
)

type ImageRef struct {
	Name   string
	Auth   RegistryAuth
	NonSSL bool
}

type ScanOption struct {
	Format Format
}

// RegistryAuth wraps registry credentials.
type RegistryAuth interface {
}

type NoAuth struct {
}

type BasicAuth struct {
	Username string
	Password string
}

type BearerAuth struct {
	Token string
}

// DBStatus is what `grype db status -o json` reports about the vulnerability database.
type DBStatus struct {
	SchemaVersion string    `json:"schemaVersion"`
	From          string    `json:"from"`
	Built         time.Time `json:"built"`
	Path          string    `json:"path"`
	Valid         bool      `json:"valid"`
	Error         string    `json:"error"`
}

type Wrapper interface {
	Scan(imageRef ImageRef, opt ScanOption) (Report, error)
	ScanSBOM(imageRef ImageRef, opt ScanOption) (any, error)
	GetVersion() (VersionInfo, error)
	DBStatus() (DBStatus, error)
}

type wrapper struct {
	config     etc.Grype
	registry   etc.Registry
	ambassador ext.Ambassador
}

func NewWrapper(config etc.Grype, registry etc.Registry, ambassador ext.Ambassador) Wrapper {
	return &wrapper{
		config:     config,
		registry:   registry,
		ambassador: ambassador,
	}
}

func (w *wrapper) Scan(imageRef ImageRef, opt ScanOption) (Report, error) {
	stdout, err := w.run(grypeCmd, w.scanArgs(imageRef, opt), w.registryEnv("GRYPE", imageRef), grypeExitOK)
	if err != nil {
		return Report{}, err
	}
	return w.parseReportFromStdout(opt.Format, stdout)
}

func (w *wrapper) ScanSBOM(imageRef ImageRef, opt ScanOption) (any, error) {
	args := []string{imageRef.Name, "--output", string(opt.Format)}
	stdout, err := w.run(syftCmd, args, w.registryEnv("SYFT", imageRef), syftExitOK)
	if err != nil {
		return nil, err
	}
	var sbom any
	if err := json.Unmarshal(stdout, &sbom); err != nil {
		return nil, xerrors.Errorf("sbom json decode error: %w", err)
	}
	return sbom, nil
}

// DBStatus runs `grype db status -o json`. For an invalid database grype exits non-zero but still
// prints the status, which is what callers want to show.
func (w *wrapper) DBStatus() (DBStatus, error) {
	printed := func(_ int, stdout []byte) bool { return len(bytes.TrimSpace(stdout)) > 0 }
	stdout, err := w.run(grypeCmd, []string{"db", "status", "-o", "json"}, nil, printed)
	if err != nil {
		return DBStatus{}, err
	}
	var status DBStatus
	if err := json.Unmarshal(stdout, &status); err != nil {
		return DBStatus{}, xerrors.Errorf("parsing grype db status: %w", err)
	}
	return status, nil
}

// grypeExitOK: with --fail-on grype exits with 2 when it finds vulnerabilities at or above the
// threshold, and the report on stdout is complete. Any other non-zero code is a failure.
func grypeExitOK(code int, stdout []byte) bool {
	return code == 0 || (code == 2 && len(bytes.TrimSpace(stdout)) > 0)
}

func syftExitOK(code int, _ []byte) bool {
	return code == 0
}

// run starts a scanner tool with SCANNER_GRYPE_TIMEOUT and a temporary directory of its own inside
// SCANNER_GRYPE_TMP_DIR, and returns its stdout. stderr carries the tool's log and is used only for
// the error message. The environment holds registry credentials, so it is never logged.
func (w *wrapper) run(tool string, args, env []string, exitOK func(code int, stdout []byte) bool) ([]byte, error) {
	path, err := w.ambassador.LookPath(tool)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(w.config.TmpDir, 0o700); err != nil {
		return nil, xerrors.Errorf("creating %s: %w", w.config.TmpDir, err)
	}
	tmp, err := os.MkdirTemp(w.config.TmpDir, tempDirPrefix)
	if err != nil {
		return nil, xerrors.Errorf("creating a temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	ctx, cancel := context.WithTimeout(context.Background(), w.config.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(append(w.ambassador.Environ(), "TMPDIR="+tmp), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	slog.Debug("Running "+tool, slog.String("args", strings.Join(args, " ")))
	err = cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, xerrors.Errorf("scan timed out after %s", w.config.Timeout)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || !exitOK(exitErr.ExitCode(), stdout.Bytes()) {
			return nil, xerrors.Errorf("running %s: %v: %s", tool, err, lastLines(stderr.String(), 5))
		}
	}
	return stdout.Bytes(), nil
}

// registryEnv passes the registry settings to grype or syft (prefix GRYPE or SYFT). A registry that
// Harbor names with http:// always needs plain HTTP, whatever SCANNER_REGISTRY_INSECURE_USE_HTTP says.
func (w *wrapper) registryEnv(prefix string, ref ImageRef) []string {
	env := []string{
		fmt.Sprintf("%s_REGISTRY_INSECURE_USE_HTTP=%t", prefix, w.registry.InsecureUseHTTP || ref.NonSSL),
		fmt.Sprintf("%s_REGISTRY_INSECURE_SKIP_TLS_VERIFY=%t", prefix, w.registry.InsecureSkipTLSVerify),
	}
	authority := registryHost(ref.Name)
	switch auth := ref.Auth.(type) {
	case BasicAuth:
		env = append(env,
			prefix+"_REGISTRY_AUTH_AUTHORITY="+authority,
			prefix+"_REGISTRY_AUTH_USERNAME="+auth.Username,
			prefix+"_REGISTRY_AUTH_PASSWORD="+auth.Password)
	case BearerAuth:
		env = append(env,
			prefix+"_REGISTRY_AUTH_AUTHORITY="+authority,
			prefix+"_REGISTRY_AUTH_TOKEN="+auth.Token)
	}
	return env
}

// scanArgs builds grype's command line from SCANNER_GRYPE_* settings.
func (w *wrapper) scanArgs(imageRef ImageRef, opt ScanOption) []string {
	args := []string{imageRef.Name, "--output", string(opt.Format)}

	if w.config.Severity != "" {
		// --fail-on takes one level: the first of SCANNER_GRYPE_SEVERITY, in grype's terms.
		first := strings.TrimSpace(strings.Split(w.config.Severity, ",")[0])
		if first != "" {
			severity := "negligible"
			switch strings.ToLower(first) {
			case "low", "medium", "high", "critical":
				severity = strings.ToLower(first)
			}
			args = append(args, "--fail-on", severity)
		}
	}
	if w.config.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}
	if w.config.OnlyFixed {
		args = append(args, "--only-fixed")
	}
	if w.config.SkipUpdate {
		args = append(args, "--skip-db-update")
	}
	if w.config.OfflineScan {
		args = append(args, "--offline")
	}
	if w.config.ConfigFile != "" {
		args = append(args, "--config", w.config.ConfigFile)
	}
	if w.config.FailOnSeverity != "" {
		args = append(args, "--fail-on", w.config.FailOnSeverity)
	}
	if w.config.AddCPEsIfNone {
		args = append(args, "--add-cpes-if-none")
	}
	if w.config.ByCVE {
		args = append(args, "--by-cve")
	}
	if w.config.Platform != "" {
		args = append(args, "--platform", w.config.Platform)
	}
	if w.config.Distro != "" {
		args = append(args, "--distro", w.config.Distro)
	}
	if w.config.ExcludeAddl != "" {
		args = append(args, "--exclude-addl", w.config.ExcludeAddl)
	}
	if w.config.DebugMode {
		args = append(args, "--verbose")
	}
	return args
}

// registryHost is the host[:port] part of an image reference.
func registryHost(imageRef string) string {
	host, _, _ := strings.Cut(imageRef, "/")
	return host
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// RemoveStaleTempDirs deletes the per-run directories left by scans that were killed together with
// the container. Call it at start-up, before any scan runs.
func RemoveStaleTempDirs(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), tempDirPrefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			slog.Warn("Failed to remove a stale temp dir", slog.String("path", path), slog.String("err", err.Error()))
		}
	}
}

func (w *wrapper) parseReportFromStdout(format Format, stdout []byte) (Report, error) {
	switch format {
	case FormatJSON:
		return w.parseJSONReportFromBytes(stdout)
	case FormatSPDX, FormatCycloneDX:
		return w.parseSBOMFromBytes(stdout)
	}
	return Report{}, xerrors.Errorf("unsupported format %s", format)
}

func (w *wrapper) parseJSONReportFromBytes(data []byte) (Report, error) {
	var scanReport ScanReport
	if err := json.Unmarshal(data, &scanReport); err != nil {
		return Report{}, xerrors.Errorf("report json decode error: %w", err)
	}

	var vulnerabilities []Vulnerability
	for _, match := range scanReport.Matches {
		vulnerabilities = append(vulnerabilities, match.Vulnerability)
	}

	return Report{
		Vulnerabilities: vulnerabilities,
		Matches:         scanReport.Matches,
	}, nil
}

func (w *wrapper) parseSBOMFromBytes(data []byte) (Report, error) {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return Report{}, xerrors.Errorf("sbom json decode error: %w", err)
	}
	return Report{SBOM: doc}, nil
}

func (w *wrapper) GetVersion() (VersionInfo, error) {
	name, err := w.ambassador.LookPath(grypeCmd)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed preparing grype version command: %w", err)
	}
	versionOutput, err := w.ambassador.RunCmd(exec.Command(name, "version", "--output", "json"))
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed running grype version command: %w: %v", err, string(versionOutput))
	}
	var vi VersionInfo
	if err := json.Unmarshal(versionOutput, &vi); err != nil {
		return VersionInfo{}, fmt.Errorf("failed parsing grype version output: %w", err)
	}
	return vi, nil
}
```

`main.go`: вызов `grype.NewWrapper(config.Grype, ambassador)` заменить на `grype.NewWrapper(config.Grype, config.Registry, ambassador)`.

Если в репозитории остались вызовы удалённых функций (`prepareScanCmd`, `extractRegistryURL`, `pullImageWithDocker`, `parseReport`), `go build ./...` их покажет. Кроме удалённого в этой задаче кода, таких вызовов быть не должно.

- [ ] **Step 5: Прогнать тесты**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: без ошибок, тесты `ok`.

- [ ] **Step 6: Commit**

```bash
gofmt -w pkg/grype/wrapper.go pkg/grype/wrapper_test.go main.go
git add pkg/grype main.go
git commit -m "fix(grype): run scanners with a timeout and own temp dir, no secrets in logs, TLS from settings

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Ключ API и дата базы в метаданных

**Files:**
- Modify: `pkg/http/api/v1/handler.go`
- Create: `pkg/http/api/v1/handler_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/http/api/v1/handler_test.go`

```go
package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

type fakeWrapper struct{ grype.Wrapper }

func (fakeWrapper) GetVersion() (grype.VersionInfo, error) {
	return grype.VersionInfo{Version: "0.117.0"}, nil
}

func (fakeWrapper) DBStatus() (grype.DBStatus, error) {
	return grype.DBStatus{Built: time.Date(2026, 9, 22, 6, 30, 41, 0, time.UTC), Valid: true}, nil
}

func newTestHandler() http.Handler {
	return NewAPIHandler(etc.BuildInfo{}, etc.Config{API: etc.API{Key: "adapter-key"}}, nil, nil, fakeWrapper{})
}

func call(h http.Handler, method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAPIRequiresKey(t *testing.T) {
	h := newTestHandler()
	assert.Equal(t, http.StatusUnauthorized, call(h, http.MethodGet, "/api/v1/metadata", nil, "").Code)
	assert.Equal(t, http.StatusUnauthorized, call(h, http.MethodGet, "/api/v1/metadata",
		map[string]string{"Authorization": "Bearer wrong"}, "").Code)
	assert.Equal(t, http.StatusUnauthorized, call(h, http.MethodPost, "/api/v1/scan", nil, "{}").Code)
}

func TestAPIAcceptsBearerAndAPIKeyHeader(t *testing.T) {
	h := newTestHandler()
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/metadata",
		map[string]string{"Authorization": "Bearer adapter-key"}, "").Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/metadata",
		map[string]string{"X-ScannerAdapter-API-Key": "adapter-key"}, "").Code)
	// with the key the request reaches the handler, which rejects the broken body
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/scan",
		map[string]string{"Authorization": "Bearer adapter-key"}, "not json").Code)
}

func TestProbesNeedNoKey(t *testing.T) {
	h := newTestHandler()
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/probe/healthy", nil, "").Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/probe/ready", nil, "").Code)
}

func TestMetadataReportsDatabaseDate(t *testing.T) {
	rec := call(newTestHandler(), http.MethodGet, "/api/v1/metadata", map[string]string{"Authorization": "Bearer adapter-key"}, "")
	require.Equal(t, http.StatusOK, rec.Code)
	var metadata struct {
		Properties map[string]string `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &metadata))
	assert.Equal(t, "2026-09-22T06:30:41Z", metadata.Properties["harbor.scanner-adapter/vulnerability-database-updated-at"])
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./pkg/http/api/v1/`
Expected: FAIL, `TestAPIRequiresKey` получает 200 вместо 401, у `TestMetadataReportsDatabaseDate` нет свойства.

- [ ] **Step 3: Реализация в `pkg/http/api/v1/handler.go`**

В импорты добавить `"crypto/subtle"` и `"strings"` (если их нет).

В `NewAPIHandler` сразу после строки `apiV1Router := router.PathPrefix("/api/v1").Subrouter()` добавить:

```go
	apiV1Router.Use(handler.requireAPIKey(config.API.Key))
```

После метода `logRequest` добавить:

```go
// requireAPIKey rejects requests to the scanner API without the key Harbor was registered with,
// sent as "Authorization: Bearer <key>" or "X-ScannerAdapter-API-Key: <key>".
func (h *requestHandler) requireAPIKey(key string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			given := req.Header.Get("X-ScannerAdapter-API-Key")
			if kind, value, ok := strings.Cut(req.Header.Get("Authorization"), " "); ok && strings.EqualFold(kind, "Bearer") {
				given = strings.TrimSpace(value)
			}
			if key == "" || subtle.ConstantTimeCompare([]byte(given), []byte(key)) != 1 {
				slog.Warn("Rejected a request without a valid API key",
					slog.String("addr", req.RemoteAddr), slog.String("uri", req.URL.RequestURI()))
				h.WriteJSONError(res, api.Error{HTTPCode: http.StatusUnauthorized, Message: "missing or invalid API key"})
				return
			}
			next.ServeHTTP(res, req)
		})
	}
}
```

В `GetMetadata` сразу после блока, который заполняет свойства `grype.*` из `vi`, добавить:

```go
	if status, err := h.wrapper.DBStatus(); err != nil {
		slog.Warn("Failed to read the vulnerability DB status", slog.String("err", err.Error()))
	} else if !status.Built.IsZero() {
		properties["harbor.scanner-adapter/vulnerability-database-updated-at"] = status.Built.UTC().Format(time.RFC3339)
	}
```

- [ ] **Step 4: Прогнать тесты**

Run: `go build ./... && go test ./...`
Expected: без ошибок, тесты `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/http/api/v1/handler.go pkg/http/api/v1/handler_test.go
git add pkg/http/api/v1
git commit -m "feat(api): require SCANNER_API_KEY and report the vulnerability DB date

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Подключение в `main.go`

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Реализация**

Строки

```go
	// Set up structured logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: etc.LogLevel(),
	})))
```

заменить на:

```go
	// Log format and level from SCANNER_LOG_FORMAT and SCANNER_LOG_LEVEL
	slog.SetDefault(slog.New(etc.NewLogHandler(os.Stdout)))
```

Сразу после создания `grypeWrapper` добавить:

```go
	// Scans killed together with the previous container leave their temp dirs behind.
	grype.RemoveStaleTempDirs(config.Grype.TmpDir)

	if status, err := grypeWrapper.DBStatus(); err != nil {
		slog.Warn("Failed to read the vulnerability DB status", slog.String("err", err.Error()))
	} else {
		slog.Info("Vulnerability DB",
			slog.String("built", status.Built.UTC().Format(time.RFC3339)),
			slog.String("schema", status.SchemaVersion),
			slog.Bool("valid", status.Valid),
			slog.String("error", status.Error))
	}
```

`time` уже импортирован в плане 1.

- [ ] **Step 2: Проверить**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: без ошибок, тесты `ok`.

- [ ] **Step 3: Commit**

```bash
gofmt -w main.go
git add main.go
git commit -m "feat: log format from settings, clean stale temp dirs, log the DB date at start

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Скрипты контейнера и обновление Exploit-DB

`start.sh` и `update-grype-db.sh` переносятся из образа комплекта. В `start.sh` добавляется копия Exploit-DB в том при первом старте и вызов `update-exploitdb.sh` в ночном задании.

**Files:**
- Modify: `start.sh` (заменить целиком)
- Modify: `update-grype-db.sh` (заменить целиком)
- Create: `update-exploitdb.sh`
- Create: `test/update-exploitdb_test.sh`

- [ ] **Step 1: `update-grype-db.sh`** — заменить целиком

```sh
#!/bin/sh
# Updates the Grype vulnerability database. Run by cron on GRYPE_DB_UPDATE_SCHEDULE;
# scans do not update the database themselves. Output goes to /var/log/grype-update.log,
# which start.sh also forwards to the container log, in the adapter's key=value format.

log() {
    level=$1
    shift
    echo "time=$(date '+%Y-%m-%dT%H:%M:%S%z') level=$level msg=\"$*\""
}

log INFO "Vulnerability DB update started"
started=$(date +%s)

if output=$(/usr/local/bin/grype db update 2>&1); then
    status=$(/usr/local/bin/grype db status 2>&1 | tr -s ' \n' ' ')
    log INFO "Vulnerability DB update finished in $(( $(date +%s) - started ))s: $(echo "$output" | tail -n 1 | tr -d '"'). $status"
else
    log ERROR "Vulnerability DB update failed after $(( $(date +%s) - started ))s: $(echo "$output" | tail -n 3 | tr '\n' ' ' | tr -d '"')"
    exit 1
fi
```

- [ ] **Step 2: `update-exploitdb.sh`**

```sh
#!/bin/sh
# Downloads the Exploit-DB list used by SCANNER_RISK_MODE=policy. Run by cron after the vulnerability
# DB update. curl honours HTTPS_PROXY. A failed or broken download keeps the previous list; the adapter
# re-reads the file within a minute after it changes.

log() {
    level=$1
    shift
    echo "time=$(date '+%Y-%m-%dT%H:%M:%S%z') level=$level msg=\"$*\""
}

url="${SCANNER_EXPLOITDB_URL:-https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv}"
file="${SCANNER_EXPLOITDB_FILE:-/home/scanner/.cache/exploitdb/files_exploits.csv}"
min_lines="${SCANNER_EXPLOITDB_MIN_LINES:-10000}"
tmp="$file.download"

mkdir -p "$(dirname "$file")"
if ! curl -fsSL --retry 3 --retry-delay 5 --max-time 600 -o "$tmp" "$url"; then
    log ERROR "Exploit-DB update failed: cannot download $url; keeping the previous list"
    rm -f "$tmp"
    exit 1
fi
if ! head -n 1 "$tmp" | grep -q '^id,.*codes'; then
    log ERROR "Exploit-DB update failed: $url is not the Exploit-DB list; keeping the previous list"
    rm -f "$tmp"
    exit 1
fi
lines=$(wc -l < "$tmp" | tr -d ' ')
if [ "$lines" -lt "$min_lines" ]; then
    log ERROR "Exploit-DB update failed: only $lines lines, expected at least $min_lines; keeping the previous list"
    rm -f "$tmp"
    exit 1
fi
mv -f "$tmp" "$file"
log INFO "Exploit-DB list updated: $lines lines"
```

- [ ] **Step 3: `start.sh`** — заменить целиком

```sh
#!/bin/sh
# Container entrypoint. Runs as root to set up /etc/hosts and cron,
# then starts the adapter as the unprivileged scanner user.
set -eu

# SCANNER_EXTRA_HOSTS="host=ip,host2=ip2": names the container cannot resolve via DNS.
for pair in $(echo "${SCANNER_EXTRA_HOSTS:-}" | tr ',' ' '); do
    host="${pair%%=*}"
    ip="${pair#*=}"
    if [ -z "$host" ] || [ -z "$ip" ] || [ "$host" = "$pair" ]; then
        echo "Ignoring malformed SCANNER_EXTRA_HOSTS entry: $pair" >&2
        continue
    fi
    grep -qxF "$ip $host" /etc/hosts || echo "$ip $host" >> /etc/hosts
done

# Exploit-DB list for SCANNER_RISK_MODE=policy: the copy baked into the image seeds the volume,
# the nightly job below keeps it fresh.
exploitdb_file="${SCANNER_EXPLOITDB_FILE:-/home/scanner/.cache/exploitdb/files_exploits.csv}"
mkdir -p "$(dirname "$exploitdb_file")"
if [ ! -s "$exploitdb_file" ] && [ -s /usr/local/share/exploitdb/files_exploits.csv ]; then
    # -p keeps the build date, so an old image's copy is reported by SCANNER_EXPLOITDB_MAX_AGE.
    cp -p /usr/local/share/exploitdb/files_exploits.csv "$exploitdb_file"
fi
chown -R scanner:scanner "$(dirname "$exploitdb_file")"

# Nightly vulnerability DB update, then the Exploit-DB list. Scans run with GRYPE_DB_AUTO_UPDATE=false,
# so the slow link to the DB server is used only on this schedule (interpreted in TZ). crond runs the
# job as the scanner user with the container environment (TZ, proxy settings, GRYPE_*, SCANNER_*).
echo "${GRYPE_DB_UPDATE_SCHEDULE:-0 0 * * *} /usr/local/bin/update-grype-db.sh >> /var/log/grype-update.log 2>&1; /usr/local/bin/update-exploitdb.sh >> /var/log/grype-update.log 2>&1" \
    > /etc/crontabs/scanner
# Level 9: only crond errors; the update scripts log their own start and result.
crond -f -l 9 -L /dev/stderr &
# The update log also goes to the container log.
tail -n 0 -F /var/log/grype-update.log &

export HOME=/home/scanner
exec su-exec scanner /home/scanner/bin/scanner-grype
```

- [ ] **Step 4: Тест скрипта обновления** `test/update-exploitdb_test.sh`

```sh
#!/bin/sh
# Checks update-exploitdb.sh against a local HTTP server: a good list replaces the file,
# a broken download keeps it. Run from the repository root: sh test/update-exploitdb_test.sh
set -eu
root=$(pwd)
work=$(mktemp -d)
port=18088
cp pkg/exploitdb/testdata/files_exploits.csv "$work/good.csv"
echo "<html>proxy error</html>" > "$work/bad.csv"
(cd "$work" && exec python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1) &
server=$!
trap 'kill $server 2>/dev/null; rm -rf "$work"' EXIT
sleep 1

run() {
    SCANNER_EXPLOITDB_URL="http://127.0.0.1:$port/$1" SCANNER_EXPLOITDB_FILE="$work/out/files_exploits.csv" \
        SCANNER_EXPLOITDB_MIN_LINES=3 sh "$root/update-exploitdb.sh"
}

run good.csv
cmp -s "$work/good.csv" "$work/out/files_exploits.csv" || { echo "FAIL: good list was not installed"; exit 1; }

if run bad.csv; then echo "FAIL: broken list was accepted"; exit 1; fi
cmp -s "$work/good.csv" "$work/out/files_exploits.csv" || { echo "FAIL: previous list was not kept"; exit 1; }

if run missing.csv; then echo "FAIL: failed download was accepted"; exit 1; fi
cmp -s "$work/good.csv" "$work/out/files_exploits.csv" || { echo "FAIL: previous list was not kept"; exit 1; }
[ ! -e "$work/out/files_exploits.csv.download" ] || { echo "FAIL: temporary file left behind"; exit 1; }

echo "PASS"
```

- [ ] **Step 5: Прогнать тест и проверить синтаксис**

Run: `chmod +x start.sh update-grype-db.sh update-exploitdb.sh test/update-exploitdb_test.sh && sh -n start.sh && sh -n update-grype-db.sh && sh -n update-exploitdb.sh && sh test/update-exploitdb_test.sh`
Expected: последней строкой `PASS`, между ней и командой — строки `time=… level=INFO msg="Exploit-DB list updated: 5 lines"` и две строки `level=ERROR`.

- [ ] **Step 6: Commit**

```bash
git add start.sh update-grype-db.sh update-exploitdb.sh test/update-exploitdb_test.sh
git commit -m "feat: container scripts of the deployed image plus the nightly Exploit-DB update

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Сборка образа из исходников

**Files:**
- Modify: `Dockerfile` (заменить целиком)
- Create: `.dockerignore`
- Modify: `.gitignore`
- Delete: `scanner-grype-linux`

- [ ] **Step 1: `Dockerfile`** — заменить целиком

```dockerfile
# syntax=docker/dockerfile:1
# Harbor Scanner Grype, built from source.
#   docker build -t ant1freeze/harbor-scanner-grype:latest .
#   docker buildx build --platform linux/amd64 -t ant1freeze/harbor-scanner-grype:latest --load .
# A grype-db.tar.zst next to this file is imported instead of downloading the vulnerability DB.

FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/scanner-grype .

FROM alpine:3.24.1
ARG TARGETARCH=amd64
ARG GRYPE_VERSION=0.117.0
ARG SYFT_VERSION=1.51.1

RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates curl su-exec tzdata

RUN set -eu; \
    arch="${TARGETARCH:-amd64}"; \
    for tool in "grype:${GRYPE_VERSION}" "syft:${SYFT_VERSION}"; do \
      name="${tool%%:*}"; version="${tool##*:}"; \
      base="https://github.com/anchore/${name}/releases/download/v${version}"; \
      file="${name}_${version}_linux_${arch}.tar.gz"; \
      curl -fsSL --retry 5 --retry-delay 3 -o "/tmp/${file}" "${base}/${file}"; \
      curl -fsSL --retry 5 --retry-delay 3 "${base}/${name}_${version}_checksums.txt" \
        | grep " ${file}\$" | (cd /tmp && sha256sum -c -); \
      tar -xzf "/tmp/${file}" -C /usr/local/bin "${name}"; \
      rm -f "/tmp/${file}"; \
    done

RUN adduser -u 10000 -D -g '' scanner

COPY --from=build /out/scanner-grype /home/scanner/bin/scanner-grype
COPY grype-config.yaml /home/scanner/.grype.yaml
COPY risk-config.yaml /app/risk-config.yaml
COPY --chmod=755 start.sh update-grype-db.sh update-exploitdb.sh /usr/local/bin/

RUN mkdir -p /home/scanner/.cache/grype /home/scanner/.cache/reports /home/scanner/.cache/exploitdb \
      /usr/local/share/exploitdb && \
    chown -R scanner:scanner /home/scanner && \
    install -o scanner -g scanner -m 644 /dev/null /var/log/grype-update.log

# Exploit-DB list baked into the image; start.sh copies it to the volume on the first start.
RUN curl -fsSL --retry 5 --retry-delay 3 -o /usr/local/share/exploitdb/files_exploits.csv \
      https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv && \
    head -n 1 /usr/local/share/exploitdb/files_exploits.csv | grep -q '^id,.*codes'

WORKDIR /home/scanner
ENV PATH=/home/scanner/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GRYPE_VERSION=0.117.0 \
    GRYPE_DB_CACHE_DIR=/home/scanner/.cache/grype \
    SCANNER_LOG_LEVEL=info

USER scanner
RUN --mount=type=bind,target=/ctx \
    if [ -f /ctx/grype-db.tar.zst ]; then grype db import /ctx/grype-db.tar.zst; else grype db update; fi
USER root

ENV GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    SYFT_CHECK_FOR_APP_UPDATE=false

EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/start.sh"]
```

- [ ] **Step 2: `.dockerignore`**

```
.git
docs
test
*.tar
*.tar.gz
!grype-db.tar.zst
scanner-grype-linux
```

- [ ] **Step 3: В конец `.gitignore` добавить**

```
# vulnerability DB placed next to the Dockerfile for an offline build
grype-db.tar.zst
.env
```

- [ ] **Step 4: Удалить готовый бинарник из репозитория**

Run: `git rm scanner-grype-linux`

- [ ] **Step 5: Собрать образ**

Для проверки собирается под архитектуру этой машины. Базу берём из комплекта, чтобы не качать её заново:

```bash
cp /Users/kp/harbor-scanner-grype/grype-db-2026-09-15.tar.zst grype-db.tar.zst
docker build -t harbor-scanner-grype:dev .
docker run --rm --entrypoint sh harbor-scanner-grype:dev -c 'grype version | head -2; syft version | head -2; ls -la /usr/local/share/exploitdb; head -1 /usr/local/share/exploitdb/files_exploits.csv; GRYPE_DB_VALIDATE_AGE=false grype db status'
```

Expected: сборка успешна; `grype` 0.117.0, `syft` 1.51.1; файл `files_exploits.csv` больше 5 МБ с заголовком `id,file,description,…,codes,…`; `grype db status` показывает `Built: 2026-09-15`.

- [ ] **Step 6: Commit**

```bash
git add Dockerfile .dockerignore .gitignore
git commit -m "build: compile the adapter from source, alpine 3.24.1, grype 0.117.0, syft 1.51.1, Exploit-DB copy

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Установка — compose, настройки, инструкция

Берутся файлы из комплекта (`/Users/kp/harbor-scanner-grype/docker-compose.yml`, `env.example`, `deploy.sh`, `INSTALL.md`) и дополняются. Пример настроек называется `.env.example`, `deploy.sh` ссылается именно на него.

**Files:**
- Modify: `docker-compose.yml` (заменить на версию из комплекта с правками ниже)
- Create: `.env.example` (из `env.example` комплекта с правками ниже)
- Modify: `deploy.sh` (заменить на версию из комплекта)
- Create: `INSTALL.md` (из комплекта с правками ниже)

- [ ] **Step 1: Скопировать файлы комплекта**

```bash
cp /Users/kp/harbor-scanner-grype/docker-compose.yml docker-compose.yml
cp /Users/kp/harbor-scanner-grype/env.example .env.example
cp /Users/kp/harbor-scanner-grype/deploy.sh deploy.sh
cp /Users/kp/harbor-scanner-grype/INSTALL.md INSTALL.md
chmod +x deploy.sh
```

- [ ] **Step 2: `docker-compose.yml`**

В `volumes:` сервиса `grype-adapter` после строки `- grype_db:/home/scanner/.cache/grype` добавить:

```yaml
      # Exploit-DB list for SCANNER_RISK_MODE=policy, refreshed by the same nightly job.
      - exploitdb:/home/scanner/.cache/exploitdb
```

В корневом `volumes:` после `grype_db:` добавить строку `  exploitdb:`.

Комментарий `# All settings live in .env (see .env.example); …` оставить: теперь он верен.

- [ ] **Step 3: `.env.example`**

Блок `Registry access` — строки

```
# Account used when Harbor sends no credentials or a Bearer token. Use a Harbor robot
# account with pull permission. Leave both empty to use only what Harbor sends.
SCANNER_REGISTRY_USERNAME=admin
SCANNER_REGISTRY_PASSWORD=Harbor12345
```

заменить на:

```
# Account used when Harbor sends no credentials or a Bearer token, and only for the registry
# hosts listed in SCANNER_REGISTRY_TRUSTED_HOSTS (host names from Harbor's scan request).
# Use a Harbor robot account with pull permission, never admin. Empty: only what Harbor sends.
SCANNER_REGISTRY_USERNAME=
SCANNER_REGISTRY_PASSWORD=
SCANNER_REGISTRY_TRUSTED_HOSTS=
```

Перед блоком `Scanning` вставить:

```
# ---------------------------------------------------------------------------
# Access to the adapter API
# ---------------------------------------------------------------------------
# Required. Harbor sends it with every request: in Harbor > Interrogation Services > Scanners,
# set Authorization to "Bearer" (or "API Key") and paste the same value.
# Generate one with: openssl rand -hex 32
SCANNER_API_KEY=
```

Блок `Severity shown in Harbor` заменить целиком:

```
# ---------------------------------------------------------------------------
# Severity shown in Harbor
# ---------------------------------------------------------------------------
# false: use Grype's own severity and ignore everything below
SCANNER_RISK_ENABLED=true
# policy:  five rules, the reason is written in front of the description (see RISK_CALCULATION.md)
#          1 CISA KEV -> Critical; 2 malicious package (GitHub "Malware in", CWE-506) -> Critical;
#          3 grype risk: from SCANNER_POLICY_CRITICAL Critical, from _HIGH High, from _MEDIUM Medium, else Low;
#          4 no EPSS -> Grype's severity, at most High; 5 public exploit raises to High (network, High/Critical)
#          or at least Medium
# formula: Risk% = EPSS*100 * CVSS/10, compared with SCANNER_RISK_CRITICAL..LOW (percent)
# cvss:    CVSS base score, compared with SCANNER_RISK_CVSS_CRITICAL..LOW
SCANNER_RISK_MODE=policy
SCANNER_POLICY_CRITICAL=70
SCANNER_POLICY_HIGH=30
SCANNER_POLICY_MEDIUM=10
# Exploit-DB list for rule 5, downloaded by the nightly job after the vulnerability DB (honours HTTPS_PROXY)
SCANNER_EXPLOITDB_URL=https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
SCANNER_EXPLOITDB_MAX_AGE=336h
# formula and cvss modes only
SCANNER_RISK_CRITICAL=85
SCANNER_RISK_HIGH=70
SCANNER_RISK_MEDIUM=50
SCANNER_RISK_LOW=0.01
SCANNER_RISK_CVSS_CRITICAL=9.0
SCANNER_RISK_CVSS_HIGH=7.0
SCANNER_RISK_CVSS_MEDIUM=4.0
SCANNER_RISK_CVSS_LOW=0.1
# Used when a vulnerability has no EPSS / CVSS data (formula mode)
SCANNER_RISK_DEFAULT_EPSS=0.1
SCANNER_RISK_DEFAULT_CVSS=5.0
```

- [ ] **Step 4: `INSTALL.md`**

Первую строку оставить. Абзац про образ заменить на:

```markdown
Образ `ant1freeze/harbor-scanner-grype:latest` собирается из этого репозитория (`Dockerfile`):
Grype 0.117.0, Syft 1.51.1, Alpine 3.24.1, база уязвимостей и список Exploit-DB внутри.
Сборка под серверы: `docker buildx build --platform linux/amd64 -t ant1freeze/harbor-scanner-grype:latest --load .`,
перенос: `docker save ant1freeze/harbor-scanner-grype:latest | gzip > harbor-scanner-grype-amd64.tar.gz`.
```

В разделе «Первая установка» `cp env.example .env` заменить на `cp .env.example .env`, а комментарий — на `# отредактировать: ключ API, учётка registry, хосты, пороги, воркеры`.

Перед разделом «База уязвимостей» вставить:

```markdown
## Регистрация в Harbor

1. Сгенерировать ключ: `openssl rand -hex 32` и записать его в `.env` как `SCANNER_API_KEY`.
2. `docker compose up -d`.
3. Harbor → Interrogation Services → Scanners → New Scanner: адрес `http://grype-adapter:8090`,
   Authorization — `Bearer`, Credentials — тот же ключ. Без ключа коннектор отвечает 401.

## Уровни в Harbor

Режим `SCANNER_RISK_MODE=policy`: уровень выставляется по пяти правилам, причина пишется в начало
описания уязвимости, например
«High: риск grype 69.0, порог High от 30 (EPSS 92%, критичность grype High); эксплойтов не найдено; в KEV нет.».
Правила и пороги — в `RISK_CALCULATION.md`. Старые отчёты сохраняют прежние уровни до пересканирования:
после переключения режима запустите Scan All.
```

В раздел «База уязвимостей» в конец добавить:

```markdown
Тем же ночным заданием обновляется список Exploit-DB (`SCANNER_EXPLOITDB_URL`, через `HTTPS_PROXY`, если задан).
Если скачать не удалось, остаётся прежняя копия; в образе есть копия на момент сборки.
```

- [ ] **Step 5: Проверить compose**

Run: `cp .env.example .env && sed -i '' 's/^SCANNER_API_KEY=$/SCANNER_API_KEY=test/' .env && docker compose config -q && rm .env && echo ok`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml .env.example deploy.sh INSTALL.md
git commit -m "docs: installation with the API key, policy mode and Exploit-DB volume

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Проверка целиком на живом контейнере

Harbor не нужен: API коннектора вызывается напрямую, как это делает Harbor. Образ для сканирования берётся из локального реестра.

- [ ] **Step 1: Поднять реестр, Redis и коннектор**

```bash
docker network create e2e
docker run -d --name e2e-registry --network e2e -p 5001:5000 registry:2
docker run -d --name e2e-redis --network e2e redis:7-alpine
docker tag redis:7-alpine localhost:5001/library/redis:7-alpine
docker push localhost:5001/library/redis:7-alpine
DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' localhost:5001/library/redis:7-alpine | cut -d@ -f2)
echo "$DIGEST"
docker run -d --name e2e-adapter --network e2e -p 18090:8090 \
  -e SCANNER_REDIS_URL=redis://e2e-redis:6379 -e SCANNER_API_KEY=e2e-key \
  -e SCANNER_RISK_ENABLED=true -e SCANNER_RISK_MODE=policy -e GRYPE_DB_VALIDATE_AGE=false \
  -e SCANNER_REGISTRY_INSECURE_USE_HTTP=true \
  harbor-scanner-grype:dev
sleep 5 && docker logs e2e-adapter 2>&1 | tail -20
```

Expected: в логе строки `level=INFO msg="Vulnerability DB"`, `msg="Loaded Exploit-DB list"`, `msg="Severity policy enabled"`.

- [ ] **Step 2: Проверить ключ**

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:18090/api/v1/metadata
curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer e2e-key' http://localhost:18090/api/v1/metadata
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:18090/probe/healthy
```

Expected: `401`, `200`, `200`.

- [ ] **Step 3: Отсканировать образ**

```bash
ID=$(curl -s -X POST http://localhost:18090/api/v1/scan -H 'Authorization: Bearer e2e-key' \
  -H 'Content-Type: application/vnd.scanner.adapter.scan.request+json; version=1.0' \
  -d "{\"registry\":{\"url\":\"http://e2e-registry:5000\",\"authorization\":\"\"},\"artifact\":{\"repository\":\"library/redis\",\"digest\":\"$DIGEST\"}}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
for i in $(seq 1 60); do
  code=$(curl -s -o /tmp/e2e-report.json -w '%{http_code}' -H 'Authorization: Bearer e2e-key' \
    -H 'Accept: application/vnd.security.vulnerability.report; version=1.1' \
    "http://localhost:18090/api/v1/scan/$ID/report")
  [ "$code" = 200 ] && break
  sleep 5
done
python3 - <<'EOF'
import json, collections
r = json.load(open("/tmp/e2e-report.json"))
items = r["vulnerabilities"]
print("items", len(items), "report severity", r["severity"])
print(collections.Counter(v["severity"] for v in items))
for v in items[:5]:
    print(v["id"], v["package"], v["severity"], "|", v["description"][:160])
assert all(v["description"].startswith(v["severity"] + ": ") for v in items)
print("OK: every item starts with its reason")
EOF
```

Expected: ненулевое число находок и строка `OK: every item starts with its reason`.

- [ ] **Step 4: Убедиться, что секретов нет в логе**

```bash
docker logs e2e-adapter 2>&1 | grep -c -i -E 'e2e-key|password=|registry_auth|authorization":' || true
```

Expected: `0`.

- [ ] **Step 5: Убрать за собой**

```bash
docker rm -f e2e-adapter e2e-redis e2e-registry
docker network rm e2e
docker rmi localhost:5001/library/redis:7-alpine
```

- [ ] **Step 6: Записать итог**

Вывод шагов 2–4 сохранить для отчёта пользователю. Коммита в этой задаче нет.

---

## Что дальше

План 3 — надёжная очередь (раздел 2.5 спецификации): списки Redis вместо Pub/Sub, возврат прерванных заданий, отметка ожидания Harbor, сроки хранения, события сканов в логе. После него — сборка образа под linux/amd64 и архив для серверов.

---

## Замечания из итоговой проверки плана 1 (учесть при выполнении)

- Разбор JSON grype в переписанной обёртке не должен строить `Report.Vulnerabilities`: отчёт идёт по
  `Matches`, а список уязвимостей только провоцирует вернуть ошибку «пакет первой находки». Заодно убрать
  отладочный `fmt.Sprintf` на каждую находку и не писать полный JSON grype в лог на уровне Info.
- `/api/v1/metadata`: показать режим риска, пороги `SCANNER_POLICY_*`, дату и число CVE загруженного списка
  Exploit-DB — по ним видно, с какими настройками работает регистрация (это нужно для порядка
  перерегистрации) и устарел ли список.
- Проверка образа: число CVE в загруженном списке Exploit-DB должно быть правдоподобным (десятки тысяч), а не
  просто больше нуля.
- При обновлении grype пересобрать фикстуры `pkg/policy/testdata`: `severityFactor` повторяет grype 0.117.0, и
  проверка совпадения риска ловит расхождение только на свежих отчётах.
- Пока план 2 не выполнен, образ из `main` собирается из закоммиченного бинарника без режима `policy`: в
  описании PR это нужно сказать.
- `pkg/scan/controller.go` сейчас пишет в лог на уровне Info заголовок авторизации реестра целиком:
  `registry_auth` в «Received scan request from Harbor», `authorization` в «Processing authorization from
  Harbor» и `credentials` в «Authorization type detected». При переписывании выбора учётных данных убрать все
  три поля (оставить только тип: Basic, Bearer или пусто) и добавить тест, что в выводе лога нет ни
  заголовка, ни токена.

## Поправки по ходу выполнения плана 2

- Task 3: подмена хоста — через `HostMap.Lookup(host)` из Task 1, а хост и порт собираются `net.JoinHostPort`,
  иначе цель `[::1]:5000` превращается в `::1:5000/…`.
- Task 5: флаги TLS для grype — только `Registry.InsecureUseHTTP/InsecureSkipTLSVerify` (переменные
  `GRYPE_REGISTRY_INSECURE_*`); `SCANNER_GRYPE_INSECURE` больше ни на что не влияет.
- Task 6: в метаданных вместо `env.SCANNER_GRYPE_INSECURE` показывать настоящие флаги реестра; добавить режим
  риска, пороги политики, дату и число CVE списка Exploit-DB (см. замечания из итоговой проверки плана 1).
- Task 7: при старте предупреждать, если проверка сертификатов реестра выключена (особенно когда задана учётка)
  и если учётка задана, но `SCANNER_REGISTRY_TRUSTED_HOSTS` пуст (`Registry.AccountUnused()`); адрес Redis
  писать в лог без пароля (только хост и порт).
- Task 10: в `.env.example` и INSTALL.md — как сгенерировать ключ (`openssl rand -hex 32`, не короче 16
  символов), что проверка TLS по умолчанию выключена и как её включить (`SSL_CERT_FILE`/`SSL_CERT_DIR` и
  `SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY=false`).
- Task 11: ключ для E2E — не короче 16 символов.

# План 3. Надёжная очередь и выпуск

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Задания не теряются. Прерванные перезапуском возвращаются в очередь. Скан, которого Harbor уже не ждёт, пропускается. События сканов видны в логе. В конце — образ linux/amd64 и комплект для серверов.

**Architecture:** Очередь — два списка Redis: `…:queue` и `…:processing`. Воркер атомарно переносит задание `BLMOVE` из очереди в «в работе» и убирает его `LREM` по завершении. При старте всё из «в работе» возвращается в очередь. Отметка `…:awaited:<id>` со сроком `SCANNER_HARBOR_POLL_TIMEOUT` ставится при приёме задания и при каждом опросе отчёта. Сроки хранения записи задания зависят от статуса.

**Tech Stack:** Go 1.22 (`GOTOOLCHAIN=go1.22.12`), go-redis v9 (`LPush`, `BLMove`, `LMove`, `LRem`), Redis 7 для тестов (локальный образ `redis:7-alpine`), Docker buildx.

**Спецификация:** `docs/superpowers/specs/2026-09-25-policy-mode-design.md`, разделы 2.5, 2.6 и 10.

**Зависит от планов 1 и 2.**

**Окружение.**
- Команды выполняются из `/Users/kp/harbor-scanner-grype-src`, go/gofmt предваряются `GOTOOLCHAIN=go1.22.12`.
- Тестам с Redis нужен локальный Redis:
  - поднять: `docker run -d --name test-redis -p 16379:6379 redis:7-alpine` (если контейнер уже есть — `docker start test-redis`);
  - в каждой команде с этими тестами передавать `SCANNER_TEST_REDIS_URL=redis://localhost:16379/15`;
  - без этой переменной такие тесты пропускаются.
- Коммиты — в `feature/policy-mode`, последней строкой `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; `gofmt -w` — только по изменённым файлам.

Предположение: работает один экземпляр коннектора на одну базу Redis, как в `docker-compose.yml` (`container_name: grype-adapter`). Возврат прерванных заданий при старте на это рассчитан.

## Файлы

| Файл | Что меняется |
|---|---|
| `pkg/etc/config.go`, `pkg/etc/config_test.go` | `RedisStore.PendingJobTTL`, `Harbor.PollTimeout` |
| `pkg/persistence/store.go` | `MarkAwaited`, `IsAwaited` |
| `pkg/persistence/redis/store.go`, `pkg/persistence/redis/store_test.go` | сроки хранения по статусу, отметка ожидания |
| `pkg/queue/queue.go` | ключи Redis, задание в очереди |
| `pkg/queue/enqueuer.go`, `pkg/queue/enqueuer_test.go` | постановка в список, отметка ожидания, «Scan queued» |
| `pkg/queue/worker.go`, `pkg/queue/worker_test.go` | `BLMOVE`, подтверждение, возврат прерванных, пропуск, остановка, события |
| `pkg/scan/controller.go` | `Scan` возвращает ошибку скана |
| `pkg/http/api/v1/handler.go`, `pkg/http/api/v1/handler_test.go` | опрос отчёта продлевает отметку |
| `main.go` | подключение и порядок остановки |

---

### Task 1: Настройки очереди

**Files:**
- Modify: `pkg/etc/config.go`
- Modify: `pkg/etc/config_test.go`

- [ ] **Step 1: Написать падающий тест** — в конец `pkg/etc/config_test.go`

```go
func TestQueueDefaults(t *testing.T) {
	t.Setenv("SCANNER_API_KEY", "test-key")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, config.RedisStore.PendingJobTTL)
	assert.Equal(t, time.Hour, config.RedisStore.ScanJobTTL)
	assert.Equal(t, 2*time.Minute, config.Harbor.PollTimeout)
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `go test ./pkg/etc/`
Expected: FAIL, `config.RedisStore.PendingJobTTL undefined`, `config.Harbor undefined`.

- [ ] **Step 3: Реализация в `pkg/etc/config.go`**

`RedisStore` заменить на:

```go
type RedisStore struct {
	Namespace     string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.grype:data-store"`
	ScanJobTTL    time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
	PendingJobTTL time.Duration `env:"SCANNER_STORE_REDIS_PENDING_JOB_TTL" envDefault:"24h"`
}
```

После `RedisStore` добавить:

```go
// Harbor configures the adapter's view of Harbor as a client.
type Harbor struct {
	// PollTimeout: Harbor polls for the report of every scan it waits for. A queued scan that has not
	// been polled for this long is skipped, because Harbor has given up on it.
	PollTimeout time.Duration `env:"SCANNER_HARBOR_POLL_TIMEOUT" envDefault:"2m"`
}
```

В `Config` после `JobQueue JobQueue` добавить поле `Harbor Harbor`.

- [ ] **Step 4: Прогнать тесты**

Run: `go test ./pkg/etc/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/etc/config.go pkg/etc/config_test.go
git add pkg/etc/config.go pkg/etc/config_test.go
git commit -m "feat(config): pending job TTL and Harbor poll timeout as in the deployed image

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Хранилище — сроки по статусу и отметка ожидания

Сейчас запись задания живёт `SCANNER_STORE_REDIS_SCAN_JOB_TTL` (1 час) с самого создания. Задание, простоявшее в очереди больше часа во время «Scan all», исчезает, и Harbor получает 404. Новое правило: пока задание ждёт или выполняется — `PendingJobTTL` (24 часа), после Finished или Failed — `ScanJobTTL`.

**Files:**
- Modify: `pkg/persistence/store.go`
- Modify: `pkg/persistence/redis/store.go`
- Create: `pkg/persistence/redis/store_test.go`

- [ ] **Step 1: Поднять тестовый Redis**

Run: `docker run -d --name test-redis -p 16379:6379 redis:7-alpine || docker start test-redis`
Expected: id контейнера или `test-redis`.

- [ ] **Step 2: Написать падающий тест** `pkg/persistence/redis/store_test.go`

```go
package redis

import (
	"context"
	"os"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
)

func testRedis(t *testing.T) *goredis.Client {
	t.Helper()
	url := os.Getenv("SCANNER_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 to run Redis tests")
	}
	opts, err := goredis.ParseURL(url)
	require.NoError(t, err)
	rdb := goredis.NewClient(opts)
	require.NoError(t, rdb.FlushDB(context.Background()).Err())
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func newTestStore(t *testing.T) (*store, *goredis.Client) {
	rdb := testRedis(t)
	s := NewStore(etc.RedisStore{Namespace: "test:" + t.Name(), ScanJobTTL: time.Hour, PendingJobTTL: 24 * time.Hour}, rdb).(*store)
	return s, rdb
}

func TestTTLFollowsStatus(t *testing.T) {
	ctx := context.Background()
	s, rdb := newTestStore(t)
	key := job.ScanJobKey{ID: "job-1"}

	require.NoError(t, s.Create(ctx, &job.ScanJob{Key: key}))
	ttl := rdb.TTL(ctx, s.redisKey(key)).Val()
	assert.Greater(t, ttl, 23*time.Hour, "a queued job lives as long as a pending one")

	require.NoError(t, s.UpdateStatus(ctx, key, job.Pending, ""))
	assert.Greater(t, rdb.TTL(ctx, s.redisKey(key)).Val(), 23*time.Hour)

	require.NoError(t, s.UpdateStatus(ctx, key, job.Finished, ""))
	ttl = rdb.TTL(ctx, s.redisKey(key)).Val()
	assert.LessOrEqual(t, ttl, time.Hour)
	assert.Greater(t, ttl, 59*time.Minute)
}

func TestAwaitedMarkerExpires(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	key := job.ScanJobKey{ID: "job-2"}

	awaited, err := s.IsAwaited(ctx, key)
	require.NoError(t, err)
	assert.False(t, awaited)

	require.NoError(t, s.MarkAwaited(ctx, key, time.Second))
	awaited, err = s.IsAwaited(ctx, key)
	require.NoError(t, err)
	assert.True(t, awaited)

	time.Sleep(1200 * time.Millisecond)
	awaited, err = s.IsAwaited(ctx, key)
	require.NoError(t, err)
	assert.False(t, awaited)
}
```

- [ ] **Step 3: Убедиться, что тест не компилируется**

Run: `SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 go test ./pkg/persistence/...`
Expected: FAIL, `s.IsAwaited undefined`, `unknown field PendingJobTTL`.

- [ ] **Step 4: Интерфейс** — заменить `pkg/persistence/store.go` целиком

```go
package persistence

import (
	"context"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
)

type Store interface {
	Create(ctx context.Context, scanJob *job.ScanJob) error
	Get(ctx context.Context, key job.ScanJobKey) (*job.ScanJob, error)
	UpdateStatus(ctx context.Context, key job.ScanJobKey, status job.Status, errorMsg string) error
	UpdateReport(ctx context.Context, key job.ScanJobKey, report *harbor.ScanReport) error
	// MarkAwaited records that Harbor still waits for the report; the mark expires after ttl.
	MarkAwaited(ctx context.Context, key job.ScanJobKey, ttl time.Duration) error
	// IsAwaited reports whether Harbor asked for the report within the last MarkAwaited ttl.
	IsAwaited(ctx context.Context, key job.ScanJobKey) (bool, error)
}
```

- [ ] **Step 5: Реализация в `pkg/persistence/redis/store.go`**

Тип `store` и `NewStore` заменить на:

```go
type store struct {
	namespace  string
	pendingTTL time.Duration
	doneTTL    time.Duration
	rdb        *redis.Client
}

func NewStore(config etc.RedisStore, rdb *redis.Client) persistence.Store {
	return &store{
		namespace:  config.Namespace,
		pendingTTL: config.PendingJobTTL,
		doneTTL:    config.ScanJobTTL,
		rdb:        rdb,
	}
}

// ttl keeps queued and running jobs for PendingJobTTL, so a long "Scan all" queue does not expire
// before it is processed, and finished jobs for ScanJobTTL.
func (s *store) ttl(status job.Status) time.Duration {
	if status == job.Finished || status == job.Failed {
		return s.doneTTL
	}
	return s.pendingTTL
}
```

В `Create` вызов `s.rdb.Set(ctx, key, scanJobData, s.ttl)` заменить на `s.rdb.Set(ctx, key, scanJobData, s.ttl(job.Queued))`.
В `UpdateStatus` — `s.rdb.Set(ctx, redisKey, scanJobData, s.ttl)` на `s.rdb.Set(ctx, redisKey, scanJobData, s.ttl(status))`.
В `UpdateReport` — `s.rdb.Set(ctx, redisKey, scanJobData, s.ttl)` на `s.rdb.Set(ctx, redisKey, scanJobData, s.ttl(scanJob.Status))`.

После метода `redisKey` добавить:

```go
func (s *store) MarkAwaited(ctx context.Context, key job.ScanJobKey, ttl time.Duration) error {
	if err := s.rdb.Set(ctx, s.awaitedKey(key), "", ttl).Err(); err != nil {
		return xerrors.Errorf("marking scan job as awaited: %w", err)
	}
	return nil
}

func (s *store) IsAwaited(ctx context.Context, key job.ScanJobKey) (bool, error) {
	n, err := s.rdb.Exists(ctx, s.awaitedKey(key)).Result()
	if err != nil {
		return false, xerrors.Errorf("checking whether scan job is awaited: %w", err)
	}
	return n > 0, nil
}

func (s *store) awaitedKey(key job.ScanJobKey) string {
	return fmt.Sprintf("%s:awaited:%s", s.namespace, key.ID)
}
```

- [ ] **Step 6: Прогнать тесты**

Run: `SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 go test ./pkg/persistence/... && go build ./...`
Expected: `ok`, сборка без ошибок. Если сборка падает на других реализациях `persistence.Store` в тестах (например, `fakeStore`), им нужны два новых метода — см. Task 5.

- [ ] **Step 7: Commit**

```bash
gofmt -w pkg/persistence/store.go pkg/persistence/redis/store.go pkg/persistence/redis/store_test.go
git add pkg/persistence
git commit -m "feat(store): keep pending jobs 24h, finished 1h, and an expiring 'Harbor waits' mark

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Постановка в очередь

**Files:**
- Create: `pkg/queue/queue.go`
- Modify: `pkg/queue/enqueuer.go`
- Create: `pkg/queue/enqueuer_test.go`

- [ ] **Step 1: Написать падающий тест** `pkg/queue/enqueuer_test.go`

```go
package queue

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	redisstore "github.com/aquasecurity/harbor-scanner-grype/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
)

func testRedis(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("SCANNER_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 to run Redis tests")
	}
	opts, err := redis.ParseURL(url)
	require.NoError(t, err)
	rdb := redis.NewClient(opts)
	require.NoError(t, rdb.FlushDB(context.Background()).Err())
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

type fixture struct {
	rdb       *redis.Client
	store     persistence.Store
	namespace string
}

func newFixture(t *testing.T) fixture {
	rdb := testRedis(t)
	store := redisstore.NewStore(etc.RedisStore{Namespace: "store:" + t.Name(), ScanJobTTL: time.Hour, PendingJobTTL: 24 * time.Hour}, rdb)
	return fixture{rdb: rdb, store: store, namespace: "queue:" + t.Name()}
}

var testScanRequest = harbor.ScanRequest{
	Registry: harbor.Registry{URL: "https://harbor.corp.local"},
	Artifact: harbor.Artifact{Repository: "library/nginx", Digest: "sha256:abc"},
}

func TestEnqueuePushesJobAndMarksItAwaited(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	e := NewEnqueuer(etc.JobQueue{Namespace: f.namespace}, f.rdb, f.store, time.Minute)

	id, err := e.Enqueue(ctx, testScanRequest)
	require.NoError(t, err)

	payloads := f.rdb.LRange(ctx, queueKey(f.namespace), 0, -1).Val()
	require.Len(t, payloads, 1)
	var queued Job
	require.NoError(t, json.Unmarshal([]byte(payloads[0]), &queued))
	assert.Equal(t, id, queued.Key.ID)
	assert.Equal(t, "library/nginx", queued.Args.ScanRequest.Artifact.Repository)
	assert.WithinDuration(t, time.Now(), queued.EnqueuedAt, time.Minute)

	scanJob, err := f.store.Get(ctx, job.ScanJobKey{ID: id})
	require.NoError(t, err)
	require.NotNil(t, scanJob)
	assert.Equal(t, job.Queued, scanJob.Status)

	awaited, err := f.store.IsAwaited(ctx, job.ScanJobKey{ID: id})
	require.NoError(t, err)
	assert.True(t, awaited)
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 go test ./pkg/queue/`
Expected: FAIL, `too many arguments in call to NewEnqueuer`, `undefined: queueKey`.

- [ ] **Step 3: `pkg/queue/queue.go`**

```go
// Package queue runs scan jobs through two Redis lists: jobs wait in "<namespace>:queue", a worker
// moves one atomically to "<namespace>:processing" and removes it there when the scan is over. Jobs
// left in processing by a stopped container go back to the queue on the next start.
package queue

import (
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
)

// Job is what travels through the Redis lists.
type Job struct {
	Key        job.ScanJobKey
	Args       Args
	EnqueuedAt time.Time
}

type Args struct {
	ScanRequest *harbor.ScanRequest
}

func (j Job) ID() string {
	return j.Key.ID
}

func queueKey(namespace string) string {
	return namespace + ":queue"
}

func processingKey(namespace string) string {
	return namespace + ":processing"
}

// imageName is what the scan log shows for a job: repository@digest.
func imageName(j Job) string {
	if j.Args.ScanRequest == nil {
		return ""
	}
	return j.Args.ScanRequest.Artifact.Repository + "@" + j.Args.ScanRequest.Artifact.Digest
}
```

- [ ] **Step 4: Заменить `pkg/queue/enqueuer.go` целиком**

```go
package queue

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
)

type Enqueuer interface {
	Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error)
}

type enqueuer struct {
	namespace   string
	rdb         *redis.Client
	store       persistence.Store
	pollTimeout time.Duration
}

func NewEnqueuer(config etc.JobQueue, rdb *redis.Client, store persistence.Store, pollTimeout time.Duration) Enqueuer {
	return &enqueuer{
		namespace:   config.Namespace,
		rdb:         rdb,
		store:       store,
		pollTimeout: pollTimeout,
	}
}

func (e *enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error) {
	scanJobID := uuid.New().String()

	// Determine media type and MIME type from capabilities
	var mediaType api.MediaType
	var mimeType api.MIMEType = api.MimeTypeSecurityVulnerabilityReport // default
	for _, capability := range request.Capabilities {
		if capability.Type == harbor.CapabilityTypeSBOM && capability.Parameters != nil {
			if len(capability.Parameters.SBOMMediaTypes) > 0 {
				mediaType = capability.Parameters.SBOMMediaTypes[0]
				mimeType = api.MimeTypeSecuritySBOMReport
				break
			}
		}
	}
	scanJobKey := job.ScanJobKey{ID: scanJobID, MIMEType: mimeType, MediaType: mediaType}

	if err := e.store.Create(ctx, &job.ScanJob{Key: scanJobKey}); err != nil {
		return "", xerrors.Errorf("creating scan job: %w", err)
	}
	// Harbor starts polling for the report right away; until then the job counts as awaited.
	if err := e.store.MarkAwaited(ctx, scanJobKey, e.pollTimeout); err != nil {
		return "", err
	}

	queued := Job{Key: scanJobKey, Args: Args{ScanRequest: &request}, EnqueuedAt: time.Now().UTC()}
	payload, err := json.Marshal(queued)
	if err != nil {
		return "", xerrors.Errorf("marshalling job: %w", err)
	}
	length, err := e.rdb.LPush(ctx, queueKey(e.namespace), payload).Result()
	if err != nil {
		return "", xerrors.Errorf("queueing job: %w", err)
	}

	slog.Info("Scan queued",
		slog.String("scan_job_id", scanJobID),
		slog.String("image", imageName(queued)),
		slog.Int64("queued", length))
	return scanJobID, nil
}
```

Функцию `redisJobChannel` и тип `Job` из старого `enqueuer.go` больше не использовать: `Job` теперь в `queue.go`. `worker.go` пока ссылается на `redisJobChannel` и не соберётся — его переписывает Task 4. Чтобы пакет собирался между задачами, в `queue.go` временно добавить:

```go
// redisJobChannel is used by the Pub/Sub worker until Task 4 replaces it.
func redisJobChannel(namespace string) string {
	return namespace + ":jobs"
}
```

В `main.go` вызов `queue.NewEnqueuer(config.JobQueue, rdb, store)` заменить на `queue.NewEnqueuer(config.JobQueue, rdb, store, config.Harbor.PollTimeout)`.

- [ ] **Step 5: Прогнать тесты**

Run: `go build ./... && SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 go test ./pkg/queue/ ./pkg/persistence/...`
Expected: сборка без ошибок, тесты `ok`.

- [ ] **Step 6: Commit**

```bash
gofmt -w pkg/queue/queue.go pkg/queue/enqueuer.go pkg/queue/enqueuer_test.go main.go
git add pkg/queue main.go
git commit -m "feat(queue): put scan jobs into a Redis list and mark them awaited

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Воркер

**Files:**
- Modify: `pkg/queue/worker.go` (заменить целиком)
- Create: `pkg/queue/worker_test.go`
- Modify: `pkg/queue/queue.go` (убрать временный `redisJobChannel`)

- [ ] **Step 1: Написать падающие тесты** `pkg/queue/worker_test.go`

```go
package queue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
)

// fakeController finishes every scan unless told to fail; with release set it waits for it first.
type fakeController struct {
	store   persistence.Store
	err     error
	release chan struct{}
	started chan string

	mu      sync.Mutex
	scanned []string
}

func (f *fakeController) Scan(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
	if f.started != nil {
		f.started <- key.ID
	}
	if f.release != nil {
		<-f.release
	}
	f.mu.Lock()
	f.scanned = append(f.scanned, key.ID)
	f.mu.Unlock()
	if f.err != nil {
		_ = f.store.UpdateStatus(ctx, key, job.Failed, f.err.Error())
		return f.err
	}
	return f.store.UpdateStatus(ctx, key, job.Finished, "")
}

func (f *fakeController) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.scanned)
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func newTestWorker(f fixture, c *fakeController, concurrency int, pollTimeout time.Duration) Worker {
	return NewWorker(etc.JobQueue{Namespace: f.namespace, WorkerConcurrency: concurrency}, f.rdb, f.store, c, pollTimeout)
}

func TestWorkerScansQueuedJobs(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	logs := captureLogs(t)
	e := NewEnqueuer(etc.JobQueue{Namespace: f.namespace}, f.rdb, f.store, time.Minute)
	var ids []string
	for i := 0; i < 3; i++ {
		id, err := e.Enqueue(ctx, testScanRequest)
		require.NoError(t, err)
		ids = append(ids, id)
	}
	c := &fakeController{store: f.store}
	w := newTestWorker(f, c, 2, time.Minute)
	w.Start(ctx)
	defer w.Stop()

	require.Eventually(t, func() bool { return c.count() == 3 }, 10*time.Second, 50*time.Millisecond)
	require.Eventually(t, func() bool { return f.rdb.LLen(ctx, processingKey(f.namespace)).Val() == 0 }, 5*time.Second, 50*time.Millisecond)
	for _, id := range ids {
		scanJob, err := f.store.Get(ctx, job.ScanJobKey{ID: id})
		require.NoError(t, err)
		assert.Equal(t, job.Finished, scanJob.Status)
	}
	assert.Contains(t, logs.String(), `msg="Scan started"`)
	assert.Contains(t, logs.String(), `msg="Scan finished"`)
	assert.Contains(t, logs.String(), `msg="Free workers"`)
}

func TestWorkerSkipsJobsHarborStoppedWaitingFor(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	logs := captureLogs(t)
	id, err := NewEnqueuer(etc.JobQueue{Namespace: f.namespace}, f.rdb, f.store, time.Second).Enqueue(ctx, testScanRequest)
	require.NoError(t, err)
	time.Sleep(1200 * time.Millisecond) // Harbor did not poll within SCANNER_HARBOR_POLL_TIMEOUT

	c := &fakeController{store: f.store}
	w := newTestWorker(f, c, 1, time.Second)
	w.Start(ctx)
	defer w.Stop()

	require.Eventually(t, func() bool {
		scanJob, _ := f.store.Get(ctx, job.ScanJobKey{ID: id})
		return scanJob != nil && scanJob.Status == job.Failed
	}, 10*time.Second, 50*time.Millisecond)
	scanJob, _ := f.store.Get(ctx, job.ScanJobKey{ID: id})
	assert.Contains(t, scanJob.Error, "scan skipped")
	assert.Equal(t, 0, c.count(), "a job Harbor gave up on is not scanned")
	assert.Contains(t, logs.String(), `msg="Scan skipped"`)
}

func TestWorkerRequeuesInterruptedJobs(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	logs := captureLogs(t)
	key := job.ScanJobKey{ID: "interrupted"}
	require.NoError(t, f.store.Create(ctx, &job.ScanJob{Key: key}))
	require.NoError(t, f.store.MarkAwaited(ctx, key, time.Minute))
	payload, err := json.Marshal(Job{Key: key, Args: Args{ScanRequest: &testScanRequest}, EnqueuedAt: time.Now()})
	require.NoError(t, err)
	// the previous container took the job and was killed before it finished
	require.NoError(t, f.rdb.LPush(ctx, processingKey(f.namespace), payload).Err())

	c := &fakeController{store: f.store}
	w := newTestWorker(f, c, 1, time.Minute)
	w.Start(ctx)
	defer w.Stop()

	require.Eventually(t, func() bool { return c.count() == 1 }, 10*time.Second, 50*time.Millisecond)
	assert.Contains(t, logs.String(), `msg="Requeued interrupted scan jobs" jobs=1`)
}

func TestStopWaitsForRunningScans(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	_, err := NewEnqueuer(etc.JobQueue{Namespace: f.namespace}, f.rdb, f.store, time.Minute).Enqueue(ctx, testScanRequest)
	require.NoError(t, err)
	c := &fakeController{store: f.store, release: make(chan struct{}), started: make(chan string, 1)}
	w := newTestWorker(f, c, 1, time.Minute)
	w.Start(ctx)
	<-c.started

	stopped := make(chan struct{})
	go func() {
		w.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("Stop returned while a scan was still running")
	case <-time.After(300 * time.Millisecond):
	}
	close(c.release)
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return after the scan finished")
	}
	assert.EqualValues(t, 0, f.rdb.LLen(ctx, processingKey(f.namespace)).Val())
}

func TestFailedScanIsLoggedAndRemovedFromProcessing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	logs := captureLogs(t)
	_, err := NewEnqueuer(etc.JobQueue{Namespace: f.namespace}, f.rdb, f.store, time.Minute).Enqueue(ctx, testScanRequest)
	require.NoError(t, err)
	c := &fakeController{store: f.store, err: errors.New("running grype: unauthorized")}
	w := newTestWorker(f, c, 1, time.Minute)
	w.Start(ctx)
	defer w.Stop()

	require.Eventually(t, func() bool { return c.count() == 1 }, 10*time.Second, 50*time.Millisecond)
	require.Eventually(t, func() bool { return f.rdb.LLen(ctx, processingKey(f.namespace)).Val() == 0 }, 5*time.Second, 50*time.Millisecond)
	assert.Contains(t, logs.String(), `msg="Scan failed"`)
	assert.Contains(t, logs.String(), "running grype: unauthorized")
}
```

- [ ] **Step 2: Убедиться, что тесты не компилируются**

Run: `SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 go test ./pkg/queue/`
Expected: FAIL, `too many arguments in call to NewWorker`.

- [ ] **Step 3: Заменить `pkg/queue/worker.go` целиком**

```go
package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/scan"
)

// takeTimeout bounds one blocking wait for a job, so Stop is noticed promptly.
const takeTimeout = 5 * time.Second

type Worker interface {
	Start(ctx context.Context)
	Stop()
}

type worker struct {
	namespace   string
	concurrency int
	pollTimeout time.Duration

	rdb        *redis.Client
	store      persistence.Store
	controller scan.Controller

	cancel context.CancelFunc
	wg     sync.WaitGroup
	busy   atomic.Int32
}

func NewWorker(config etc.JobQueue, rdb *redis.Client, store persistence.Store, controller scan.Controller, pollTimeout time.Duration) Worker {
	return &worker{
		namespace:   config.Namespace,
		concurrency: config.WorkerConcurrency,
		pollTimeout: pollTimeout,
		rdb:         rdb,
		store:       store,
		controller:  controller,
	}
}

// Start returns jobs interrupted by the previous stop to the queue and starts the workers.
func (w *worker) Start(ctx context.Context) {
	loopCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.requeueInterrupted(loopCtx)
	for i := 0; i < w.concurrency; i++ {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			w.run(loopCtx)
		}()
	}
	w.logWorkers(loopCtx)
}

// Stop stops taking jobs and waits for the scans in progress. Scans still running when the container
// is killed stay in the processing list and go back to the queue on the next start.
func (w *worker) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
}

func (w *worker) run(ctx context.Context) {
	for ctx.Err() == nil {
		payload, err := w.rdb.BLMove(ctx, queueKey(w.namespace), processingKey(w.namespace), "RIGHT", "LEFT", takeTimeout).Result()
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("Failed to take a scan job from the queue", slog.String("err", err.Error()))
			sleep(ctx, time.Second)
			continue
		}
		w.process(payload)
	}
}

// process runs one job. It uses its own context: stopping the adapter lets running scans finish.
func (w *worker) process(payload string) {
	ctx := context.Background()
	w.busy.Add(1)
	defer func() {
		w.busy.Add(-1)
		w.ack(ctx, payload)
		w.logWorkers(ctx)
	}()

	var j Job
	if err := json.Unmarshal([]byte(payload), &j); err != nil {
		slog.Error("Dropped a malformed scan job", slog.String("err", err.Error()))
		return
	}
	log := slog.With(slog.String("scan_job_id", j.Key.ID), slog.String("image", imageName(j)))

	awaited, err := w.store.IsAwaited(ctx, j.Key)
	if err != nil {
		log.Warn("Failed to check whether Harbor still waits for the report; scanning anyway", slog.String("err", err.Error()))
		awaited = true
	}
	if !awaited {
		reason := fmt.Sprintf("Harbor has not asked for the report for more than %s", w.pollTimeout)
		if err := w.store.UpdateStatus(ctx, j.Key, job.Failed, "scan skipped: "+reason); err != nil {
			log.Error("Failed to mark a skipped scan job", slog.String("err", err.Error()))
		}
		log.Warn("Scan skipped", slog.String("reason", reason), slog.Duration("waited", waited(j)))
		return
	}

	log.Info("Scan started", slog.Duration("waited", waited(j)))
	started := time.Now()
	err = w.controller.Scan(ctx, j.Key, j.Args.ScanRequest)
	duration := time.Since(started).Round(time.Millisecond)
	if err != nil {
		log.Error("Scan failed", slog.Duration("duration", duration), slog.String("err", err.Error()))
		return
	}
	attrs := []any{slog.Duration("duration", duration)}
	if scanJob, err := w.store.Get(ctx, j.Key); err == nil && scanJob != nil && scanJob.Report != nil {
		attrs = append(attrs, vulnerabilityAttrs(scanJob.Report)...)
	}
	log.Info("Scan finished", attrs...)
}

// ack removes a job from the processing list. If that fails, the job runs again after the next
// start, which only costs a repeated scan.
func (w *worker) ack(ctx context.Context, payload string) {
	if err := w.rdb.LRem(ctx, processingKey(w.namespace), 1, payload).Err(); err != nil {
		slog.Error("Failed to remove scan job from processing list; it will be requeued on next start",
			slog.String("err", err.Error()))
	}
}

// requeueInterrupted moves jobs left in the processing list back to the queue, to its consuming end,
// so they run first.
func (w *worker) requeueInterrupted(ctx context.Context) {
	requeued := 0
	for {
		err := w.rdb.LMove(ctx, processingKey(w.namespace), queueKey(w.namespace), "RIGHT", "RIGHT").Err()
		if errors.Is(err, redis.Nil) {
			break
		}
		if err != nil {
			slog.Error("Failed to requeue interrupted scan jobs", slog.String("err", err.Error()))
			return
		}
		requeued++
	}
	if requeued > 0 {
		slog.Info("Requeued interrupted scan jobs", slog.Int("jobs", requeued))
	}
}

func (w *worker) logWorkers(ctx context.Context) {
	queued, err := w.rdb.LLen(ctx, queueKey(w.namespace)).Result()
	if err != nil {
		queued = -1
	}
	busy := int(w.busy.Load())
	slog.Info("Free workers", slog.Int("free", w.concurrency-busy), slog.Int("busy", busy), slog.Int64("queued", queued))
}

func waited(j Job) time.Duration {
	if j.EnqueuedAt.IsZero() {
		return 0
	}
	return time.Since(j.EnqueuedAt).Round(time.Second)
}

// vulnerabilityAttrs summarises a finished report for the log.
func vulnerabilityAttrs(report *harbor.ScanReport) []any {
	counts := map[harbor.Severity]int{}
	for _, v := range report.Vulnerabilities {
		counts[v.Severity]++
	}
	return []any{
		slog.Int("vulnerabilities", len(report.Vulnerabilities)),
		slog.Int("critical", counts[harbor.SevCritical]),
		slog.Int("high", counts[harbor.SevHigh]),
		slog.Int("medium", counts[harbor.SevMedium]),
		slog.Int("low", counts[harbor.SevLow]),
		slog.Int("unknown", counts[harbor.SevUnknown]),
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
```

Из `pkg/queue/queue.go` удалить временную функцию `redisJobChannel`.

В `main.go` вызов `queue.NewWorker(config.JobQueue, rdb, controller)` заменить на `queue.NewWorker(config.JobQueue, rdb, store, controller, config.Harbor.PollTimeout)`.

- [ ] **Step 4: Прогнать тесты**

Run: `go build ./... && SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 go test ./pkg/queue/ -count=1`
Expected: сборка без ошибок, `ok`.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/queue/worker.go pkg/queue/worker_test.go pkg/queue/queue.go main.go
git add pkg/queue main.go
git commit -m "feat(queue): reliable worker with requeue, skipped scans, graceful stop and scan events

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Контроллер, опрос отчёта и подключение

**Files:**
- Modify: `pkg/scan/controller.go`
- Modify: `pkg/http/api/v1/handler.go`
- Modify: `pkg/http/api/v1/handler_test.go`
- Modify: `main.go`

- [ ] **Step 1: Написать падающий тест** — дописать в `pkg/http/api/v1/handler_test.go`

В импорты добавить `"context"`, `"github.com/aquasecurity/harbor-scanner-grype/pkg/job"`, `"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"`. В конец файла:

```go
// fakeStore knows one queued job and records the awaited marks.
type fakeStore struct {
	persistence.Store
	marked []time.Duration
}

func (f *fakeStore) Get(_ context.Context, key job.ScanJobKey) (*job.ScanJob, error) {
	if key.ID != "job-1" {
		return nil, nil
	}
	return &job.ScanJob{Key: key, Status: job.Queued}, nil
}

func (f *fakeStore) MarkAwaited(_ context.Context, _ job.ScanJobKey, ttl time.Duration) error {
	f.marked = append(f.marked, ttl)
	return nil
}

func TestPollingForAQueuedReportKeepsItAwaited(t *testing.T) {
	store := &fakeStore{}
	config := etc.Config{API: etc.API{Key: "adapter-key"}, Harbor: etc.Harbor{PollTimeout: 2 * time.Minute}}
	h := NewAPIHandler(etc.BuildInfo{}, config, nil, store, fakeWrapper{})

	rec := call(h, http.MethodGet, "/api/v1/scan/job-1/report", map[string]string{
		"Authorization": "Bearer adapter-key",
		"Accept":        "application/vnd.security.vulnerability.report; version=1.1",
	}, "")

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, []time.Duration{2 * time.Minute}, store.marked)
}
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `go test ./pkg/http/api/v1/`
Expected: FAIL: `store.marked` пуст.

- [ ] **Step 3: Опрос отчёта продлевает отметку** — `pkg/http/api/v1/handler.go`

В `GetScanReport` блок

```go
	if scanJob.Status == job.Queued || scanJob.Status == job.Pending {
		scanJobLog.Debug("Scan job has not finished yet")
```

заменить на:

```go
	if scanJob.Status == job.Queued || scanJob.Status == job.Pending {
		// Harbor still waits for this report: keep the job from being skipped.
		if err := h.store.MarkAwaited(req.Context(), scanJob.Key, h.config.Harbor.PollTimeout); err != nil {
			scanJobLog.Warn("Failed to mark the scan job as awaited", slog.String("err", err.Error()))
		}
		scanJobLog.Debug("Scan job has not finished yet")
```

- [ ] **Step 4: Контроллер возвращает ошибку скана** — `pkg/scan/controller.go`

Метод `Scan` заменить на:

```go
// Scan runs one scan job and stores its report. A failed scan is stored as Failed and its error
// returned, so the worker can log it.
func (c *controller) Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error {
	if err := c.scan(ctx, scanJobKey, request); err != nil {
		if updateErr := c.store.UpdateStatus(ctx, scanJobKey, job.Failed, err.Error()); updateErr != nil {
			return xerrors.Errorf("%v; updating scan job as failed: %w", err, updateErr)
		}
		return err
	}
	return nil
}
```

В начале метода `scan` блок `defer`:

```go
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
```

заменить на:

```go
	defer func() {
		if r := recover(); r != nil {
			err = xerrors.Errorf("scan panicked: %v", r)
		}
	}()
```

- [ ] **Step 5: Порядок остановки в `main.go`**

Остановку в конце `main` заменить на порядок «сначала перестать принимать, потом дождаться сканов»:

```go
	<-sigChan
	slog.Info("Shutdown signal received")

	// Stop accepting scan requests first, then let the scans in progress finish. Scans still running
	// when the container is killed are requeued on the next start.
	server.Shutdown()
	worker.Stop()
	cancel()

	slog.Info("Harbor Scanner Grype stopped")
```

В `docker-compose.yml` ничего не менять: `stop_grace_period: 30s` уже задан.

- [ ] **Step 6: Прогнать всё**

Run: `go build ./... && go vet ./... && SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 go test ./... -count=1`
Expected: без ошибок, все тесты `ok`.

- [ ] **Step 7: Commit**

```bash
gofmt -w pkg/scan/controller.go pkg/http/api/v1/handler.go pkg/http/api/v1/handler_test.go main.go
git add pkg/scan/controller.go pkg/http/api/v1 main.go
git commit -m "feat: polling keeps a scan awaited, worker logs results, graceful shutdown order

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Проверка очереди на живом контейнере

Повторить Task 11 плана 2 (реестр, Redis, коннектор) с новым образом `harbor-scanner-grype:dev` (пересобрать: `docker build -t harbor-scanner-grype:dev .`). Дополнительно — две проверки.

- [ ] **Step 1: Перезапуск посреди очереди**

Поставить в очередь 5 сканов (`postgres:15-alpine` из локальных образов, запушенный в `localhost:5001/library/postgres:15-alpine`), через 3 секунды выполнить `docker restart e2e-adapter`. Опрашивать отчёты всех пяти, как в плане 2 (каждый опрос продлевает отметку).

Expected: все пять отчётов в итоге приходят с кодом 200. В `docker logs e2e-adapter` есть `msg="Requeued interrupted scan jobs"` (если на момент перезапуска шёл скан) и по одному `msg="Scan finished"` на задание после старта.

- [ ] **Step 2: Пропуск скана, который Harbor бросил**

Запустить коннектор с `-e SCANNER_HARBOR_POLL_TIMEOUT=5s` и `-e SCANNER_JOB_QUEUE_WORKER_CONCURRENCY=1`. Поставить в очередь 3 скана и не опрашивать их отчёты.

Expected: первый скан выполняется, у следующих в логе `msg="Scan skipped" reason="Harbor has not asked for the report for more than 5s"`.

- [ ] **Step 3: Убрать за собой** — как в Task 11 плана 2, плюс `docker rmi localhost:5001/library/postgres:15-alpine`.

- [ ] **Step 4: Записать итог для отчёта пользователю.** Коммита нет.

---

### Task 7: Выпуск для серверов

- [ ] **Step 1: Собрать образ linux/amd64**

```bash
cp /Users/kp/harbor-scanner-grype/grype-db-2026-09-15.tar.zst grype-db.tar.zst
docker buildx build --platform linux/amd64 -t ant1freeze/harbor-scanner-grype:latest --load .
docker image inspect ant1freeze/harbor-scanner-grype:latest --format '{{.Architecture}} {{.Size}}'
```

Expected: `amd64` и размер образа.

Внимание: `ant1freeze/harbor-scanner-grype:latest` на этой машине — образ из старого комплекта, загруженный для проверок. Сборка его перезапишет, и это ожидаемо. Базу при необходимости обновить до сборки: `grype db update` на машине с доступом в интернет и `grype db export`-архив, либо просто без файла `grype-db.tar.zst` — тогда сборка скачает свежую базу.

- [ ] **Step 2: Сложить комплект** в `/Users/kp/harbor-scanner-grype-policy/`

```bash
OUT=/Users/kp/harbor-scanner-grype-policy
mkdir -p "$OUT"
docker save ant1freeze/harbor-scanner-grype:latest | gzip > "$OUT/harbor-scanner-grype-amd64.tar.gz"
cp docker-compose.yml .env.example deploy.sh INSTALL.md RISK_CALCULATION.md "$OUT/"
cp /Users/kp/harbor-scanner-grype/grype-db-2026-09-15.tar.zst "$OUT/"
(cd "$OUT" && shasum -a 256 harbor-scanner-grype-amd64.tar.gz docker-compose.yml .env.example deploy.sh INSTALL.md RISK_CALCULATION.md grype-db-2026-09-15.tar.zst > SHA256SUMS && shasum -a 256 -c SHA256SUMS)
ls -la "$OUT"
```

Expected: все строки `OK`.

- [ ] **Step 3: Проверить, что образ из архива стартует** (под эмуляцией amd64)

```bash
docker run --rm --platform linux/amd64 --entrypoint sh ant1freeze/harbor-scanner-grype:latest -c \
  'scanner-grype 2>&1 | head -3; grype version | sed -n 2p; ls -la /usr/local/share/exploitdb'
```

Expected: коннектор сразу завершается с сообщением про `SCANNER_API_KEY is required` — так и задумано. Выводятся версия grype 0.117.0 и файл Exploit-DB.

- [ ] **Step 4: Записать итог.** Коммита нет: комплект лежит вне репозитория.

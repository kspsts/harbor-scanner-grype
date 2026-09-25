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
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
	redisstore "github.com/aquasecurity/harbor-scanner-grype/pkg/persistence/redis"
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

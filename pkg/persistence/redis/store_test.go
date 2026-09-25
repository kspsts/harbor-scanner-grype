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

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

// syncBuffer is a bytes.Buffer safe for concurrent use: several worker goroutines log concurrently
// with the test goroutine reading captureLogs' buffer, and a plain bytes.Buffer is not safe for that.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buf
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

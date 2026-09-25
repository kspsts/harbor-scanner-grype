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

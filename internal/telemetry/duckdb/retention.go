package duckdb

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// RetentionCleaner periodically sweeps the DuckDB database to enforce 14-day retention and 1 GB file size ceiling.
type RetentionCleaner struct {
	db            *sql.DB
	dbPath        string
	retentionDays int
	maxSizeBytes  int64
	interval      time.Duration
	stopCh        chan struct{}
	wg            sync.WaitGroup
	mu            sync.Mutex
}

// NewRetentionCleaner initializes a new retention cleaner instance.
func NewRetentionCleaner(db *sql.DB, dbPath string, retentionDays int, maxSizeBytes int64, interval time.Duration) *RetentionCleaner {
	if retentionDays <= 0 {
		retentionDays = 14
	}
	if maxSizeBytes <= 0 {
		maxSizeBytes = 1024 * 1024 * 1024 // 1 GB
	}
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	return &RetentionCleaner{
		db:            db,
		dbPath:        dbPath,
		retentionDays: retentionDays,
		maxSizeBytes:  maxSizeBytes,
		interval:      interval,
		stopCh:        make(chan struct{}),
	}
}

// Start launches the background retention loop. It runs one immediate sweep and then runs periodically.
func (r *RetentionCleaner) Start() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		// Run immediate retention sweep upon daemon startup (ADR 0043)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		if err := r.EnforceRetention(ctx); err != nil {
			slog.Warn("Initial DuckDB telemetry retention sweep encountered error", slog.String("error", err.Error()))
		}
		cancel()

		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-r.stopCh:
				return
			case <-ticker.C:
				runCtx, runCancel := context.WithTimeout(context.Background(), 5*time.Minute)
				if err := r.EnforceRetention(runCtx); err != nil {
					slog.Warn("Periodic DuckDB telemetry retention sweep encountered error", slog.String("error", err.Error()))
				}
				runCancel()
			}
		}
	}()
}

// Stop gracefully stops the background retention cleaner.
func (r *RetentionCleaner) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

// EnforceRetention performs time-based pruning and file-size ceiling enforcement, followed by a CHECKPOINT.
func (r *RetentionCleaner) EnforceRetention(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	// 1. Time-based retention pruning (delete entries older than retentionDays)
	cutoff := time.Now().AddDate(0, 0, -r.retentionDays)
	res, err := r.db.ExecContext(ctx, "DELETE FROM tool_audit_logs WHERE timestamp < ?", cutoff)
	if err != nil {
		return fmt.Errorf("failed to prune expired audit logs: %w", err)
	}
	if rowsAffected, _ := res.RowsAffected(); rowsAffected > 0 {
		slog.Info("DuckDB telemetry pruned expired records",
			slog.Int64("rows_deleted", rowsAffected),
			slog.Int("retention_days", r.retentionDays),
		)
	}

	// 2. File size ceiling enforcement (1 GB limit)
	if r.dbPath != "" && r.dbPath != ":memory:" {
		fi, statErr := os.Stat(r.dbPath)
		if statErr == nil && fi.Size() > r.maxSizeBytes {
			slog.Warn("DuckDB telemetry exceeded size ceiling, starting aggressive pruning",
				slog.Int64("current_size_bytes", fi.Size()),
				slog.Int64("max_size_bytes", r.maxSizeBytes),
			)

			// Iteratively purge oldest records in batches of 5000 until size drops or table is cleared
			maxIterations := 20
			for i := 0; i < maxIterations; i++ {
				delRes, delErr := r.db.ExecContext(ctx, `
					DELETE FROM tool_audit_logs 
					WHERE id IN (
						SELECT id FROM tool_audit_logs 
						ORDER BY timestamp ASC 
						LIMIT 5000
					)
				`)
				if delErr != nil {
					break
				}
				affected, _ := delRes.RowsAffected()
				if affected == 0 {
					break
				}

				// Checkpoint after batch
				_, _ = r.db.ExecContext(ctx, "CHECKPOINT;")

				curFi, curErr := os.Stat(r.dbPath)
				if curErr == nil && curFi.Size() <= r.maxSizeBytes {
					slog.Info("DuckDB telemetry file size brought under ceiling",
						slog.Int64("current_size_bytes", curFi.Size()),
					)
					break
				}
			}
		}
	}

	// 3. Issue DuckDB CHECKPOINT to reclaim WAL and compact storage pages
	if _, cpErr := r.db.ExecContext(ctx, "CHECKPOINT;"); cpErr != nil {
		slog.Debug("DuckDB checkpoint execution note", slog.String("info", cpErr.Error()))
	}

	return nil
}

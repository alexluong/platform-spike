// Package outbox drains outbox rows to the authz engine through the
// RelationSync port: synchronously at the end of the request that wrote them,
// and from a background loop for anything left over.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/jackc/pgx/v5/pgxpool"
)

// alertAttempts: log loudly once an event has failed this many times (it is still retried).
const alertAttempts = 10

type Relay struct {
	DB   *pgxpool.Pool
	Sync authz.RelationSync
	Log  *slog.Logger
}

// Drain applies every pending row in id order. One drainer at a time
// (advisory lock) keeps engine writes in commit order per object.
func (r *Relay) Drain(ctx context.Context) error {
	for {
		n, err := r.batch(ctx)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

func (r *Relay) batch(ctx context.Context) (int, error) {
	tx, err := r.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(777)`); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `SELECT id, event, attempts FROM outbox WHERE processed_at IS NULL ORDER BY id LIMIT 100`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id       int64
		ev       authz.Event
		attempts int
	}
	var batch []row
	for rows.Next() {
		var x row
		var raw []byte
		if err := rows.Scan(&x.id, &raw, &x.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		if err := json.Unmarshal(raw, &x.ev); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var applyErr error
	done := 0
	for _, x := range batch {
		if err := r.Sync.Apply(ctx, x.ev); err != nil {
			attempts := x.attempts + 1
			if errors.Is(err, authz.ErrPermanent) {
				// The engine will never take it: dead-letter (processed, with the error) and move on.
				r.Log.Error("outbox event dead-lettered", "id", x.id, "type", x.ev.Type, "err", err)
				if _, err := tx.Exec(ctx, `UPDATE outbox SET attempts=$2, last_error=$3, processed_at=now() WHERE id=$1`, x.id, attempts, "dead: "+err.Error()); err != nil {
					return 0, err
				}
				done++
				continue
			}
			// Transient (engine down, timeout): never drop, since a dropped revocation keeps access
			// forever. Later events wait behind it, in order.
			if attempts == alertAttempts {
				r.Log.Error("outbox event still failing; relay keeps retrying", "id", x.id, "type", x.ev.Type, "attempts", attempts, "err", err)
			}
			_, _ = tx.Exec(ctx, `UPDATE outbox SET attempts=$2, last_error=$3 WHERE id=$1`, x.id, attempts, err.Error())
			applyErr = fmt.Errorf("outbox %d (%s): %w", x.id, x.ev.Type, err)
			break // keep order: later events wait for this one
		}
		if _, err := tx.Exec(ctx, `UPDATE outbox SET processed_at=now(), attempts=attempts+1 WHERE id=$1`, x.id); err != nil {
			return 0, err
		}
		done++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	if applyErr != nil {
		return 0, applyErr
	}
	return done, nil
}

// Run drains every interval until ctx is done.
func (r *Relay) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Drain(ctx); err != nil {
				r.Log.Warn("relay drain", "err", err)
			}
		}
	}
}

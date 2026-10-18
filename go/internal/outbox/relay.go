// Package outbox drains outbox rows to their consumers (the authz engine through the
// RelationSync port; on stack a2 also the IdP's identity sync): synchronously at the
// end of the request that wrote them, and from a background loop for anything left over.
// Each event is written once per consumer that takes it; each consumer drains its own rows.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/jackc/pgx/v5/pgxpool"
)

// alertAttempts: log loudly once an event has failed this many times (it is still retried).
const alertAttempts = 10

// ConsumerAuthz is the authz engine's consumer name (the column default).
const ConsumerAuthz = "authz"

type Relay struct {
	DB   *pgxpool.Pool
	Sync authz.RelationSync
	Log  *slog.Logger
	// Consumer whose rows this relay drains ("" = ConsumerAuthz). Every consumer follows
	// the same retry and dead-letter rules.
	Consumer string
	// Lock is the advisory lock key of this consumer's drainer (0 = 777).
	Lock int32
	// Partitioned: one drainer per partition (merchant) instead of one global drainer;
	// order holds per partition only. A failing row blocks its own partition only.
	Partitioned bool
	// Accepts filters the event types this consumer takes (nil = all).
	Accepts func(evType string) bool
	// Background: the request that wrote a row doesn't wait for it; only the background loop
	// drains this consumer (stack i: provisioning a merchant's Zitadel instance takes seconds,
	// SPEC §16.3 lets the merchant show "provisioning" meanwhile).
	Background bool
	// Workers: partitions drained in parallel (partitioned consumers; 0/1 = one at a time).
	Workers int
}

func (r *Relay) consumer() string {
	if r.Consumer == "" {
		return ConsumerAuthz
	}
	return r.Consumer
}

func (r *Relay) lock() int32 {
	if r.Lock == 0 {
		return 777
	}
	return r.Lock
}

// Drain applies every pending row of this consumer (every partition), in id order.
func (r *Relay) Drain(ctx context.Context) error {
	if !r.Partitioned {
		return r.drainPartition(ctx, nil)
	}
	rows, err := r.DB.Query(ctx, `SELECT DISTINCT partition_key FROM outbox WHERE consumer=$1 AND processed_at IS NULL`, r.consumer())
	if err != nil {
		return err
	}
	var parts []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		parts = append(parts, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	return r.drainPartitions(ctx, parts)
}

func (r *Relay) drainPartitions(ctx context.Context, parts []string) error {
	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
	)
	workers := max(r.Workers, 1)
	sem := make(chan struct{}, workers)
	seen := map[string]bool{}
	for _, p := range parts {
		if seen[p] {
			continue
		}
		seen[p] = true
		sem <- struct{}{}
		wg.Add(1)
		go func(p string) {
			defer func() { <-sem; wg.Done() }()
			if err := r.drainPartition(ctx, &p); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// drainPartition drains one partition (nil = the whole consumer, unpartitioned).
func (r *Relay) drainPartition(ctx context.Context, part *string) error {
	for {
		n, err := r.batch(ctx, part)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

// batch applies up to 100 rows under the drainer's advisory lock. One drainer at a time
// per consumer (per partition when partitioned) keeps writes in order per object.
func (r *Relay) batch(ctx context.Context, part *string) (int, error) {
	tx, err := r.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	q := `SELECT id, event, attempts FROM outbox WHERE consumer=$1 AND processed_at IS NULL ORDER BY id LIMIT 100`
	args := []any{r.consumer()}
	if part == nil {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, int64(r.lock())); err != nil {
			return 0, err
		}
	} else {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::int, hashtext($2))`, r.lock(), *part); err != nil {
			return 0, err
		}
		q = `SELECT id, event, attempts FROM outbox WHERE consumer=$1 AND partition_key=$2 AND processed_at IS NULL ORDER BY id LIMIT 100`
		args = append(args, *part)
	}
	rows, err := tx.Query(ctx, q, args...)
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
				// The consumer will never take it: dead-letter (processed, with the error) and move on.
				r.Log.Error("outbox event dead-lettered", "consumer", r.consumer(), "id", x.id, "type", x.ev.Type, "err", err)
				if _, err := tx.Exec(ctx, `UPDATE outbox SET attempts=$2, last_error=$3, processed_at=now() WHERE id=$1`, x.id, attempts, "dead: "+err.Error()); err != nil {
					return 0, err
				}
				done++
				continue
			}
			// Transient (engine or IdP down, timeout): never drop, since a dropped revocation keeps
			// access forever. Later events wait behind it, in order.
			if attempts == alertAttempts {
				r.Log.Error("outbox event still failing; relay keeps retrying", "consumer", r.consumer(), "id", x.id, "type", x.ev.Type, "attempts", attempts, "err", err)
			}
			_, _ = tx.Exec(ctx, `UPDATE outbox SET attempts=$2, last_error=$3 WHERE id=$1`, x.id, attempts, err.Error())
			applyErr = fmt.Errorf("outbox %s %d (%s): %w", r.consumer(), x.id, x.ev.Type, err)
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
				r.Log.Warn("relay drain", "consumer", r.consumer(), "err", err)
			}
		}
	}
}

// Relays is the outbox seen by the executor (core.Drainer): it routes each event to the
// consumers that take it and drains what a request wrote. Consumers are independent:
// one failing doesn't stop the others.
type Relays []*Relay

func (rs Relays) Routes(ev authz.Event) []core.Route {
	var out []core.Route
	for _, r := range rs {
		if r.Accepts != nil && !r.Accepts(ev.Type) {
			continue
		}
		p := ""
		if r.Partitioned {
			p = ev.MerchantID
		}
		out = append(out, core.Route{Consumer: r.consumer(), Partition: p})
	}
	return out
}

func (rs Relays) Drain(ctx context.Context, written []core.Route) error {
	var errs []error
	for _, r := range rs {
		if r.Background {
			continue
		}
		var parts []string
		wrote := false
		for _, w := range written {
			if w.Consumer == r.consumer() {
				wrote = true
				parts = append(parts, w.Partition)
			}
		}
		if !wrote {
			continue
		}
		var err error
		if r.Partitioned {
			err = r.drainPartitions(ctx, parts)
		} else {
			err = r.Drain(ctx)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DrainAll drains every consumer (startup).
func (rs Relays) DrainAll(ctx context.Context) error {
	var errs []error
	for _, r := range rs {
		if err := r.Drain(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Run starts every consumer's background loop.
func (rs Relays) Run(ctx context.Context, every time.Duration) {
	for _, r := range rs {
		go r.Run(ctx, every)
	}
}

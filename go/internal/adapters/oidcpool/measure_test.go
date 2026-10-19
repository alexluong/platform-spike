package oidcpool

import (
	"context"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/alexluong/platform-spike/go/internal/db"
)

// TestMeasurePools (OIDCPOOL_MEASURE=1): what a pool costs in-process. Provisioning time inside
// one transaction (no HTTP, no app rows), and heap per pool once it's in use: directory entry,
// cached signing key, Sign in with Shop relying party (discovery + key set).
func TestMeasurePools(t *testing.T) {
	if os.Getenv("OIDCPOOL_MEASURE") == "" {
		t.Skip("OIDCPOOL_MEASURE not set")
	}
	e := newEnv(t)
	ctx := context.Background()
	const n = 500
	var times []time.Duration
	var ids []*Pool
	for i := 0; i < n; i++ {
		mid := db.NewID("m")
		start := time.Now()
		tx, _ := e.pool.Begin(ctx)
		if err := e.iss.provisionMerchant(db.WithTx(ctx, tx), mid); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		times = append(times, time.Since(start))
		var pid string
		_ = e.pool.QueryRow(ctx, `SELECT id FROM idp_pools WHERE merchant_id=$1`, mid).Scan(&pid)
		p, _ := e.iss.dir.get(ctx, pid)
		ids = append(ids, p)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	t.Logf("ProvisionMerchant + commit: p50 %v p95 %v max %v", times[n/2], times[n*95/100], times[n-1])

	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	h0 := heap()
	for _, p := range ids {
		if _, err := e.iss.keys.live(ctx, p.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	h1 := heap()
	for _, p := range ids {
		if _, err := e.iss.fed.relyingParty(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	h2 := heap()
	t.Logf("heap per pool: directory+keys %d B, + Shop relying party %d B (n=%d)", int64(h1-h0)/n, int64(h2-h1)/n, n)
}

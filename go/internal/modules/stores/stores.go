// Package stores: stores of a merchant.
package stores

import (
	"context"
	"strings"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
)

type Module struct{}

type Store struct {
	ID         string `json:"id"`
	MerchantID string `json:"merchantId"`
	Name       string `json:"name"`
}

func (m *Module) Ops() []core.Op {
	merchant := func(ctx context.Context, r *core.Req) (core.Target, error) { return scope.Merchant(ctx, r.Tx, r.Path("mid")) }
	store := func(ctx context.Context, r *core.Req) (core.Target, error) { return scope.Store(ctx, r.Tx, r.Path("sid")) }
	return []core.Op{
		{Action: "store.create", Method: "POST", Path: "/api/merchants/{mid}/stores", Status: 201, Target: merchant, Run: m.create},
		{Auth: core.AuthAny, Method: "GET", Path: "/api/merchants/{mid}/stores", Target: merchant, Run: m.list},
		{Action: "store.view", Method: "GET", Path: "/api/stores/{sid}", Target: store, Run: m.get},
	}
}

func (m *Module) create(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		Name string `json:"name"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, core.BadInput("name is required")
	}
	s := Store{ID: db.NewID("s"), MerchantID: r.Target.MerchantID, Name: strings.TrimSpace(in.Name)}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO stores(id, merchant_id, name) VALUES ($1,$2,$3)`, s.ID, s.MerchantID, s.Name); err != nil {
		return nil, err
	}
	return s, r.Emit(ctx, authz.Event{Type: authz.EvStoreCreated, MerchantID: s.MerchantID, StoreID: s.ID})
}

// list: stores of the merchant (SQL, tenant-scoped) the caller has store.view on (batch can).
// Platform staff reach merchant data only through break-glass: without one the list is 403, not
// an empty 200 (SPEC §7). The check holds store.view at the merchant and audits the request.
func (m *Module) list(ctx context.Context, r *core.Req) (any, error) {
	if r.P.Kind == perm.KindPlatform {
		ok, err := r.CanMany(ctx, []core.Check{{Action: "store.view", Target: r.Target}})
		if err != nil {
			return nil, err
		}
		if !ok[0] {
			return nil, core.ErrForbidden
		}
	}
	rows, err := r.Tx.Query(ctx, `SELECT id, merchant_id, name FROM stores WHERE merchant_id=$1 ORDER BY created_at`, r.Target.MerchantID)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Store, error) {
		var s Store
		return s, row.Scan(&s.ID, &s.MerchantID, &s.Name)
	})
	if err != nil {
		return nil, err
	}
	checks := make([]core.Check, len(all))
	for i, s := range all {
		checks[i] = core.Check{Action: "store.view", Target: core.StoreTarget(s.ID, s.MerchantID, nil)}
	}
	ok, err := r.CanMany(ctx, checks)
	if err != nil {
		return nil, err
	}
	items := []Store{}
	for i, s := range all {
		if ok[i] {
			items = append(items, s)
		}
	}
	return map[string]any{"items": items}, nil
}

func (m *Module) get(ctx context.Context, r *core.Req) (any, error) {
	var s Store
	err := r.Tx.QueryRow(ctx, `SELECT id, merchant_id, name FROM stores WHERE id=$1 AND merchant_id=$2`, r.Target.Resource.ID, r.Target.MerchantID).
		Scan(&s.ID, &s.MerchantID, &s.Name)
	return s, err
}

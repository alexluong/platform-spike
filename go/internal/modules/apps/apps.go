// Package apps: installing platform-registered apps on a store with scopes (SPEC §5).
package apps

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/jackc/pgx/v5"
)

type Module struct{}

type Install struct {
	ID      string   `json:"id"`
	AppID   string   `json:"appId"`
	StoreID string   `json:"storeId"`
	Scopes  []string `json:"scopes"`
}

func storeTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	return scope.Store(ctx, r.Tx, r.Path("sid"))
}

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Action: "app.install", Method: "POST", Path: "/api/stores/{sid}/apps", Status: 201, Target: storeTarget, Run: m.install},
		{Action: "app.uninstall", Method: "DELETE", Path: "/api/stores/{sid}/apps/{installId}", Status: 204, Target: storeTarget, Run: m.uninstall},
		{Action: "app.view", Method: "GET", Path: "/api/stores/{sid}/apps", Target: storeTarget, Run: m.list},
	}
}

func (m *Module) install(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		AppID  string   `json:"appId"`
		Scopes []string `json:"scopes"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	var requested []string
	err := r.Tx.QueryRow(ctx, `SELECT scopes FROM apps WHERE id=$1`, in.AppID).Scan(&requested)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound // an unknown id is 404 wherever it appears (SPEC §9)
	} else if err != nil {
		return nil, err
	}
	scopes := core.Dedupe(in.Scopes)
	for _, s := range scopes {
		if !slices.Contains(requested, s) {
			return nil, core.E(http.StatusBadRequest, "scope_not_requested", s)
		}
	}
	// The installer must hold every scope they grant, at this store.
	if ok, err := r.HoldsAll(ctx, r.Target, scopes, core.Unlimited); err != nil {
		return nil, err
	} else if !ok {
		return nil, core.ErrEscalation
	}
	inst := Install{ID: db.NewID("inst"), AppID: in.AppID, StoreID: r.Target.Resource.ID, Scopes: scopes}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO app_installs(id, merchant_id, store_id, app_id, scopes) VALUES ($1,$2,$3,$4,$5)`,
		inst.ID, r.Target.MerchantID, inst.StoreID, inst.AppID, inst.Scopes); err != nil {
		return nil, err
	}
	return inst, r.Emit(ctx, authz.Event{Type: authz.EvAppInstalled, MerchantID: r.Target.MerchantID, StoreID: inst.StoreID,
		InstallID: inst.ID, AppID: inst.AppID, Permissions: inst.Scopes})
}

func (m *Module) uninstall(ctx context.Context, r *core.Req) (any, error) {
	var appID string
	err := r.Tx.QueryRow(ctx, `DELETE FROM app_installs WHERE id=$1 AND store_id=$2 AND merchant_id=$3 RETURNING app_id`,
		r.Path("installId"), r.Target.Resource.ID, r.Target.MerchantID).Scan(&appID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return nil, r.Emit(ctx, authz.Event{Type: authz.EvAppUninstalled, MerchantID: r.Target.MerchantID, StoreID: r.Target.Resource.ID,
		InstallID: r.Path("installId"), AppID: appID})
}

func (m *Module) list(ctx context.Context, r *core.Req) (any, error) {
	rows, err := r.Tx.Query(ctx, `SELECT id, app_id, store_id, scopes FROM app_installs WHERE store_id=$1 AND merchant_id=$2 ORDER BY created_at`,
		r.Target.Resource.ID, r.Target.MerchantID)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Install, error) {
		var x Install
		return x, row.Scan(&x.ID, &x.AppID, &x.StoreID, &x.Scopes)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": core.NonNil(items)}, nil
}

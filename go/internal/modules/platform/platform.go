// Package platform: platform staff actions (merchants, apps, break-glass, audit). SPEC §7.
package platform

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
)

type Module struct {
	IdP identity.Provisioner
}

type Merchant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

func platformTarget(context.Context, *core.Req) (core.Target, error) { return core.PlatformTarget, nil }

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Action: "platform.merchant.create", Method: "POST", Path: "/api/platform/merchants", Status: 201, Target: platformTarget, Run: m.createMerchant},
		{Action: "platform.merchant.view", Method: "GET", Path: "/api/platform/merchants", Target: platformTarget, Run: m.listMerchants},
		{Action: "platform.merchant.suspend", Method: "POST", Path: "/api/platform/merchants/{mid}/suspend", Target: platformTarget, Run: m.setStatus("suspended")},
		{Action: "platform.merchant.suspend", Method: "POST", Path: "/api/platform/merchants/{mid}/reinstate", Target: platformTarget, Run: m.setStatus("active")},
		{Action: "platform.app.register", Method: "POST", Path: "/api/platform/apps", Status: 201, Target: platformTarget, Run: m.registerApp},
		{Action: "platform.break_glass", Method: "POST", Path: "/api/platform/break-glass", Status: 201, Target: breakGlassTarget, Run: m.breakGlass},
		{Action: "platform.audit.view", Method: "GET", Path: "/api/platform/audit", Target: platformTarget, Run: m.audit},
	}
}

func (m *Module) createMerchant(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		Name        string `json:"name"`
		OwnerUserID string `json:"ownerUserId"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || in.OwnerUserID == "" {
		return nil, core.BadInput("name and ownerUserId are required")
	}
	var kind string
	var current *string
	err := r.Tx.QueryRow(ctx, `SELECT kind, merchant_id FROM users WHERE id=$1 FOR UPDATE`, in.OwnerUserID).Scan(&kind, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.E(http.StatusBadRequest, "invalid_input", "owner user not found")
	} else if err != nil {
		return nil, err
	}
	if kind != string(perm.KindUser) {
		return nil, core.BadInput("owner must be a merchant user")
	}
	if current != nil {
		return nil, core.Conflict("already_member")
	}
	mer := Merchant{ID: db.NewID("m"), Name: in.Name, Status: "active"}
	aid := db.NewID("ra")
	if _, err := r.Tx.Exec(ctx, `INSERT INTO merchants(id, name, status) VALUES ($1,$2,'active')`, mer.ID, mer.Name); err != nil {
		return nil, err
	}
	if _, err := r.Tx.Exec(ctx, `UPDATE users SET merchant_id=$2 WHERE id=$1`, in.OwnerUserID, mer.ID); err != nil {
		return nil, err
	}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO role_assignments(id, merchant_id, user_id, role_id, scope_type, scope_id) VALUES ($1,$2,$3,'owner','merchant',$2)`,
		aid, mer.ID, in.OwnerUserID); err != nil {
		return nil, err
	}
	if err := r.Emit(ctx, authz.Event{Type: authz.EvMerchantCreated, MerchantID: mer.ID}); err != nil {
		return nil, err
	}
	if err := r.Emit(ctx, authz.Event{Type: authz.EvAssignmentCreated, MerchantID: mer.ID, AssignmentID: aid, UserID: in.OwnerUserID,
		RoleID: perm.RoleOwner, ScopeType: "merchant", ScopeID: mer.ID}); err != nil {
		return nil, err
	}
	return mer, nil
}

func (m *Module) listMerchants(ctx context.Context, r *core.Req) (any, error) {
	rows, err := r.Tx.Query(ctx, `SELECT id, name, status FROM merchants ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Merchant, error) {
		var x Merchant
		return x, row.Scan(&x.ID, &x.Name, &x.Status)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": core.NonNil(items)}, nil
}

func (m *Module) setStatus(status string) func(context.Context, *core.Req) (any, error) {
	return func(ctx context.Context, r *core.Req) (any, error) {
		mid := r.Path("mid")
		var mer Merchant
		err := r.Tx.QueryRow(ctx, `UPDATE merchants SET status=$2 WHERE id=$1 RETURNING id, name, status`, mid, status).
			Scan(&mer.ID, &mer.Name, &mer.Status)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.ErrNotFound
		} else if err != nil {
			return nil, err
		}
		ev := authz.EvMerchantReinstated
		if status == "suspended" {
			ev = authz.EvMerchantSuspended
		}
		if err := r.Emit(ctx, authz.Event{Type: ev, MerchantID: mid}); err != nil {
			return nil, err
		}
		return map[string]any{"id": mer.ID, "status": mer.Status}, nil
	}
}

func (m *Module) registerApp(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, core.BadInput("name is required")
	}
	for _, s := range in.Scopes {
		if !perm.IsGrantable(s) {
			return nil, core.E(http.StatusBadRequest, "not_grantable", s)
		}
		if !perm.IsGrantableToApps(s) {
			return nil, core.E(http.StatusBadRequest, "not_grantable_to_apps", s)
		}
	}
	id := db.NewID("app")
	c, err := m.IdP.CreateClient(ctx, id)
	if err != nil {
		return nil, err
	}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO apps(id, name, scopes, client_id, idp_subject) VALUES ($1,$2,$3,$4,$5)`,
		id, in.Name, core.Dedupe(in.Scopes), c.ClientID, c.Subject); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "clientId": c.ClientID, "clientSecret": c.ClientSecret}, nil
}

type breakGlassIn struct {
	MerchantID string `json:"merchantId"`
	Reason     string `json:"reason"`
	Minutes    int    `json:"minutes"`
}

func breakGlassTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	var in breakGlassIn
	if err := r.Decode(&in); err != nil {
		return core.Target{}, err
	}
	if in.MerchantID == "" {
		return core.Target{}, core.BadInput("merchantId is required")
	}
	return scope.Merchant(ctx, r.Tx, in.MerchantID)
}

func (m *Module) breakGlass(ctx context.Context, r *core.Req) (any, error) {
	var in breakGlassIn
	_ = r.Decode(&in)
	if strings.TrimSpace(in.Reason) == "" || in.Minutes <= 0 || in.Minutes > 24*60 {
		return nil, core.BadInput("reason and minutes (1..1440) are required")
	}
	id := db.NewID("bg")
	exp := r.Now.Add(time.Duration(in.Minutes) * time.Minute).UTC()
	if _, err := r.Tx.Exec(ctx, `INSERT INTO break_glass(id, merchant_id, staff_id, reason, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		id, in.MerchantID, r.P.ID, in.Reason, exp); err != nil {
		return nil, err
	}
	if err := core.Audit(ctx, r.Tx, r.P.ID, "platform.break_glass", in.MerchantID, r.Now); err != nil {
		return nil, err
	}
	if err := r.Emit(ctx, authz.Event{Type: authz.EvBreakGlassOpened, MerchantID: in.MerchantID, UserID: r.P.ID, ExpiresAt: &exp}); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "expiresAt": exp}, nil
}

func (m *Module) audit(ctx context.Context, r *core.Req) (any, error) {
	type entry struct {
		Actor      string    `json:"actor"`
		Action     string    `json:"action"`
		MerchantID *string   `json:"merchantId"`
		At         time.Time `json:"at"`
	}
	q := `SELECT actor, action, merchant_id, at FROM audit`
	args := []any{}
	if mid := r.HTTP.URL.Query().Get("merchantId"); mid != "" {
		q += ` WHERE merchant_id=$1`
		args = append(args, mid)
	}
	rows, err := r.Tx.Query(ctx, q+` ORDER BY id DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (entry, error) {
		var e entry
		return e, row.Scan(&e.Actor, &e.Action, &e.MerchantID, &e.At)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": core.NonNil(items)}, nil
}

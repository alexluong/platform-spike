// Package roles: system + custom roles and role assignments, with the
// no-escalation guardrails (SPEC §3). Custom roles are data; the platform's
// policy (schema) never changes when a merchant edits a role.
package roles

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
)

type Module struct{}

type Role struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	System           bool     `json:"system"`
	Permissions      []string `json:"permissions"`
	RefundLimitCents *int64   `json:"refundLimitCents,omitempty"`
}

type Scope struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Assignment struct {
	ID     string `json:"id"`
	UserID string `json:"userId"`
	RoleID string `json:"roleId"`
	Scope  Scope  `json:"scope"`
}

var errSystemRole = core.E(http.StatusForbidden, "system_role", "system roles cannot be changed")

func merchantTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	return scope.Merchant(ctx, r.Tx, r.Path("mid"))
}

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Action: "merchant.view", Method: "GET", Path: "/api/merchants/{mid}/roles", Target: merchantTarget, Run: m.list},
		{Action: "role.manage", Method: "POST", Path: "/api/merchants/{mid}/roles", Status: 201, Target: merchantTarget, Run: m.create},
		{Action: "role.manage", Method: "PATCH", Path: "/api/merchants/{mid}/roles/{rid}", Target: merchantTarget, Run: m.update},
		{Action: "role.manage", Method: "DELETE", Path: "/api/merchants/{mid}/roles/{rid}", Status: 204, Target: merchantTarget, Run: m.delete},
		{Action: "role.manage", Method: "POST", Path: "/api/merchants/{mid}/role-assignments", Status: 201, Target: m.assignTarget, Run: m.assign},
		{Action: "role.manage", Method: "DELETE", Path: "/api/merchants/{mid}/role-assignments/{aid}", Status: 204, Target: m.unassignTarget, Run: m.unassign},
	}
}

// Load returns a role visible in merchant mid (system or the merchant's custom role).
func Load(ctx context.Context, q core.Querier, mid, rid string) (*Role, error) {
	if sr, ok := perm.GetSystemRole(rid); ok {
		return &Role{ID: sr.ID, Name: sr.Name, System: true, Permissions: sr.Permissions}, nil
	}
	var x Role
	err := q.QueryRow(ctx, `SELECT id, name, permissions, refund_limit_cents FROM roles WHERE id=$1 AND merchant_id=$2`, rid, mid).
		Scan(&x.ID, &x.Name, &x.Permissions, &x.RefundLimitCents)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return &x, err
}

func (m *Module) list(ctx context.Context, r *core.Req) (any, error) {
	items := []Role{}
	for _, sr := range perm.SystemRoles {
		items = append(items, Role{ID: sr.ID, Name: sr.Name, System: true, Permissions: sr.Permissions})
	}
	rows, err := r.Tx.Query(ctx, `SELECT id, name, permissions, refund_limit_cents FROM roles WHERE merchant_id=$1 ORDER BY created_at`, r.Path("mid"))
	if err != nil {
		return nil, err
	}
	custom, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Role, error) {
		var x Role
		return x, row.Scan(&x.ID, &x.Name, &x.Permissions, &x.RefundLimitCents)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": append(items, custom...)}, nil
}

func validatePerms(ps []string) ([]string, error) {
	ps = core.Dedupe(ps)
	for _, p := range ps {
		if !perm.IsGrantable(p) {
			return nil, core.E(http.StatusBadRequest, "not_grantable", p)
		}
	}
	return ps, nil
}

// guard: the caller must hold every permission of the role at t, and a refund
// limit at least as high as the role's (SPEC §3 guardrails), through can().
func guard(ctx context.Context, r *core.Req, t core.Target, perms []string, limit *int64) error {
	amount := core.Unlimited
	if limit != nil {
		amount = *limit
	}
	ok, err := r.HoldsAll(ctx, t, perms, amount)
	if err != nil {
		return err
	}
	if !ok {
		return core.ErrEscalation
	}
	return nil
}

type roleIn struct {
	Name             *string   `json:"name"`
	Permissions      *[]string `json:"permissions"`
	RefundLimitCents *int64    `json:"refundLimitCents"`
}

func (m *Module) create(ctx context.Context, r *core.Req) (any, error) {
	var in roleIn
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" || in.Permissions == nil {
		return nil, core.BadInput("name and permissions are required")
	}
	ps, err := validatePerms(*in.Permissions)
	if err != nil {
		return nil, err
	}
	if in.RefundLimitCents != nil && (*in.RefundLimitCents < 0 || *in.RefundLimitCents > core.MaxCents) {
		return nil, core.BadInput("refundLimitCents must be >= 0")
	}
	if err := guard(ctx, r, r.Target, ps, in.RefundLimitCents); err != nil {
		return nil, err
	}
	role := Role{ID: db.NewID("r"), Name: strings.TrimSpace(*in.Name), Permissions: ps, RefundLimitCents: in.RefundLimitCents}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO roles(id, merchant_id, name, permissions, refund_limit_cents) VALUES ($1,$2,$3,$4,$5)`,
		role.ID, r.Target.MerchantID, role.Name, role.Permissions, role.RefundLimitCents); err != nil {
		return nil, err
	}
	return role, emitRole(ctx, r, &role)
}

func emitRole(ctx context.Context, r *core.Req, role *Role) error {
	return r.Emit(ctx, authz.Event{Type: authz.EvRoleUpserted, MerchantID: r.Target.MerchantID, RoleID: role.ID,
		Permissions: role.Permissions, RefundLimitCents: role.RefundLimitCents})
}

func (m *Module) update(ctx context.Context, r *core.Req) (any, error) {
	var raw map[string]any
	if err := r.Decode(&raw); err != nil {
		return nil, err
	}
	var in roleIn
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	rid := r.Path("rid")
	if _, ok := perm.GetSystemRole(rid); ok {
		return nil, errSystemRole
	}
	role, err := Load(ctx, r.Tx, r.Target.MerchantID, rid)
	if err != nil {
		return nil, err
	}
	next := *role
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			return nil, core.BadInput("name must not be empty")
		}
		next.Name = strings.TrimSpace(*in.Name)
	}
	if in.Permissions != nil {
		if next.Permissions, err = validatePerms(*in.Permissions); err != nil {
			return nil, err
		}
	}
	if _, present := raw["refundLimitCents"]; present {
		next.RefundLimitCents = in.RefundLimitCents // explicit null removes the limit
		if in.RefundLimitCents != nil && (*in.RefundLimitCents < 0 || *in.RefundLimitCents > core.MaxCents) {
			return nil, core.BadInput("refundLimitCents must be >= 0")
		}
	}
	// Must hold the role before and after the edit: old ∪ new permissions, the higher limit.
	union := core.Dedupe(append(slices.Clone(role.Permissions), next.Permissions...))
	if err := guard(ctx, r, r.Target, union, higher(role.RefundLimitCents, next.RefundLimitCents)); err != nil {
		return nil, err
	}
	if _, err := r.Tx.Exec(ctx, `UPDATE roles SET name=$2, permissions=$3, refund_limit_cents=$4 WHERE id=$1`,
		next.ID, next.Name, next.Permissions, next.RefundLimitCents); err != nil {
		return nil, err
	}
	return next, emitRole(ctx, r, &next)
}

// higher returns the larger limit; nil (no limit) is highest.
func higher(a, b *int64) *int64 {
	if a == nil || b == nil {
		return nil
	}
	if *a > *b {
		return a
	}
	return b
}

func (m *Module) delete(ctx context.Context, r *core.Req) (any, error) {
	rid := r.Path("rid")
	if _, ok := perm.GetSystemRole(rid); ok {
		return nil, errSystemRole
	}
	role, err := Load(ctx, r.Tx, r.Target.MerchantID, rid)
	if err != nil {
		return nil, err
	}
	if err := guard(ctx, r, r.Target, role.Permissions, role.RefundLimitCents); err != nil {
		return nil, err
	}
	rows, err := r.Tx.Query(ctx, `DELETE FROM role_assignments WHERE role_id=$1 AND merchant_id=$2 RETURNING id, user_id, scope_type, scope_id`, rid, r.Target.MerchantID)
	if err != nil {
		return nil, err
	}
	gone, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Assignment, error) {
		var a Assignment
		return a, row.Scan(&a.ID, &a.UserID, &a.Scope.Type, &a.Scope.ID)
	})
	if err != nil {
		return nil, err
	}
	for _, a := range gone {
		if err := r.Emit(ctx, authz.Event{Type: authz.EvAssignmentDeleted, MerchantID: r.Target.MerchantID, AssignmentID: a.ID,
			UserID: a.UserID, RoleID: rid, ScopeType: a.Scope.Type, ScopeID: a.Scope.ID}); err != nil {
			return nil, err
		}
	}
	if _, err := r.Tx.Exec(ctx, `DELETE FROM roles WHERE id=$1`, rid); err != nil {
		return nil, err
	}
	return nil, r.Emit(ctx, authz.Event{Type: authz.EvRoleDeleted, MerchantID: r.Target.MerchantID, RoleID: rid})
}

type assignIn struct {
	UserID string `json:"userId"`
	RoleID string `json:"roleId"`
	Scope  Scope  `json:"scope"`
}

// scopeTarget resolves an assignment scope inside merchant mid.
func scopeTarget(ctx context.Context, q core.Querier, mid string, s Scope) (core.Target, error) {
	switch s.Type {
	case "merchant":
		if s.ID != mid {
			return core.Target{}, core.BadInput("merchant scope must be this merchant")
		}
		return scope.Merchant(ctx, q, mid)
	case "store":
		t, err := scope.Store(ctx, q, s.ID)
		if err != nil {
			return t, err
		}
		if t.MerchantID != mid {
			return core.Target{}, core.ErrNotFound
		}
		return t, nil
	}
	return core.Target{}, core.BadInput("scope.type must be merchant or store")
}

func (m *Module) assignTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	mid := r.Path("mid")
	if _, err := scope.Merchant(ctx, r.Tx, mid); err != nil {
		return core.Target{}, err
	}
	var in assignIn
	if err := r.Decode(&in); err != nil {
		return core.Target{}, err
	}
	return scopeTarget(ctx, r.Tx, mid, in.Scope)
}

func (m *Module) assign(ctx context.Context, r *core.Req) (any, error) {
	var in assignIn
	_ = r.Decode(&in)
	mid := r.Path("mid")
	if in.UserID == "" || in.RoleID == "" {
		return nil, core.BadInput("userId and roleId are required")
	}
	var member *string
	// FOR SHARE: a concurrent member removal (FOR UPDATE on the user) can't slip between
	// this check and the insert and leave an assignment on a non-member.
	err := r.Tx.QueryRow(ctx, `SELECT merchant_id FROM users WHERE id=$1 FOR SHARE`, in.UserID).Scan(&member)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if member == nil || *member != mid {
		return nil, core.E(http.StatusBadRequest, "not_member", "user is not a member of this merchant")
	}
	role, err := Load(ctx, r.Tx, mid, in.RoleID)
	if err != nil {
		return nil, err
	}
	if role.ID == perm.RoleOwner {
		if err := ownerRule(ctx, r, mid); err != nil {
			return nil, err
		}
	}
	if err := guard(ctx, r, r.Target, role.Permissions, role.RefundLimitCents); err != nil {
		return nil, err
	}
	var dup string
	err = r.Tx.QueryRow(ctx, `SELECT id FROM role_assignments WHERE user_id=$1 AND role_id=$2 AND scope_type=$3 AND scope_id=$4`,
		in.UserID, in.RoleID, in.Scope.Type, in.Scope.ID).Scan(&dup)
	if err == nil {
		return nil, core.Conflict("already_assigned")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	a := Assignment{ID: db.NewID("ra"), UserID: in.UserID, RoleID: in.RoleID, Scope: in.Scope}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO role_assignments(id, merchant_id, user_id, role_id, scope_type, scope_id) VALUES ($1,$2,$3,$4,$5,$6)`,
		a.ID, mid, a.UserID, a.RoleID, a.Scope.Type, a.Scope.ID); err != nil {
		return nil, err
	}
	return a, r.Emit(ctx, authz.Event{Type: authz.EvAssignmentCreated, MerchantID: mid, AssignmentID: a.ID, UserID: a.UserID,
		RoleID: a.RoleID, ScopeType: a.Scope.Type, ScopeID: a.Scope.ID})
}

// ownerRule: only an owner can assign or remove the owner role.
func ownerRule(ctx context.Context, r *core.Req, mid string) error {
	ok, err := r.Can(ctx, "role.manage_owner", core.MerchantTarget(mid), nil)
	if err != nil {
		return err
	}
	if !ok {
		return core.E(http.StatusForbidden, "forbidden", "only an owner can manage the owner role")
	}
	return nil
}

func (m *Module) unassignTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	mid := r.Path("mid")
	var a Assignment
	err := r.Tx.QueryRow(ctx, `SELECT id, user_id, role_id, scope_type, scope_id FROM role_assignments WHERE id=$1 AND merchant_id=$2 FOR UPDATE`,
		r.Path("aid"), mid).Scan(&a.ID, &a.UserID, &a.RoleID, &a.Scope.Type, &a.Scope.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := scope.Merchant(ctx, r.Tx, mid); err != nil {
			return core.Target{}, err
		}
		return core.Target{}, core.ErrNotFound
	} else if err != nil {
		return core.Target{}, err
	}
	t, err := scopeTarget(ctx, r.Tx, mid, a.Scope)
	if err != nil {
		return t, err
	}
	t.Data = &a
	return t, nil
}

func (m *Module) unassign(ctx context.Context, r *core.Req) (any, error) {
	a := r.Target.Data.(*Assignment)
	mid := r.Path("mid")
	if a.RoleID == perm.RoleOwner {
		if err := ownerRule(ctx, r, mid); err != nil {
			return nil, err
		}
		if a.Scope.Type == "merchant" {
			var n int
			if err := r.Tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT id FROM role_assignments WHERE merchant_id=$1 AND role_id='owner' AND scope_type='merchant' FOR UPDATE) x`, mid).Scan(&n); err != nil {
				return nil, err
			}
			if n <= 1 {
				return nil, core.Conflict("last_owner")
			}
		}
	}
	if _, err := r.Tx.Exec(ctx, `DELETE FROM role_assignments WHERE id=$1`, a.ID); err != nil {
		return nil, err
	}
	return nil, r.Emit(ctx, authz.Event{Type: authz.EvAssignmentDeleted, MerchantID: mid, AssignmentID: a.ID, UserID: a.UserID,
		RoleID: a.RoleID, ScopeType: a.Scope.Type, ScopeID: a.Scope.ID})
}

// SystemRoleEvents are the outbox events that keep the engine's copy of the
// system roles current. The composition root enqueues them at every start, so
// a permission the platform adds reaches owner/admin without a migration.
func SystemRoleEvents() []authz.Event {
	var out []authz.Event
	for _, sr := range perm.SystemRoles {
		out = append(out, authz.Event{Type: authz.EvRoleUpserted, RoleID: sr.ID, Permissions: sr.Permissions, OwnerRole: sr.ID == perm.RoleOwner})
	}
	return out
}

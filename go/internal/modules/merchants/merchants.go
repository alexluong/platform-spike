// Package merchants: merchant view, membership and invitations. SPEC §9 Merchant, §15.2.
package merchants

import (
	"context"
	"errors"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
)

type Module struct {
	// MultiMerchant: a platform account may be a member of several merchants (SPEC §16.2,
	// round-4 stacks). Off: one merchant per user (409 already_member).
	MultiMerchant bool
}

// StatusSQL: the status a client sees. A merchant whose tenant pool is still being
// provisioned (SPEC §16.3) shows "provisioning" until it is ready, unless suspended.
const StatusSQL = `CASE WHEN status='active' AND NOT pool_ready THEN 'provisioning' ELSE status END`

func merchantTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	return scope.Merchant(ctx, r.Tx, r.Path("mid"))
}

func (m *Module) Ops() []core.Op {
	return append([]core.Op{
		{Action: "merchant.view", Method: "GET", Path: "/api/merchants/{mid}", Target: merchantTarget, Run: m.get},
		{Action: "member.manage", Method: "POST", Path: "/api/merchants/{mid}/members", Status: 201, Target: merchantTarget, Run: m.addMember},
		{Action: "member.manage", Method: "DELETE", Path: "/api/merchants/{mid}/members/{uid}", Status: 204, Target: merchantTarget, Run: m.removeMember},
	}, m.invitationOps()...)
}

func (m *Module) get(ctx context.Context, r *core.Req) (any, error) {
	var id, name, status string
	if err := r.Tx.QueryRow(ctx, `SELECT id, name, `+StatusSQL+` FROM merchants WHERE id=$1`, r.Path("mid")).Scan(&id, &name, &status); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name, "status": status}, nil
}

func (m *Module) addMember(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		UserID string `json:"userId"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if in.UserID == "" {
		return nil, core.BadInput("userId is required")
	}
	mid := r.Path("mid")
	var kind string
	var subject, home *string
	var memberships int
	var here bool
	err := r.Tx.QueryRow(ctx, `SELECT kind, idp_subject, home_merchant_id,
		  (SELECT count(*) FROM memberships WHERE user_id=users.id),
		  EXISTS(SELECT 1 FROM memberships WHERE user_id=users.id AND merchant_id=$2)
		FROM users WHERE id=$1 FOR UPDATE`, in.UserID, mid).Scan(&kind, &subject, &home, &memberships, &here)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	// Another merchant's tenant staff (SPEC §16.2): they exist only in that merchant's pool.
	// Hidden like any cross-tenant resource.
	if home != nil && *home != mid {
		return nil, core.ErrNotFound
	}
	if kind != string(perm.KindUser) {
		return nil, core.BadInput("only merchant users can be members")
	}
	if here || (memberships > 0 && !m.MultiMerchant) {
		return nil, core.Conflict("already_member") // one merchant per user unless MultiMerchant
	}
	// The executor's suspension check reads the merchant without a lock. Lock it here (as
	// invitation accept does) so a concurrent suspend either waits for this join, and its
	// outbox row lands after member.added, or wins and the join is refused. Without it a join
	// committed after the suspend reached the IdP after the suspension's fan-out, and the new
	// member could log in to a suspended merchant (review-a2 finding 1).
	var mstatus string
	if err := r.Tx.QueryRow(ctx, `SELECT status FROM merchants WHERE id=$1 FOR SHARE`, mid).Scan(&mstatus); err != nil {
		return nil, err
	}
	if mstatus == "suspended" {
		return nil, core.ErrMerchantSuspended
	}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO memberships(user_id, merchant_id) VALUES ($1,$2)`, in.UserID, mid); err != nil {
		return nil, err
	}
	if err := r.Emit(ctx, authz.Event{Type: authz.EvMemberAdded, MerchantID: mid, UserID: in.UserID, Subject: deref(subject)}); err != nil {
		return nil, err
	}
	return map[string]any{"userId": in.UserID, "merchantId": mid}, nil
}

func (m *Module) removeMember(ctx context.Context, r *core.Req) (any, error) {
	mid, uid := r.Path("mid"), r.Path("uid")
	var subject *string
	var member bool
	err := r.Tx.QueryRow(ctx, `SELECT idp_subject, EXISTS(SELECT 1 FROM memberships WHERE user_id=users.id AND merchant_id=$2)
		FROM users WHERE id=$1 FOR UPDATE`, uid, mid).Scan(&subject, &member)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err != nil || !member {
		return nil, core.ErrNotFound
	}
	// Lock the merchant's owner assignments, then apply the owner rules.
	rows, err := r.Tx.Query(ctx, `SELECT id, user_id, role_id, scope_type, scope_id FROM role_assignments WHERE merchant_id=$1 FOR UPDATE`, mid)
	if err != nil {
		return nil, err
	}
	type asg struct{ id, user, role, st, sid string }
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (asg, error) {
		var a asg
		return a, row.Scan(&a.id, &a.user, &a.role, &a.st, &a.sid)
	})
	if err != nil {
		return nil, err
	}
	var mine []asg
	owners, myOwners := 0, 0
	for _, a := range all {
		isOwner := a.role == perm.RoleOwner && a.st == "merchant"
		if isOwner {
			owners++
		}
		if a.user == uid {
			mine = append(mine, a)
			if isOwner {
				myOwners++
			}
		}
	}
	if myOwners > 0 {
		if ok, err := r.Can(ctx, "role.manage_owner", core.MerchantTarget(mid), nil); err != nil {
			return nil, err
		} else if !ok {
			return nil, core.ErrForbidden
		}
		if owners-myOwners < 1 {
			return nil, core.Conflict("last_owner")
		}
	}
	for _, a := range mine {
		if _, err := r.Tx.Exec(ctx, `DELETE FROM role_assignments WHERE id=$1`, a.id); err != nil {
			return nil, err
		}
		if err := r.Emit(ctx, authz.Event{Type: authz.EvAssignmentDeleted, MerchantID: mid, AssignmentID: a.id, UserID: a.user,
			RoleID: a.role, ScopeType: a.st, ScopeID: a.sid}); err != nil {
			return nil, err
		}
	}
	if _, err := r.Tx.Exec(ctx, `DELETE FROM memberships WHERE user_id=$1 AND merchant_id=$2`, uid, mid); err != nil {
		return nil, err
	}
	return nil, r.Emit(ctx, authz.Event{Type: authz.EvMemberRemoved, MerchantID: mid, UserID: uid, Subject: deref(subject)})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

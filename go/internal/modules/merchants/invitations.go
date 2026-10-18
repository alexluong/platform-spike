package merchants

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
)

// Invitations (SPEC §15.2): app-side. The invitee is an existing user who joins on accept.
// IdP-neutral: joining emits member.added like POST /members, so an IdP that owns
// membership (stack a2) learns about it through the outbox.

type Invitation struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Status string `json:"status"`
}

func (m *Module) invitationOps() []core.Op {
	return []core.Op{
		{Action: "member.manage", Method: "POST", Path: "/api/merchants/{mid}/invitations", Status: 201, Target: merchantTarget, Run: m.invite},
		{Action: "member.manage", Method: "GET", Path: "/api/merchants/{mid}/invitations", Target: merchantTarget, Run: m.listInvitations},
		{Action: "member.manage", Method: "DELETE", Path: "/api/merchants/{mid}/invitations/{iid}", Status: 204, Target: merchantTarget, Run: m.cancelInvitation},
		// Any authenticated principal; Run checks it is the invited user.
		{Auth: core.AuthAny, Method: "POST", Path: "/api/invitations/{iid}/accept", Run: m.acceptInvitation},
	}
}

func (m *Module) invite(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		Email string `json:"email"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, core.BadInput("email is required")
	}
	inv := Invitation{ID: db.NewID("inv"), Email: email, Status: "pending"}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO invitations(id, merchant_id, email, invited_by) VALUES ($1,$2,$3,$4)`,
		inv.ID, r.Target.MerchantID, inv.Email, r.P.ID); err != nil {
		return nil, err
	}
	return inv, nil
}

func (m *Module) listInvitations(ctx context.Context, r *core.Req) (any, error) {
	rows, err := r.Tx.Query(ctx, `SELECT id, email, status FROM invitations WHERE merchant_id=$1 ORDER BY created_at DESC`, r.Target.MerchantID)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Invitation, error) {
		var x Invitation
		return x, row.Scan(&x.ID, &x.Email, &x.Status)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": core.NonNil(items)}, nil
}

func (m *Module) cancelInvitation(ctx context.Context, r *core.Req) (any, error) {
	tag, err := r.Tx.Exec(ctx, `UPDATE invitations SET status='cancelled' WHERE id=$1 AND merchant_id=$2 AND status='pending'`,
		r.Path("iid"), r.Target.MerchantID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, core.ErrNotFound
	}
	return nil, nil
}

// acceptInvitation: the invited user (email match, case-insensitive) joins with no roles.
// Order: unknown or someone else's invitation → 404 (not revealed); not pending → 409;
// caller already in a merchant → 409 already_member; merchant suspended → 403.
func (m *Module) acceptInvitation(ctx context.Context, r *core.Req) (any, error) {
	if r.P.Kind != perm.KindUser {
		return nil, core.ErrForbidden
	}
	var mid, email, status string
	err := r.Tx.QueryRow(ctx, `SELECT merchant_id, email, status FROM invitations WHERE id=$1 FOR UPDATE`, r.Path("iid")).Scan(&mid, &email, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	var myEmail, subject string
	if err := r.Tx.QueryRow(ctx, `SELECT coalesce(email,''), coalesce(idp_subject,'') FROM users WHERE id=$1 FOR UPDATE`, r.P.ID).Scan(&myEmail, &subject); err != nil {
		return nil, err
	}
	if !strings.EqualFold(myEmail, email) {
		return nil, core.ErrNotFound
	}
	if status != "pending" {
		return nil, core.E(http.StatusConflict, "invitation_not_pending", status)
	}
	if err := CanJoin(ctx, r.Tx, r.P.ID, mid, m.MultiMerchant); err != nil {
		return nil, err
	}
	// FOR SHARE: a concurrent suspend waits for this join (and then disables the new member too).
	var mstatus string
	if err := r.Tx.QueryRow(ctx, `SELECT status FROM merchants WHERE id=$1 FOR SHARE`, mid).Scan(&mstatus); err != nil {
		return nil, err
	}
	if mstatus == "suspended" {
		return nil, core.ErrMerchantSuspended
	}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO memberships(user_id, merchant_id) VALUES ($1,$2)`, r.P.ID, mid); err != nil {
		return nil, err
	}
	if _, err := r.Tx.Exec(ctx, `UPDATE invitations SET status='accepted', accepted_by=$2 WHERE id=$1`, r.Path("iid"), r.P.ID); err != nil {
		return nil, err
	}
	if err := r.Emit(ctx, authz.Event{Type: authz.EvMemberAdded, MerchantID: mid, UserID: r.P.ID, Subject: subject}); err != nil {
		return nil, err
	}
	return map[string]any{"merchantId": mid}, nil
}

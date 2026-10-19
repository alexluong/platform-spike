// Package agents: AI agents registered by merchant users, acting for the user
// who granted them, with expiring grants (SPEC §6).
package agents

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

const maxGrantSeconds = 365 * 24 * 3600

type Module struct {
	IdP identity.Provisioner
}

func storeTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	return scope.Store(ctx, r.Tx, r.Path("sid"))
}

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Auth: core.AuthAny, Method: "POST", Path: "/api/agents", Status: 201, Run: m.register},
		{Action: "agent.grant", Method: "POST", Path: "/api/stores/{sid}/agent-grants", Status: 201, Target: storeTarget, Run: m.grant},
		{Action: "agent.grant", Method: "DELETE", Path: "/api/stores/{sid}/agent-grants/{gid}", Status: 204, Target: storeTarget, Run: m.revoke},
	}
}

// register: any merchant user (SPEC §9).
func (m *Module) register(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		Name       string `json:"name"`
		MerchantID string `json:"merchantId"` // partners in several merchants (SPEC §16.2) name one
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if r.P.Kind != perm.KindUser || len(r.P.MerchantIDs) == 0 {
		return nil, core.ErrForbidden
	}
	mid := r.P.MerchantID
	if in.MerchantID != "" {
		if !r.P.IsMemberOf(in.MerchantID) {
			return nil, core.ErrForbidden
		}
		mid = in.MerchantID
	}
	if mid == "" {
		return nil, core.BadInput("merchantId is required for a member of several merchants")
	}
	var status string
	if err := r.Tx.QueryRow(ctx, `SELECT status FROM merchants WHERE id=$1`, mid).Scan(&status); err != nil {
		return nil, err
	}
	if status == "suspended" {
		return nil, core.ErrMerchantSuspended
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, core.BadInput("name is required")
	}
	id := db.NewID("ag")
	// The IdP call can't join the transaction. IdPs with tenancy create the client disabled
	// and enable it from the agent.registered outbox row, so a rolled-back registration
	// leaves an inert client (review-a finding 12).
	c, err := m.IdP.CreateClient(ctx, id, mid)
	if err != nil {
		return nil, err
	}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO agents(id, merchant_id, owner_user_id, name, client_id, idp_subject) VALUES ($1,$2,$3,$4,$5,$6)`,
		id, mid, r.P.ID, strings.TrimSpace(in.Name), c.ClientID, c.Subject); err != nil {
		return nil, err
	}
	if err := r.Emit(ctx, authz.Event{Type: authz.EvAgentRegistered, MerchantID: mid, AgentID: id, Subject: c.Subject}); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "clientId": c.ClientID, "clientSecret": c.ClientSecret}, nil
}

func (m *Module) grant(ctx context.Context, r *core.Req) (any, error) {
	if r.P.Kind != perm.KindUser {
		return nil, core.ErrForbidden // grants act for a user; only users can create them
	}
	var in struct {
		AgentID          string   `json:"agentId"`
		Permissions      []string `json:"permissions"`
		ExpiresInSeconds int64    `json:"expiresInSeconds"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if in.ExpiresInSeconds <= 0 || len(in.Permissions) == 0 {
		return nil, core.BadInput("permissions and expiresInSeconds > 0 are required")
	}
	if in.ExpiresInSeconds > maxGrantSeconds { // also keeps the Duration below from overflowing
		return nil, core.BadInput("expiresInSeconds must be at most one year")
	}
	perms := core.Dedupe(in.Permissions)
	for _, p := range perms {
		if !perm.IsGrantable(p) {
			return nil, core.E(http.StatusBadRequest, "not_grantable", p)
		}
	}
	var agentMerchant, registrant string
	err := r.Tx.QueryRow(ctx, `SELECT merchant_id, owner_user_id FROM agents WHERE id=$1`, in.AgentID).Scan(&agentMerchant, &registrant)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && agentMerchant != r.Target.MerchantID) {
		return nil, core.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	// Only the user who registered the agent (and so holds its secret) may grant it.
	// A grant lends the grantor's rights to whoever holds the credential: letting user A
	// lend rights to user B's agent would keep working after B leaves the merchant. It also
	// keeps every live grant of an agent from one user, which the engine models rely on
	// (results/a.md: set algebra can't tie a grant to its grantor).
	if registrant != r.P.ID {
		return nil, core.E(http.StatusForbidden, "forbidden", "only the agent's registrant can grant it")
	}
	// The grantor must hold every permission at this store (refund: holds it at all; the
	// agent later uses the grantor's own limit).
	if ok, err := r.HoldsAll(ctx, r.Target, perms, 0); err != nil {
		return nil, err
	} else if !ok {
		return nil, core.ErrEscalation
	}
	id := db.NewID("gr")
	exp := r.Now.Add(time.Duration(in.ExpiresInSeconds) * time.Second).UTC()
	if _, err := r.Tx.Exec(ctx, `INSERT INTO agent_grants(id, merchant_id, store_id, agent_id, grantor_user_id, permissions, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, r.Target.MerchantID, r.Target.Resource.ID, in.AgentID, r.P.ID, perms, exp); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "expiresAt": exp}, r.Emit(ctx, authz.Event{Type: authz.EvAgentGrantCreated, MerchantID: r.Target.MerchantID,
		StoreID: r.Target.Resource.ID, GrantID: id, AgentID: in.AgentID, UserID: r.P.ID, Permissions: perms, ExpiresAt: &exp})
}

func (m *Module) revoke(ctx context.Context, r *core.Req) (any, error) {
	var agentID, grantor string
	err := r.Tx.QueryRow(ctx, `UPDATE agent_grants SET revoked_at=now() WHERE id=$1 AND store_id=$2 AND merchant_id=$3 AND revoked_at IS NULL RETURNING agent_id, grantor_user_id`,
		r.Path("gid"), r.Target.Resource.ID, r.Target.MerchantID).Scan(&agentID, &grantor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return nil, r.Emit(ctx, authz.Event{Type: authz.EvAgentGrantRevoked, MerchantID: r.Target.MerchantID, StoreID: r.Target.Resource.ID,
		GrantID: r.Path("gid"), AgentID: agentID, UserID: grantor})
}

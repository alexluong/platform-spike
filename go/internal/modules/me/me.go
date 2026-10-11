// Package me: who am I, and what may I do here (batch can = AuthZEN action search).
package me

import (
	"context"

	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/alexluong/platform-spike/go/internal/perm"
)

type Module struct{}

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Auth: core.AuthAny, Method: "GET", Path: "/api/me", Run: m.me},
		{Auth: core.AuthAny, Method: "GET", Path: "/api/me/permissions", Target: permTarget, Run: m.permissions},
	}
}

func (m *Module) me(ctx context.Context, r *core.Req) (any, error) {
	out := map[string]any{"id": r.P.ID, "kind": r.P.Kind}
	if r.P.MerchantID != "" {
		out["merchantId"] = r.P.MerchantID
	}
	return out, nil
}

func permTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	q := r.HTTP.URL.Query()
	if sid := q.Get("storeId"); sid != "" {
		return scope.Store(ctx, r.Tx, sid)
	}
	if mid := q.Get("merchantId"); mid != "" {
		return scope.Merchant(ctx, r.Tx, mid)
	}
	return core.Target{}, core.BadInput("storeId or merchantId is required")
}

func (m *Module) permissions(ctx context.Context, r *core.Req) (any, error) {
	st := perm.ScopeType(r.Target.Resource.Type)
	var ids []string
	var checks []core.Check
	for _, a := range perm.Catalog {
		if a.Internal || !a.AllowsScope(st) {
			continue
		}
		ids = append(ids, a.ID)
		checks = append(checks, core.Check{Action: a.ID, Target: r.Target, Context: core.RefundContext(a.ID, 0)})
	}
	ok, err := r.CanMany(ctx, checks)
	if err != nil {
		return nil, err
	}
	actions := []string{}
	for i, id := range ids {
		if ok[i] {
			actions = append(actions, id)
		}
	}
	return map[string]any{"actions": actions}, nil
}

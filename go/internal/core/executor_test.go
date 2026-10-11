package core

import (
	"context"
	"testing"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
)

// fakeQ answers the merchant status query.
type fakeQ struct{ status string }

type row struct{ s string }

func (r row) Scan(dest ...any) error {
	if r.s == "" {
		return pgx.ErrNoRows
	}
	*(dest[0].(*string)) = r.s
	return nil
}

func (q fakeQ) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row { return row{q.status} }

// fakeAuthz allows what is listed and records what reached the engine.
type fakeAuthz struct {
	allow map[string]bool // "action"
	seen  []authz.Request
}

func (f *fakeAuthz) Evaluate(ctx context.Context, r authz.Request) (authz.Decision, error) {
	f.seen = append(f.seen, r)
	return authz.Decision{Decision: f.allow[r.Action.Name]}, nil
}

func (f *fakeAuthz) EvaluateMany(ctx context.Context, rs []authz.Request) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(rs))
	for i, r := range rs {
		out[i], _ = f.Evaluate(ctx, r)
	}
	return out, nil
}

func TestCanPrechecks(t *testing.T) {
	user := &Principal{ID: "u1", Kind: perm.KindUser, MerchantID: "m1"}
	app := &Principal{ID: "a1", Kind: perm.KindApp}
	staff := &Principal{ID: "s1", Kind: perm.KindPlatform, PlatformRole: "support"}
	cust := &Principal{ID: "c1", Kind: perm.KindCustomer}
	s1 := StoreTarget("s1", "m1", nil)
	other := StoreTarget("s9", "m9", nil)

	cases := []struct {
		name     string
		p        *Principal
		action   string
		t        Target
		status   string
		want     bool
		reason   string
		toEngine bool
	}{
		{"member allowed", user, "order.view", s1, "active", true, "", true},
		{"other tenant stops before engine", user, "order.view", other, "active", false, ReasonTenant, false},
		{"suspended merchant", user, "order.view", s1, "suspended", false, ReasonSuspended, false},
		{"apps never manage roles", app, "role.manage", s1, "active", false, ReasonKind, false},
		{"apps may view orders", app, "order.view", s1, "active", true, "", true},
		{"customers are not in the engine", cust, "order.view", s1, "active", false, ReasonKind, false},
		{"staff never write merchant data", staff, "order.cancel", s1, "active", false, ReasonKind, false},
		{"staff reads go to the engine (break-glass)", staff, "order.view", s1, "suspended", true, "", true},
		{"platform action at store scope", staff, "platform.merchant.view", s1, "active", false, ReasonScope, false},
		{"grantable held at merchant scope", user, "order.view", MerchantTarget("m1"), "active", true, "", true},
		{"unknown action", user, "order.nope", s1, "active", false, ReasonUnknownAction, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fa := &fakeAuthz{allow: map[string]bool{"order.view": true}}
			e := &Executor{Authz: fa}
			d, err := e.Can(context.Background(), fakeQ{c.status}, c.p, c.action, c.t, nil)
			if err != nil {
				t.Fatal(err)
			}
			if d.Decision != c.want || (c.reason != "" && d.Reason != c.reason) {
				t.Fatalf("got %+v, want decision=%v reason=%q", d, c.want, c.reason)
			}
			if (len(fa.seen) > 0) != c.toEngine {
				t.Fatalf("engine called=%v, want %v", len(fa.seen) > 0, c.toEngine)
			}
		})
	}
}

func TestDenialCodes(t *testing.T) {
	if denial(authz.Decision{Reason: ReasonTenant}) != ErrNotFound {
		t.Fatal("tenant → 404")
	}
	if denial(authz.Decision{Reason: ReasonSuspended}) != ErrMerchantSuspended {
		t.Fatal("suspended → merchant_suspended")
	}
	if denial(authz.Decision{Reason: "denied"}) != ErrForbidden {
		t.Fatal("engine deny → forbidden")
	}
}

// The guardrail asks order.refund with the role's limit, others without context.
func TestHoldsAllRefundContext(t *testing.T) {
	fa := &fakeAuthz{allow: map[string]bool{"order.view": true, "order.refund": true}}
	e := &Executor{Authz: fa}
	r := &Req{P: &Principal{ID: "u1", Kind: perm.KindUser, MerchantID: "m1"}, exec: e, Tx: nil}
	// Req.CanMany uses r.Tx as the querier; give it one through a tiny wrapper.
	ok, err := e.CanMany(context.Background(), fakeQ{"active"}, r.P, []Check{
		{Action: "order.view", Target: StoreTarget("s1", "m1", nil), Context: RefundContext("order.view", 500)},
		{Action: "order.refund", Target: StoreTarget("s1", "m1", nil), Context: RefundContext("order.refund", 500)},
	})
	if err != nil || !ok[0].Decision || !ok[1].Decision {
		t.Fatalf("got %+v %v", ok, err)
	}
	if fa.seen[0].Context != nil || fa.seen[1].Context[authz.CtxAmountCents] != int64(500) {
		t.Fatalf("contexts: %+v", fa.seen)
	}
}

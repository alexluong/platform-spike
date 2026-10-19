package oidcpool

// review-h2 tests: the structural guards against cross-pool rows, and the gaps the review found
// (results/review-h2.md).

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/alexluong/platform-spike/go/internal/db"
)

// Every SQL statement on a pool-scoped table names pool_id (lint, no DB). The library hands
// storage only a ctx, so a forgotten filter is a cross-pool bug no protocol check catches; this
// test makes forgetting one fail CI. Exceptions are listed with the reason.
func TestEveryQueryNamesItsPool(t *testing.T) {
	scoped := regexp.MustCompile(`\bidp_(users|clients|auth_requests|refresh_tokens|signing_keys|federation_states)\b`)
	allowed := []*regexp.Regexp{
		regexp.MustCompile(`^DELETE FROM idp_\w+ WHERE (expires_at|retire_at) < now\(\) - interval`), // sweep: global expiry
	}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || !strings.HasPrefix(lit.Value, "`") {
				return true
			}
			q := strings.Join(strings.Fields(strings.Trim(lit.Value, "`")), " ")
			if !scoped.MatchString(q) {
				return true
			}
			checked++
			for _, a := range allowed {
				if a.MatchString(q) {
					return true
				}
			}
			if !strings.Contains(q, "pool_id") {
				t.Errorf("%s: query on a pool-scoped table without pool_id: %s", fset.Position(lit.Pos()), q)
			}
			return true
		})
	}
	if checked < 25 {
		t.Fatalf("only %d queries found: is the lint still reading the adapter?", checked)
	}
}

// The database refuses rows that tie one pool's protocol objects to another pool's users or
// requests (schema/102_pool_guards.sql), whatever a query forgets.
func TestCrossPoolRowsRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m1, p1 := e.merchant()
	_, p2 := e.merchant()
	sub := e.tenantCustomer(m1, uniq("c"), "pw")
	uid := strings.TrimPrefix(sub, p1+":")

	// a refresh token of pool 2 for pool 1's user
	_, err := e.pool.Exec(ctx, `INSERT INTO idp_refresh_tokens(id, pool_id, family, user_id, client_id, scopes, audience, amr, auth_time, expires_at)
		VALUES ($1,$2,'f',$3,'storefront','{}','{}','{}',now(),now()+interval '1 hour')`, db.NewID("rt"), p2, uid)
	if err == nil {
		t.Error("refresh token of pool 2 for a pool 1 user was stored")
	}
	// pool 2's auth request marked done for pool 1's user
	_, c := pkce()
	id, _ := e.requestAt(p2, "storefront", c)
	if _, err := e.pool.Exec(ctx, `UPDATE idp_auth_requests SET user_id=$2, done=true WHERE id=$1`, id, uid); err == nil {
		t.Error("pool 2 auth request completed for a pool 1 user")
	}
	// a federation state of pool 1 for pool 2's auth request
	if _, err := e.pool.Exec(ctx, `INSERT INTO idp_federation_states(id, pool_id, auth_request_id, verifier, nonce, binding_hash, expires_at)
		VALUES ($1,$2,$3,'v','n','\x00',now()+interval '1 minute')`, db.NewID("fs"), p1, id); err == nil {
		t.Error("federation state of pool 1 for a pool 2 auth request was stored")
	}
	// the same rows within one pool are fine
	if _, err := e.pool.Exec(ctx, `INSERT INTO idp_refresh_tokens(id, pool_id, family, user_id, client_id, scopes, audience, amr, auth_time, expires_at)
		VALUES ($1,$2,'f',$3,'storefront','{}','{}','{}',now(),now()+interval '1 hour')`, db.NewID("rt"), p1, uid); err != nil {
		t.Errorf("same-pool refresh token: %v", err)
	}
}

// signInWithShop runs the whole round trip at pool p; returns the tenant tokens' status and body.
func (e *env) signInWithShop(p, email, pw string) (int, tokens) {
	e.t.Helper()
	shopAuth, cookie, v := e.shopStart(p)
	cb, st := e.shopLeg(shopAuth, email, pw)
	if cb == nil {
		return st, tokens{}
	}
	res := e.callback(cb, cookie)
	if res.StatusCode != 302 {
		return res.StatusCode, tokens{}
	}
	back, _ := url.Parse(res.Header.Get("Location"))
	return e.exchangeAt(p, "storefront", back.Query().Get("code"), v)
}

// Disabling (or deleting) a Shop account ends its tenant sessions at every merchant at the next
// refresh; a tenant identity the merchant disabled can't come back through Shop.
func TestShopAccountDisabledEndsTenantSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.recordLinks()
	_, p1 := e.merchant()
	_, p2 := e.merchant()
	buyer := uniq("buyer")
	shopSub, _ := e.iss.CreateUser(ctx, buyer, "pw-shop", "customer")
	shopID := strings.TrimPrefix(shopSub, "shop:")

	st, t1 := e.signInWithShop(p1, buyer, "pw-shop")
	if st != 200 || t1.RefreshToken == "" {
		t.Fatalf("Sign in with Shop at M1: %d %+v", st, t1)
	}
	st, t2 := e.signInWithShop(p2, buyer, "pw-shop")
	if st != 200 || t2.RefreshToken == "" {
		t.Fatalf("Sign in with Shop at M2: %d", st)
	}
	refresh := func(p, rt string) int {
		return e.post("/oidc/"+p+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"storefront"}}).StatusCode
	}

	if _, err := e.pool.Exec(ctx, `UPDATE idp_users SET disabled_at=now() WHERE id=$1 AND pool_id='shop'`, shopID); err != nil {
		t.Fatal(err)
	}
	if st := refresh(p1, t1.RefreshToken); st == 200 {
		t.Error("M1 tenant refresh still works after the Shop account was disabled")
	}
	if st := refresh(p2, t2.RefreshToken); st == 200 {
		t.Error("M2 tenant refresh still works after the Shop account was disabled")
	}
	if st, _ := e.signInWithShop(p1, buyer, "pw-shop"); st == 200 {
		t.Error("Sign in with Shop with a disabled Shop account")
	}
	// re-enabled: the (unrotated) refresh token works again
	_, _ = e.pool.Exec(ctx, `UPDATE idp_users SET disabled_at=NULL WHERE id=$1 AND pool_id='shop'`, shopID)
	if st := refresh(p1, t1.RefreshToken); st != 200 {
		t.Errorf("refresh after the Shop account was re-enabled: %d", st)
	}
	// the merchant disables its linked identity: Shop can't bring it back
	if _, err := e.pool.Exec(ctx, `UPDATE idp_users SET disabled_at=now() WHERE pool_id=$1 AND upstream_sub=$2`, p1, shopID); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.signInWithShop(p1, buyer, "pw-shop"); st == 200 {
		t.Error("Sign in with Shop revived a tenant identity the merchant disabled")
	}
	if st, _ := e.signInWithShop(p2, buyer, "pw-shop"); st != 200 {
		t.Errorf("M2 unaffected by M1 disabling its identity: %d", st)
	}
}

// A code issued just before a suspension mints nothing after it.
func TestCodeRefusedAfterSuspension(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m, p := e.merchant()
	email := uniq("c")
	e.tenantCustomer(m, email, "pw")
	v, c := pkce()
	code, st := e.codeAt(p, "storefront", email, "pw", c)
	if code == "" {
		t.Fatalf("login: %d", st)
	}
	_ = e.iss.SetMerchantSuspended(ctx, m, true)
	if st, _ := e.exchangeAt(p, "storefront", code, v); st == 200 {
		t.Error("code redeemed after the pool was suspended")
	}
	_ = e.iss.SetMerchantSuspended(ctx, m, false)
}

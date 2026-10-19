package oidcpool

// Pool tests (stack h2): what pools add on top of stack h's checklist. Every item a pool could
// weaken: codes, refresh tokens, keys, clients and logins must stay inside their pool; a merchant's
// pool is provisioned atomically; suspension is enforced by the pool; Sign in with Shop is a real
// OIDC round trip bound to the user agent that started it.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
)

// merchant provisions a tenant pool for a fresh merchant id; returns the merchant id and pool id.
func (e *env) merchant() (string, string) {
	e.t.Helper()
	mid := db.NewID("m")
	if err := e.iss.provisionMerchant(context.Background(), mid); err != nil {
		e.t.Fatal(err)
	}
	var pool string
	if err := e.pool.QueryRow(context.Background(), `SELECT id FROM idp_pools WHERE merchant_id=$1`, mid).Scan(&pool); err != nil {
		e.t.Fatal(err)
	}
	return mid, pool
}

func (e *env) tenantCustomer(mid, email, pw string) string {
	e.t.Helper()
	sub, err := e.iss.CreateTenantCustomer(context.Background(), mid, email, pw)
	if err != nil {
		e.t.Fatal(err)
	}
	return sub
}

func authorizeAt(pool, client, challenge string) string {
	q := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {"openid offline_access"}, "state": {"s1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"prompt": {"consent"}}
	return "/oidc/" + pool + "/authorize?" + q.Encode()
}

// requestAt starts a code flow at pool with client; returns the auth request id (or "" + status).
func (e *env) requestAt(pool, client, challenge string) (string, int) {
	res := e.get(authorizeAt(pool, client, challenge))
	if res.StatusCode != 302 {
		return "", res.StatusCode
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	return loc.Query().Get("id"), 302
}

// codeAt: authorize + login at pool with client; the code, or "" and the login status.
func (e *env) codeAt(pool, client, email, pw, challenge string) (string, int) {
	e.t.Helper()
	id, st := e.requestAt(pool, client, challenge)
	if id == "" {
		return "", st
	}
	res := e.post("/oidc/"+pool+"/login", url.Values{"id": {id}, "email": {email}, "password": {pw}})
	if res.StatusCode != 302 {
		return "", res.StatusCode
	}
	back, _ := url.Parse(res.Header.Get("Location"))
	return back.Query().Get("code"), 302
}

func (e *env) exchangeAt(pool, client, code, verifier string) (int, tokens) {
	res := e.post("/oidc/"+pool+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {client}, "code_verifier": {verifier}})
	var t tokens
	_ = json.NewDecoder(res.Body).Decode(&t)
	return res.StatusCode, t
}

func (e *env) loginAt(pool, client, email, pw string) (int, tokens) {
	e.t.Helper()
	v, c := pkce()
	code, st := e.codeAt(pool, client, email, pw, c)
	if code == "" {
		return st, tokens{}
	}
	return e.exchangeAt(pool, client, code, v)
}

func jwtClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	jws, err := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &c)
	return c
}

func TestPoolIssuersKeysAndDirectory(t *testing.T) {
	e := newEnv(t)
	_, p1 := e.merchant()
	_, p2 := e.merchant()
	kids := map[string]string{}
	for _, p := range []string{"workforce", "platform", "shop", p1, p2} {
		res := e.get("/oidc/" + p + "/.well-known/openid-configuration")
		var d struct {
			Issuer  string `json:"issuer"`
			JwksURI string `json:"jwks_uri"`
		}
		_ = json.NewDecoder(res.Body).Decode(&d)
		if res.StatusCode != 200 || d.Issuer != e.iss.cfg.PublicURL+"/oidc/"+p || d.JwksURI != d.Issuer+"/keys" {
			t.Fatalf("%s discovery: %d %+v", p, res.StatusCode, d)
		}
		// each pool's JWKS holds its own keys only
		var ks jose.JSONWebKeySet
		_ = json.NewDecoder(e.get("/oidc/" + p + "/keys").Body).Decode(&ks)
		if len(ks.Keys) == 0 {
			t.Fatalf("%s: empty JWKS", p)
		}
		for _, k := range ks.Keys {
			if other, dup := kids[k.KeyID]; dup {
				t.Fatalf("kid %s published by %s and %s", k.KeyID, other, p)
			}
			kids[k.KeyID] = p
		}
	}
	// spoofed Host / forwarded headers don't move a tenant issuer
	req, _ := http.NewRequest("GET", e.srv.URL+"/oidc/"+p1+"/.well-known/openid-configuration", nil)
	req.Host = "evil.example"
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("Forwarded", "host=evil.example;proto=https")
	res, _ := e.hc.Do(req)
	if b := body(res); strings.Contains(b, "evil") {
		t.Fatalf("issuer from headers: %s", b)
	}
	// unknown pools, pool-shaped junk and encoded pool segments → 404 (directory, not the path)
	for _, p := range []string{"/oidc/pl_nope/.well-known/openid-configuration", "/oidc/PLATFORM/keys", "/oidc/%70latform/keys",
		"/oidc/../oidc/platform/keys", "/oidc//keys", "/oidc/pl_x%2f..%2fplatform/keys"} {
		if res := e.get(p); res.StatusCode == 200 {
			t.Errorf("%s → 200", p)
		}
	}
	// a pool created on another instance is found at once (directory miss reads the DB)
	b := startIssuer(t, e.pool, e.iss.cfg.PublicURL)
	_, p3 := e.merchant()
	if res := b.get("/oidc/" + p3 + "/keys"); res.StatusCode != 200 {
		t.Fatalf("new pool on second instance: %d", res.StatusCode)
	}
}

func TestTokensStayInTheirPool(t *testing.T) {
	e := newEnv(t)
	m1, p1 := e.merchant()
	m2, p2 := e.merchant()
	email := uniq("same")
	s1 := e.tenantCustomer(m1, email, "pw-m1")
	s2 := e.tenantCustomer(m2, email, "pw-m2")
	if s1 == s2 || !strings.HasPrefix(s1, p1+":") || !strings.HasPrefix(s2, p2+":") {
		t.Fatalf("subjects %s %s", s1, s2)
	}
	// same email, two pools: each password works only at its own pool
	if st, _ := e.loginAt(p1, "storefront", email, "pw-m2"); st == 200 {
		t.Fatal("M2's password worked at M1")
	}
	st, tok := e.loginAt(p1, "storefront", email, "pw-m1")
	if st != 200 {
		t.Fatalf("M1 login: %d", st)
	}
	got, err := e.iss.Verify(context.Background(), tok.AccessToken)
	if err != nil || got.Subject != s1 || got.MerchantID != m1 {
		t.Fatalf("verify: %v %+v", err, got)
	}
	if iss := jwtClaims(t, tok.AccessToken)["iss"]; iss != e.iss.issuerFor(p1) {
		t.Fatalf("iss %v", iss)
	}

	// a code from M1's pool is unknown at M2's (and the platform pool's) token endpoint, and
	// presenting it there doesn't burn it at home
	v, c := pkce()
	code, _ := e.codeAt(p1, "storefront", email, "pw-m1", c)
	for _, p := range []string{p2, "platform"} {
		client := map[string]string{p2: "storefront", "platform": "platform-cli"}[p]
		if st, _ := e.exchangeAt(p, client, code, v); st == 200 {
			t.Fatalf("M1 code redeemed at %s", p)
		}
	}
	if st, _ := e.exchangeAt(p1, "storefront", code, v); st != 200 {
		t.Fatalf("M1 code at home after foreign attempts: %d", st)
	}

	// a refresh token from M1 doesn't refresh at M2
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token")
	}
	res := e.post("/oidc/"+p2+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {"storefront"}})
	if res.StatusCode == 200 {
		t.Fatal("M1 refresh token worked at M2")
	}
	res = e.post("/oidc/"+p1+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {"storefront"}})
	if res.StatusCode != 200 {
		t.Fatalf("refresh at home: %d %s", res.StatusCode, body(res))
	}

	// forged: M1's key with M2's issuer, M2's issuer with an M1 subject, the platform pool's key
	// with a tenant issuer; tenant tokens via the platform login client
	k1, _ := e.iss.keys.signing(context.Background(), p1)
	kp, _ := e.iss.keys.signing(context.Background(), "platform")
	now := time.Now().Unix()
	claims := func(iss, sub, client string) map[string]any {
		return map[string]any{"iss": iss, "sub": sub, "aud": []string{"platform-api"}, "exp": now + 60, "iat": now,
			"client_id": client, "token_use": "access"}
	}
	sign := func(k sigKey, c map[string]any) string {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.id}}, (&jose.SignerOptions{}).WithType("JWT"))
		b, _ := json.Marshal(c)
		jws, _ := s.Sign(b)
		raw, _ := jws.CompactSerialize()
		return raw
	}
	raw1 := strings.TrimPrefix(s1, p1+":")
	for name, raw := range map[string]string{
		"control: M1 key, M1 issuer":     sign(k1, claims(e.iss.issuerFor(p1), raw1, "storefront")),
		"M1 key, M2 issuer":              sign(k1, claims(e.iss.issuerFor(p2), raw1, "storefront")),
		"platform key, M1 issuer":        sign(kp, claims(e.iss.issuerFor(p1), raw1, "storefront")),
		"M1 key, platform client":        sign(k1, claims(e.iss.issuerFor(p1), raw1, "platform-cli")),
		"M1 key, machine-client shape":   sign(k1, claims(e.iss.issuerFor(p1), "cli_x", "cli_x")),
		"M1 key, issuer with trailing /": sign(k1, claims(e.iss.issuerFor(p1)+"/", raw1, "storefront")),
		"M1 key, unknown pool issuer":    sign(k1, claims(e.iss.cfg.PublicURL+"/oidc/pl_nope", raw1, "storefront")),
		"M1 key, issuer on another host": sign(k1, claims("http://evil.example/oidc/"+p1, raw1, "storefront")),
	} {
		_, err := e.iss.Verify(context.Background(), raw)
		if ok := err == nil; ok != strings.HasPrefix(name, "control") {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

// SPEC v4.1: a tenant pool holds customers only, through the storefront client; merchant staff
// are platform accounts and have no identity or client there.
func TestTenantPoolCustomersOnly(t *testing.T) {
	e := newEnv(t)
	m, p := e.merchant()
	cust, staff := uniq("cust"), uniq("staff")
	e.tenantCustomer(m, cust, "pw-c")
	e.user(staff, "pw-s") // a platform account
	cases := []struct {
		client, email, pw string
		ok                bool
	}{
		{"storefront", cust, "pw-c", true},
		{"storefront", staff, "pw-s", false},    // platform accounts aren't tenant identities
		{"merchant-admin", cust, "pw-c", false}, // no staff client any more
		{"platform-cli", cust, "pw-c", false},   // not a client of a tenant pool
	}
	for _, c := range cases {
		st, _ := e.loginAt(p, c.client, c.email, c.pw)
		if (st == 200) != c.ok {
			t.Errorf("%s %s: %d", c.client, c.email, st)
		}
	}
	// and the tenant clients don't exist at the platform-level pools
	if _, st := e.requestAt("platform", "storefront", "x"); st == 302 {
		t.Error("storefront client at the platform pool")
	}
}

func TestProvisioningIsTransactional(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	count := func(mid string) (n int) {
		_ = e.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM idp_pools WHERE merchant_id=$1) + (SELECT count(*) FROM idp_clients WHERE merchant_id=$1)
			+ (SELECT count(*) FROM idp_signing_keys k JOIN idp_pools p ON p.id=k.pool_id WHERE p.merchant_id=$1)
			+ (SELECT count(*) FROM idp_users u JOIN idp_pools p ON p.id=u.pool_id WHERE p.merchant_id=$1)`, mid).Scan(&n)
		return
	}
	mid := db.NewID("m")
	tx, _ := e.pool.Begin(ctx)
	if err := e.iss.provisionMerchant(db.WithTx(ctx, tx), mid); err != nil {
		t.Fatal(err)
	}
	if _, err := e.iss.CreateTenantCustomer(db.WithTx(ctx, tx), mid, uniq("x"), "pw"); err != nil {
		t.Fatal(err)
	}
	if n := count(mid); n != 0 {
		t.Fatalf("uncommitted pool visible outside the tx: %d rows", n)
	}
	_ = tx.Rollback(ctx)
	if n := count(mid); n != 0 {
		t.Fatalf("rolled back, %d rows left", n)
	}
	if _, err := e.iss.PoolIdentity(ctx, mid); err != identity.ErrNotFound {
		t.Fatalf("issuer of a rolled-back merchant: %v", err)
	}
	tx, _ = e.pool.Begin(ctx)
	_ = e.iss.provisionMerchant(db.WithTx(ctx, tx), mid)
	_ = tx.Commit(ctx)
	if n := count(mid); n != 3 { // pool + federation client + key
		t.Fatalf("committed: %d rows, want 3", n)
	}
}

func TestSuspendedPool(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m, p := e.merchant()
	email := uniq("c")
	e.tenantCustomer(m, email, "pw")
	st, tok := e.loginAt(p, "storefront", email, "pw")
	if st != 200 {
		t.Fatal(st)
	}
	_ = e.iss.SetMerchantSuspended(ctx, m, true)
	if st, _ := e.loginAt(p, "storefront", email, "pw"); st != 403 {
		t.Errorf("login while suspended: %d", st)
	}
	res := e.post("/oidc/"+p+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {"storefront"}})
	if res.StatusCode == 200 {
		t.Error("refresh while suspended")
	}
	// tokens issued before still verify: the app answers 403 merchant_suspended, not 401 (SPEC §16.6.8)
	if _, err := e.iss.Verify(ctx, tok.AccessToken); err != nil {
		t.Errorf("old token: %v", err)
	}
	_ = e.iss.SetMerchantSuspended(ctx, m, false)
	if st, _ := e.loginAt(p, "storefront", email, "pw"); st != 200 {
		t.Errorf("login after reinstate: %d", st)
	}
}

func TestPerPoolRotation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, p := e.merchant()
	kidsOf := func(pool string) string {
		var ks jose.JSONWebKeySet
		_ = json.NewDecoder(e.get("/oidc/" + pool + "/keys").Body).Decode(&ks)
		var ids []string
		for _, k := range ks.Keys {
			ids = append(ids, k.KeyID)
		}
		return strings.Join(ids, ",")
	}
	before, platform := kidsOf(p), kidsOf("platform")
	if err := Rotate(ctx, e.pool, e.iss.cfg.Secret, p, 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	_, _ = e.iss.keys.live(ctx, p, true)
	_, _ = e.iss.keys.live(ctx, "platform", true)
	if after := kidsOf(p); after == before || !strings.HasPrefix(after, before) {
		t.Fatalf("tenant JWKS after rotate: %s (before %s)", after, before)
	}
	if kidsOf("platform") != platform {
		t.Fatal("rotating a tenant pool changed the platform pool's keys")
	}
}

// ---- Sign in with Shop ----

type shopLink struct{ mid, shop, tenant string }

func (e *env) recordLinks() *[]shopLink {
	var mu sync.Mutex
	links := &[]shopLink{}
	e.iss.cfg.OnShopLink = func(_ context.Context, mid, shop, tenant string) error {
		mu.Lock()
		*links = append(*links, shopLink{mid, shop, tenant})
		mu.Unlock()
		return nil
	}
	return links
}

// shopStart: storefront authorize at the tenant pool + "Sign in with Shop"; returns the redirect to
// the shop pool, the binding cookie and the tenant request's PKCE verifier.
func (e *env) shopStart(pool string) (shopAuth *url.URL, cookie *http.Cookie, verifier string) {
	e.t.Helper()
	v, c := pkce()
	id, st := e.requestAt(pool, "storefront", c)
	if id == "" {
		e.t.Fatalf("tenant authorize: %d", st)
	}
	res := e.get("/oidc/" + pool + "/login/shop?id=" + url.QueryEscape(id))
	if res.StatusCode != 302 || len(res.Cookies()) == 0 {
		e.t.Fatalf("login/shop: %d %s", res.StatusCode, body(res))
	}
	u, _ := url.Parse(res.Header.Get("Location"))
	return u, res.Cookies()[0], v
}

// shopLeg: the shop pool's authorize + login; returns the callback URL (code + state).
func (e *env) shopLeg(shopAuth *url.URL, email, pw string) (*url.URL, int) {
	res := e.get(shopAuth.RequestURI())
	if res.StatusCode != 302 {
		return nil, res.StatusCode
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	res = e.post("/oidc/shop/login", url.Values{"id": {loc.Query().Get("id")}, "email": {email}, "password": {pw}})
	if res.StatusCode != 302 {
		return nil, res.StatusCode
	}
	cb, _ := url.Parse(res.Header.Get("Location"))
	return cb, 302
}

func (e *env) callback(cb *url.URL, cookie *http.Cookie) *http.Response {
	req, _ := http.NewRequest("GET", e.srv.URL+cb.RequestURI(), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res, err := e.hc.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func TestSignInWithShop(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	links := e.recordLinks()
	m, p := e.merchant()
	buyer := uniq("buyer")
	shopSub, _ := e.iss.CreateUser(ctx, buyer, "pw-shop", "customer")

	shopAuth, cookie, v := e.shopStart(p)
	if !strings.HasPrefix(shopAuth.String(), e.iss.issuerFor("shop")+"/authorize?") || shopAuth.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("redirect to shop: %s", shopAuth)
	}
	cb, st := e.shopLeg(shopAuth, buyer, "pw-shop")
	if cb == nil || !strings.HasPrefix(cb.String(), e.iss.issuerFor(p)+fedCallbackPath+"?") {
		t.Fatalf("shop leg: %d %v", st, cb)
	}
	// without the binding cookie the callback refuses (and the state isn't burned by it)
	if res := e.callback(cb, nil); res.StatusCode != 400 {
		t.Fatalf("callback without cookie: %d", res.StatusCode)
	}
	// with someone else's cookie: refused
	if res := e.callback(cb, &http.Cookie{Name: fedCookie, Value: "forged"}); res.StatusCode != 400 {
		t.Fatalf("callback with a forged cookie: %d", res.StatusCode)
	}
	res := e.callback(cb, cookie)
	if res.StatusCode != 302 {
		t.Fatalf("callback: %d %s", res.StatusCode, body(res))
	}
	back, _ := url.Parse(res.Header.Get("Location"))
	st, tok := e.exchangeAt(p, "storefront", back.Query().Get("code"), v)
	if st != 200 {
		t.Fatalf("tenant token: %d %+v", st, tok)
	}
	got, err := e.iss.Verify(ctx, tok.AccessToken)
	if err != nil || got.MerchantID != m || !strings.HasPrefix(got.Subject, p+":") {
		t.Fatalf("tenant token verify: %v %+v", err, got)
	}
	if len(*links) != 1 || (*links)[0] != (shopLink{m, shopSub, got.Subject}) {
		t.Fatalf("links: %+v (shop %s, tenant %s)", *links, shopSub, got.Subject)
	}
	// replaying the callback: the state is single-use
	if res := e.callback(cb, cookie); res.StatusCode != 400 {
		t.Fatalf("replayed callback: %d", res.StatusCode)
	}
	// the same buyer again → the same tenant identity
	shopAuth, cookie, v = e.shopStart(p)
	cb, _ = e.shopLeg(shopAuth, buyer, "pw-shop")
	res = e.callback(cb, cookie)
	back, _ = url.Parse(res.Header.Get("Location"))
	_, tok2 := e.exchangeAt(p, "storefront", back.Query().Get("code"), v)
	if got2, _ := e.iss.Verify(ctx, tok2.AccessToken); got2.Subject != got.Subject {
		t.Fatalf("second sign-in: %s vs %s", got2.Subject, got.Subject)
	}
	// a callback from M1's round trip presented at M2's pool: the state belongs to M1
	_, p2 := e.merchant()
	shopAuth, cookie, _ = e.shopStart(p)
	cb, _ = e.shopLeg(shopAuth, buyer, "pw-shop")
	foreign, _ := url.Parse(strings.Replace(cb.String(), "/oidc/"+p+"/", "/oidc/"+p2+"/", 1))
	c2 := *cookie
	if res := e.callback(foreign, &c2); res.StatusCode != 400 {
		t.Fatalf("M1 state at M2: %d", res.StatusCode)
	}
	// wrong Shop password: no callback at all
	shopAuth, _, _ = e.shopStart(p)
	if cb, st := e.shopLeg(shopAuth, buyer, "wrong"); cb != nil || st != 401 {
		t.Fatalf("wrong shop password: %d", st)
	}
	// Sign in with Shop only at tenant pools (the storefront is their only login client)
	if res := e.get("/oidc/platform/login/shop?id=x"); res.StatusCode != 404 {
		t.Fatalf("Shop at the platform pool: %d", res.StatusCode)
	}
	// suspended merchant: Sign in with Shop refuses at the start
	_ = e.iss.SetMerchantSuspended(ctx, m, true)
	_, c := pkce()
	id, _ := e.requestAt(p, "storefront", c)
	if res := e.get("/oidc/" + p + "/login/shop?id=" + id); res.StatusCode != 403 {
		t.Fatalf("Shop while suspended: %d", res.StatusCode)
	}
}

// The federation client gets Shop tokens for itself only: the Shop access token it receives
// isn't an API token, and its secret can't do client_credentials.
func TestFederationClientIsNotAnAPIClient(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	mid, p := e.merchant()
	buyer := uniq("buyer")
	_, _ = e.iss.CreateUser(ctx, buyer, "pw", "customer")
	var fedID string
	var enc []byte
	if err := e.pool.QueryRow(ctx, `SELECT upstream_client_id, upstream_secret_enc FROM idp_pools WHERE merchant_id=$1`, mid).Scan(&fedID, &enc); err != nil {
		t.Fatal(err)
	}
	secret, err := e.iss.keys.open(enc, "upstream:"+p)
	if err != nil {
		t.Fatal(err)
	}
	// the secret is stored hashed on the shop side and encrypted on the tenant side
	var h []byte
	_ = e.pool.QueryRow(ctx, `SELECT secret_hash FROM idp_clients WHERE id=$1`, fedID).Scan(&h)
	if want := sha256.Sum256(secret); string(h) != string(want[:]) || strings.Contains(string(enc), string(secret)) {
		t.Fatal("federation secret storage")
	}
	if res := e.post("/oidc/shop/oauth/token", url.Values{"grant_type": {"client_credentials"}}, fedID, string(secret)); res.StatusCode == 200 {
		t.Fatal("federation client got a client_credentials token")
	}
	// run the code flow as the federation client directly and present its access token to the API
	v, c := pkce()
	q := url.Values{"client_id": {fedID}, "redirect_uri": {e.iss.issuerFor(p) + fedCallbackPath}, "response_type": {"code"},
		"scope": {"openid"}, "code_challenge": {c}, "code_challenge_method": {"S256"}}
	res := e.get("/oidc/shop/authorize?" + q.Encode())
	loc, _ := url.Parse(res.Header.Get("Location"))
	res = e.post("/oidc/shop/login", url.Values{"id": {loc.Query().Get("id")}, "email": {buyer}, "password": {"pw"}})
	back, _ := url.Parse(res.Header.Get("Location"))
	res = e.post("/oidc/shop/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")},
		"redirect_uri": {e.iss.issuerFor(p) + fedCallbackPath}, "code_verifier": {v}}, fedID, string(secret))
	var tok tokens
	_ = json.NewDecoder(res.Body).Decode(&tok)
	if res.StatusCode != 200 || tok.AccessToken == "" {
		t.Fatalf("federation code flow: %d %+v", res.StatusCode, tok)
	}
	if _, err := e.iss.Verify(ctx, tok.AccessToken); err == nil {
		t.Fatal("a federation client's Shop access token was accepted by the API")
	}
	if sub := jwtClaims(t, tok.IDToken)["sub"]; sub == nil || sub == "" {
		t.Fatal("ID token without sub")
	}
	// and the federation client can't log in tenant users at the tenant pool
	if _, st := e.requestAt(p, fedID, c); st == 302 {
		t.Fatal("federation client accepted at the tenant pool")
	}
	_ = pgx.ErrNoRows
}

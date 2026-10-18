package oidcop

// Integration tests: the issuer on a real Postgres (OIDCOP_TEST_DATABASE_URL), served by
// httptest. Each pins one item of the in-house issuer checklist (results/h.md).
//
//	OIDCOP_TEST_DATABASE_URL=postgres://postgres:…@localhost:15432/issuer_test go test ./internal/adapters/oidcop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
)

const redirect = "http://127.0.0.1/callback"

type env struct {
	t    *testing.T
	pool *pgxpool.Pool
	iss  *Issuer
	srv  *httptest.Server
	hc   *http.Client
}

var setupOnce sync.Once

func newEnv(t *testing.T) *env {
	t.Helper()
	dsn := os.Getenv("OIDCOP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("OIDCOP_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	setupOnce.Do(func() {
		if err := Migrate(ctx, pool); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `TRUNCATE idp_users, idp_clients, idp_auth_requests, idp_refresh_tokens, idp_signing_keys`); err != nil {
			t.Fatal(err)
		}
	})
	return startIssuer(t, pool, "")
}

// startIssuer: one "instance" (own key cache, own limiter) on the shared DB. issuer ""
// means this instance's own URL; instances behind one name share it.
func startIssuer(t *testing.T, pool *pgxpool.Pool, issuer string) *env {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	if issuer == "" {
		issuer = base + "/oidc"
	}
	iss, err := New(context.Background(), pool, Config{
		Issuer: issuer, LoginURL: base + "/login", Secret: "test-secret-0123456789abcdef-0123456789",
		Audience: "platform-api", LoginClientID: "platform-cli", RedirectURIs: []string{redirect},
		AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	iss.Mount(mux)
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &env{t: t, pool: pool, iss: iss, srv: srv, hc: hc}
}

func (e *env) user(email, pw string) string {
	e.t.Helper()
	id, err := e.iss.CreateUser(context.Background(), email, pw, "user")
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
}

func (e *env) get(path string) *http.Response {
	e.t.Helper()
	res, err := e.hc.Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func (e *env) post(path string, form url.Values, basic ...string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	res, err := e.hc.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func authorizeQuery(challenge string, extra map[string]string) string {
	q := url.Values{"client_id": {"platform-cli"}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"s1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q.Encode()
}

// code runs authorize → login (which answers with the code) and returns the code (or fails).
func (e *env) code(email, pw, challenge string, extra map[string]string) string {
	e.t.Helper()
	res := e.get("/oidc/authorize?" + authorizeQuery(challenge, extra))
	if res.StatusCode != 302 {
		e.t.Fatalf("authorize: %d %s", res.StatusCode, body(res))
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	id := loc.Query().Get("id")
	res = e.post("/login", url.Values{"id": {id}, "email": {email}, "password": {pw}})
	if res.StatusCode != 302 {
		e.t.Fatalf("login: %d %s", res.StatusCode, body(res))
	}
	back, _ := url.Parse(res.Header.Get("Location"))
	if back.Query().Get("code") == "" || !strings.HasPrefix(back.String(), redirect) {
		e.t.Fatalf("login: no code in %s", back)
	}
	return back.Query().Get("code")
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

func (e *env) exchange(code, verifier string) (int, tokens) {
	res := e.post("/oidc/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {"platform-cli"}, "code_verifier": {verifier}})
	var t tokens
	_ = json.NewDecoder(res.Body).Decode(&t)
	return res.StatusCode, t
}

func (e *env) login(email, pw string, extra map[string]string) tokens {
	e.t.Helper()
	v, c := pkce()
	st, t := e.exchange(e.code(email, pw, c, extra), v)
	if st != 200 {
		e.t.Fatalf("token: %d %+v", st, t)
	}
	return t
}

func body(res *http.Response) string {
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func uniq(p string) string { return p + "-" + db.NewID("t") + "@example.com" }

func TestCodeFlowTokenChecks(t *testing.T) {
	e := newEnv(t)
	email := uniq("flow")
	sub := e.user(email, "pw-1")
	tok := e.login(email, "pw-1", nil)
	got, err := e.iss.Verify(context.Background(), tok.AccessToken)
	if err != nil || got.Subject != sub {
		t.Fatalf("access token: %v %+v", err, got)
	}
	// The ID token has the same typ ("JWT") and our audience; token_use tells them apart.
	if tok.IDToken == "" {
		t.Fatal("expected an id_token")
	}
	if _, err := e.iss.Verify(context.Background(), tok.IDToken); err == nil {
		t.Fatal("ID token accepted as access token")
	}

	// Tokens signed with the live key but wrong claims, and tokens signed otherwise.
	k, err := e.iss.keys.signing(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	good := map[string]any{"iss": e.iss.cfg.Issuer, "sub": sub, "aud": []string{"platform-api"}, "exp": now + 60,
		"iat": now, "client_id": "platform-cli", "token_use": "access"}
	with := func(kv ...any) map[string]any {
		c := map[string]any{}
		for k, v := range good {
			c[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(c, kv[i].(string))
			} else {
				c[kv[i].(string)] = kv[i+1]
			}
		}
		return c
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := []struct {
		name   string
		key    any
		kid    string
		claims map[string]any
		ok     bool
	}{
		{"forged with the live key (control)", k.priv, k.id, good, true},
		{"other audience", k.priv, k.id, with("aud", []string{"other-api"}), false},
		{"other client for a user", k.priv, k.id, with("client_id", "cli_someone"), false},
		{"no token_use (ID-token shaped)", k.priv, k.id, with("token_use", nil), false},
		{"wrong issuer", k.priv, k.id, with("iss", "http://evil.example/oidc"), false},
		{"expired", k.priv, k.id, with("exp", now-120), false},
		{"unknown key, same kid", other, k.id, good, false},
		{"unknown kid", other, "key_nope", good, false},
	}
	for _, c := range cases {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: c.key, KeyID: c.kid}}, (&jose.SignerOptions{}).WithType("JWT"))
		b, _ := json.Marshal(c.claims)
		jws, _ := s.Sign(b)
		raw, _ := jws.CompactSerialize()
		if _, err := e.iss.Verify(context.Background(), raw); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
	// alg none: header + claims + empty signature.
	enc := base64.RawURLEncoding.EncodeToString
	b, _ := json.Marshal(good)
	none := enc([]byte(`{"alg":"none","typ":"JWT","kid":"`+k.id+`"}`)) + "." + enc(b) + "."
	if _, err := e.iss.Verify(context.Background(), none); err == nil {
		t.Error("alg none accepted")
	}
}

func TestAuthorizeRejects(t *testing.T) {
	e := newEnv(t)
	_, c := pkce()
	for name, extra := range map[string]map[string]string{
		"no PKCE":                 {"code_challenge": "", "code_challenge_method": ""},
		"plain PKCE":              {"code_challenge_method": "plain"},
		"implicit (token)":        {"response_type": "token"},
		"implicit (id_token)":     {"response_type": "id_token"},
		"unknown client":          {"client_id": "evil"},
		"unregistered redirect":   {"redirect_uri": "https://evil.example/cb"},
		"redirect path differs":   {"redirect_uri": "http://127.0.0.1/callback/../evil"},
		"redirect host differs":   {"redirect_uri": "http://evil.example/callback"},
		"machine client":          {"client_id": "cli_x"},
		"loopback, other path":    {"redirect_uri": "http://127.0.0.1:9999/other"},
		"loopback, extra query":   {"redirect_uri": "http://127.0.0.1/callback?x=1"},
		"localhost name, ok port": {"redirect_uri": "http://localhost.evil.example/callback"},
	} {
		res := e.get("/oidc/authorize?" + authorizeQuery(c, extra))
		loc := res.Header.Get("Location")
		switch {
		case res.StatusCode == 302 && (strings.HasPrefix(loc, redirect+"?") || strings.HasPrefix(loc, redirect+"#")) && strings.Contains(loc, "error="):
			// error sent to the registered redirect URI: fine
		case res.StatusCode >= 400:
		default:
			t.Errorf("%s: %d Location=%q", name, res.StatusCode, loc)
		}
		if strings.Contains(loc, "evil") || strings.Contains(loc, "/login") {
			t.Errorf("%s: redirected to %q", name, loc)
		}
	}
	// RFC 8252: a loopback redirect with another port is the same client.
	res := e.get("/oidc/authorize?" + authorizeQuery(c, map[string]string{"redirect_uri": "http://127.0.0.1:43123/callback"}))
	if res.StatusCode != 302 || !strings.Contains(res.Header.Get("Location"), "/login?id=") {
		t.Errorf("loopback any-port: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// The library matches loopback redirects on path and query only (RFC 8252 §7.3 says the
	// port may vary; it also ignores the host): any loopback host works. Pinned, not a hole:
	// the code still goes to the user's own machine, where any port was already allowed.
	for _, ru := range []string{"http://127.0.0.2/callback", "http://localhost/callback", "http://[::1]:8080/callback"} {
		res := e.get("/oidc/authorize?" + authorizeQuery(c, map[string]string{"redirect_uri": ru}))
		if res.StatusCode != 302 || !strings.Contains(res.Header.Get("Location"), "/login?id=") {
			t.Errorf("loopback variant %s: %d", ru, res.StatusCode)
		}
	}
	// Encoded and odd paths never reach /authorize unchecked (there is no gate of ours to
	// bypass). ServeMux answers unclean paths with a 301 to the clean one on our own host.
	q := authorizeQuery(c, map[string]string{"client_id": "evil", "redirect_uri": "https://evil.example/cb", "response_type": "token"})
	for _, p := range []string{"/oidc/%61uthorize", "/oidc/AUTHORIZE", "/oidc//authorize", "/oidc/./authorize", "/oidc/x/../authorize", "/%6Fidc/authorize"} {
		res := e.get(p + "?" + q)
		if u, _ := url.Parse(res.Header.Get("Location")); u != nil && (u.Host != "" || strings.HasPrefix(u.Path, "/login")) {
			t.Errorf("%s: redirected to %s", p, res.Header.Get("Location"))
		}
	}
}

func TestIssuerPinned(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.srv.URL+"/oidc/.well-known/openid-configuration", nil)
	req.Host = "evil.example"
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("Forwarded", "host=evil.example;proto=https")
	res, err := e.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	_ = json.NewDecoder(res.Body).Decode(&d)
	if res.StatusCode != 200 || d.Issuer != e.iss.cfg.Issuer || strings.Contains(d.TokenEndpoint, "evil") {
		t.Fatalf("discovery follows headers: %+v", d)
	}
}

func TestCodeSingleUse(t *testing.T) {
	e := newEnv(t)
	email := uniq("code")
	e.user(email, "pw")
	v, c := pkce()
	code := e.code(email, "pw", c, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st, _ := e.exchange(code, v); st == 200 {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("code redeemed %d times in parallel", ok)
	}
	if st, _ := e.exchange(code, v); st == 200 {
		t.Fatal("code redeemed again")
	}
	// Wrong verifier: refused (and the code is burnt).
	v2, c2 := pkce()
	code2 := e.code(email, "pw", c2, nil)
	if st, _ := e.exchange(code2, v); st == 200 {
		t.Fatal("wrong verifier accepted")
	}
	if st, _ := e.exchange(code2, v2); st == 200 {
		t.Fatal("code usable after a failed attempt")
	}
}

// The code goes only to whoever submitted the password: the library's callback endpoint
// (code for anyone holding the auth request id, which whoever started /authorize has) is
// closed, and a done request can't be logged into again.
func TestCodeOnlyToTheLogin(t *testing.T) {
	e := newEnv(t)
	email := uniq("cb")
	e.user(email, "pw")
	_, c := pkce()
	res := e.get("/oidc/authorize?" + authorizeQuery(c, nil))
	loc, _ := url.Parse(res.Header.Get("Location"))
	id := loc.Query().Get("id")
	res = e.post("/login", url.Values{"id": {id}, "email": {email}, "password": {"pw"}})
	if res.StatusCode != 302 || !strings.Contains(res.Header.Get("Location"), "code=") {
		t.Fatalf("login: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	for _, p := range []string{"/oidc/authorize/callback?id=", "/oidc/authorize/%63allback?id="} {
		if cb := e.get(p + url.QueryEscape(id)); cb.StatusCode != 404 {
			t.Fatalf("%s: %d %s", p, cb.StatusCode, cb.Header.Get("Location"))
		}
	}
	if err := e.iss.SaveAuthCode(context.Background(), id, "second"); err == nil {
		t.Fatal("a second code was saved for one request")
	}
	if res := e.post("/login", url.Values{"id": {id}, "email": {email}, "password": {"pw"}}); res.StatusCode == 302 {
		t.Fatal("login replayed")
	}
}

// Parallel guesses can't outrun the failure count: every attempt is counted before it hashes.
func TestParallelGuessesCapped(t *testing.T) {
	e := newEnv(t)
	email := uniq("par")
	e.user(email, "right")
	_, c := pkce()
	res := e.get("/oidc/authorize?" + authorizeQuery(c, nil))
	loc, _ := url.Parse(res.Header.Get("Location"))
	id := loc.Query().Get("id")
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[int]int{}
	for i := 0; i < 4*maxFailsPerSource; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := e.post("/login", url.Values{"id": {id}, "email": {email}, "password": {"wrong"}}).StatusCode
			mu.Lock()
			counts[st]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if counts[401] != maxFailsPerSource || counts[429] != 3*maxFailsPerSource {
		t.Fatalf("40 parallel guesses: %v, want %d checked", counts, maxFailsPerSource)
	}
}

func TestHashConcurrency(t *testing.T) {
	for _, c := range []struct {
		procs int
		mem   int64
		want  int
	}{{4, math.MaxInt64, 4}, {4, 200 << 20, 4}, {64, 200 << 20, 5}, {64, 1 << 30, 26}, {1, 10 << 20, 1}, {8, 0, 8}} {
		if got := hashConcurrency(c.procs, c.mem); got != c.want {
			t.Errorf("hashConcurrency(%d, %d) = %d, want %d", c.procs, c.mem, got, c.want)
		}
	}
}

func TestLoginFailuresAndLimits(t *testing.T) {
	e := newEnv(t)
	email := uniq("lim")
	e.user(email, "right")
	_, c := pkce()
	res := e.get("/oidc/authorize?" + authorizeQuery(c, nil))
	loc, _ := url.Parse(res.Header.Get("Location"))
	id := loc.Query().Get("id")
	try := func(em, pw string) int {
		return e.post("/login", url.Values{"id": {id}, "email": {em}, "password": {pw}}).StatusCode
	}
	if st := try(uniq("nobody"), "x"); st != 401 {
		t.Fatalf("unknown email: %d", st)
	}
	for i := 0; i < maxFailsPerSource; i++ {
		if st := try(email, "wrong"); st != 401 {
			t.Fatalf("attempt %d: %d", i, st)
		}
	}
	if st := try(email, "right"); st != 429 {
		t.Fatalf("after %d failures: %d, want 429", maxFailsPerSource, st)
	}
}

func TestLoginTimingUnknownVsWrong(t *testing.T) {
	e := newEnv(t)
	email := uniq("timing")
	e.user(email, "right")
	measure := func(em string) time.Duration {
		start := time.Now()
		e.iss.authenticate(context.Background(), em, "wrong")
		return time.Since(start)
	}
	var known, unknown time.Duration
	for i := 0; i < 10; i++ {
		known += measure(email)
		unknown += measure(uniq("nobody"))
	}
	if r := float64(unknown) / float64(known); r < 0.5 || r > 2 {
		t.Fatalf("unknown/known timing ratio %.2f (known %v, unknown %v)", r, known/10, unknown/10)
	}
}

func clientToken(e *env, id, secret string) (int, tokens) {
	res := e.post("/oidc/oauth/token", url.Values{"grant_type": {"client_credentials"}}, id, secret)
	var t tokens
	_ = json.NewDecoder(res.Body).Decode(&t)
	return res.StatusCode, t
}

func TestMachineClientsInTx(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// Rolled back with the caller's transaction: the secret never works.
	var rolled identity.Client
	_ = pgx.BeginFunc(ctx, e.pool, func(tx pgx.Tx) error {
		var err error
		rolled, err = e.iss.CreateClient(db.WithTx(ctx, tx), "agent-x", "m_1")
		if err != nil {
			t.Fatal(err)
		}
		return errors.New("rollback")
	})
	if st, _ := clientToken(e, rolled.ClientID, rolled.ClientSecret); st == 200 {
		t.Fatal("rolled-back client got a token")
	}

	// Committed: works, no refresh token, sub == client_id, verifies.
	var c identity.Client
	if err := pgx.BeginFunc(ctx, e.pool, func(tx pgx.Tx) error {
		var err error
		c, err = e.iss.CreateClient(db.WithTx(ctx, tx), "app-y", "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	st, tok := clientToken(e, c.ClientID, c.ClientSecret)
	if st != 200 || tok.RefreshToken != "" || tok.IDToken != "" {
		t.Fatalf("client_credentials: %d %+v", st, tok)
	}
	if got, err := e.iss.Verify(ctx, tok.AccessToken); err != nil || got.Subject != c.Subject {
		t.Fatalf("verify client token: %v %+v", err, got)
	}
	// A machine client can't use the user flows.
	if res := e.post("/oidc/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}, c.ClientID, c.ClientSecret); res.StatusCode == 200 {
		t.Fatal("machine client refresh grant")
	}

	// Rolled-back user: can't log in.
	email := uniq("rolled")
	_ = pgx.BeginFunc(ctx, e.pool, func(tx pgx.Tx) error {
		if _, err := e.iss.CreateUser(db.WithTx(ctx, tx), email, "pw", "user"); err != nil {
			t.Fatal(err)
		}
		return errors.New("rollback")
	})
	if _, ok := e.iss.authenticate(ctx, email, "pw"); ok {
		t.Fatal("rolled-back user can log in")
	}

	// DeleteClient: the secret stops at once.
	if err := e.iss.DeleteClient(ctx, c.ClientID); err != nil {
		t.Fatal(err)
	}
	if st, _ := clientToken(e, c.ClientID, c.ClientSecret); st == 200 {
		t.Fatal("deleted client got a token")
	}

	// Secret guessing: locked after maxFailsPerSource failures from one source (client id +
	// IP; this test has one IP).
	var c2 identity.Client
	c2, _ = e.iss.CreateClient(ctx, "app-z", "")
	for i := 0; i < maxFailsPerSource; i++ {
		clientToken(e, c2.ClientID, "wrong")
	}
	if st, _ := clientToken(e, c2.ClientID, c2.ClientSecret); st != 429 {
		t.Fatalf("after %d wrong secrets: %d, want 429", maxFailsPerSource, st)
	}
}

func TestRefreshRotationAndReuse(t *testing.T) {
	e := newEnv(t)
	email := uniq("refresh")
	e.user(email, "pw")
	tok := e.login(email, "pw", map[string]string{"scope": "openid offline_access"})
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token with offline_access")
	}
	refresh := func(rt string) (int, tokens) {
		res := e.post("/oidc/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"platform-cli"}})
		var t tokens
		_ = json.NewDecoder(res.Body).Decode(&t)
		return res.StatusCode, t
	}
	st, next := refresh(tok.RefreshToken)
	if st != 200 || next.RefreshToken == "" || next.RefreshToken == tok.RefreshToken {
		t.Fatalf("rotate: %d %+v", st, next)
	}
	if _, err := e.iss.Verify(context.Background(), next.AccessToken); err != nil {
		t.Fatal(err)
	}
	// Reuse of the rotated token: refused, and it revokes the family (the new one too).
	if st, _ := refresh(tok.RefreshToken); st == 200 {
		t.Fatal("rotated refresh token reused")
	}
	if st, _ := refresh(next.RefreshToken); st == 200 {
		t.Fatal("family not revoked after reuse")
	}
	// /revoke kills a fresh family.
	tok2 := e.login(email, "pw", map[string]string{"scope": "openid offline_access"})
	res := e.post("/oidc/revoke", url.Values{"token": {tok2.RefreshToken}, "client_id": {"platform-cli"}})
	if res.StatusCode != 200 {
		t.Fatalf("revoke: %d %s", res.StatusCode, body(res))
	}
	if st, _ := refresh(tok2.RefreshToken); st == 200 {
		t.Fatal("revoked refresh token works")
	}
	// A disabled user can't refresh.
	tok3 := e.login(email, "pw", map[string]string{"scope": "openid offline_access"})
	_, _ = e.pool.Exec(context.Background(), `UPDATE idp_users SET disabled_at=now() WHERE email=$1`, email)
	if st, _ := refresh(tok3.RefreshToken); st == 200 {
		t.Fatal("disabled user refreshed")
	}
}

// Two instances on one DB: same key, tokens cross over; a rotation on one is picked up by
// the other without a restart; a retired key stops verifying everywhere.
func TestTwoInstancesAndRotation(t *testing.T) {
	a := newEnv(t)
	b := startIssuer(t, a.pool, a.iss.cfg.Issuer) // two instances behind one public name
	ctx := context.Background()
	email := uniq("multi")
	a.user(email, "pw")
	v, c := pkce()
	code := a.code(email, "pw", c, nil)
	st, tok := b.exchange(code, v) // code from A redeemed on B
	if st != 200 {
		t.Fatalf("cross-instance code: %d", st)
	}
	if _, err := a.iss.Verify(ctx, tok.AccessToken); err != nil {
		t.Fatalf("B's token on A: %v", err)
	}

	// Rotate (sign at once), then B signs with the new key: A has never seen it.
	if err := Rotate(ctx, a.pool, a.iss.cfg.Secret, 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := b.iss.keys.live(ctx, true); err != nil { // B's next scheduled reload
		t.Fatal(err)
	}
	newTok := b.login(email, "pw", nil)
	if _, err := a.iss.Verify(ctx, newTok.AccessToken); err != nil {
		t.Fatalf("A rejects the rotated key's token: %v", err)
	}
	if _, err := b.iss.Verify(ctx, tok.AccessToken); err != nil {
		t.Fatalf("old key's token rejected during overlap: %v", err)
	}

	// Compromise: retire every older key now. After the reload interval both reject.
	if _, err := a.pool.Exec(ctx, `UPDATE idp_signing_keys SET retire_at=now() WHERE id <> (SELECT id FROM idp_signing_keys ORDER BY sign_from DESC LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	for _, inst := range []*env{a, b} {
		if _, err := inst.iss.keys.live(ctx, true); err != nil {
			t.Fatal(err)
		}
		if _, err := inst.iss.Verify(ctx, tok.AccessToken); err == nil {
			t.Fatal("retired key still verifies after reload")
		}
	}
	var n int
	_ = a.pool.QueryRow(ctx, `SELECT count(*) FROM idp_signing_keys WHERE retire_at IS NULL`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d live unretired keys", n)
	}
}

func TestKeysEncryptedAtRest(t *testing.T) {
	e := newEnv(t)
	var enc []byte
	if err := e.pool.QueryRow(context.Background(), `SELECT private_enc FROM idp_signing_keys LIMIT 1`).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), "PRIVATE") || len(enc) < 100 {
		t.Fatal("key not encrypted")
	}
	wrong, _ := newKeyRing(e.pool, "another-secret-0123456789abcdef-0123")
	if _, err := wrong.live(context.Background(), true); err == nil {
		t.Fatal("keys decrypt with another secret")
	}
	// An instance with the wrong secret refuses to start (instead of failing every token).
	if _, err := New(context.Background(), e.pool, Config{Issuer: "http://x/oidc", Secret: "another-secret-0123456789abcdef-0123"},
		slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("started with a secret that can't decrypt the keys")
	}
}

func TestPasswordHash(t *testing.T) {
	h := hashPassword("s3cret")
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") || !checkPassword(h, "s3cret") || checkPassword(h, "s3creT") {
		t.Fatalf("hash/check: %s", h)
	}
	if checkPassword("$2a$10$bcrypt", "x") || checkPassword("garbage", "x") {
		t.Fatal("accepted a non-argon2id hash")
	}
}

// Retiring every key by hand (a leaked key, no rotation first) doesn't stop logins until a
// restart: the next signing creates a key.
func TestAllKeysRetired(t *testing.T) {
	e := newEnv(t)
	email := uniq("retired")
	e.user(email, "pw")
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `UPDATE idp_signing_keys SET retire_at=now() WHERE retire_at IS NULL OR retire_at > now()`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.iss.keys.live(ctx, true); err != nil {
		t.Fatal(err)
	}
	tok := e.login(email, "pw", nil)
	if _, err := e.iss.Verify(ctx, tok.AccessToken); err != nil {
		t.Fatalf("token after all keys were retired: %v", err)
	}
}

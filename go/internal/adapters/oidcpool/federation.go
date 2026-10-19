package oidcpool

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
)

// Sign in with Shop (SPEC §16.5): a tenant pool's customer login with the shop pool as an
// upstream OpenID provider, over HTTP, as if the shop pool were another company's IdP. The
// tenant pool is a confidential client of the shop pool (created with the merchant); the RP
// side is zitadel/oidc's certified pkg/client/rp (discovery, code exchange with PKCE, ID token
// verification against the shop pool's JWKS). Both pools live in this app, so the back channel
// calls the app itself (InternalURL); nothing in the flow uses an in-process shortcut.
//
//	1. GET  /oidc/<tenant>/login/shop?id=<auth request>   (the "Sign in with Shop" button)
//	   → state row + cookie binding it to this user agent → 302 to the shop pool's /authorize
//	2. the shop pool's login (/oidc/shop/login) → 302 back with ?code&state
//	3. GET  /oidc/<tenant>/federation/shop/callback       → claim the state (once, cookie must
//	   match), exchange the code, verify the ID token (iss, aud, nonce), find or create the
//	   tenant identity linked to the shop subject, let the app link its customer record (same
//	   transaction), mark the tenant auth request done → 302 with the tenant pool's code.

const (
	fedStateTTL = 10 * time.Minute
	fedCookie   = "h2_fed"
)

type federation struct {
	s    *Issuer
	hc   *http.Client
	mu   sync.Mutex
	rps  map[string]rp.RelyingParty // per tenant pool (client id + secret differ), discovery cached
	rpAt map[string]time.Time
}

func newFederation(s *Issuer) *federation {
	return &federation{s: s, hc: backChannel(s.cfg.PublicURL, s.cfg.InternalURL), rps: map[string]rp.RelyingParty{}, rpAt: map[string]time.Time{}}
}

// backChannel: an HTTP client that sends requests for the public host to the internal URL
// (the app reaching itself), keeping the URLs, and so the issuer strings, public.
func backChannel(public, internal string) *http.Client {
	pu, _ := url.Parse(public)
	iu, _ := url.Parse(internal)
	base := http.DefaultTransport
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
			if internal != "" && iu != nil && r.URL.Host == pu.Host {
				r = r.Clone(r.Context())
				r.URL.Scheme, r.URL.Host = iu.Scheme, iu.Host
			}
			return base.RoundTrip(r)
		}),
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// relyingParty for the tenant pool p at the shop pool. Cached per pool for an hour (discovery is
// one HTTP call; the JWKS is cached by the RP's key set).
func (f *federation) relyingParty(ctx context.Context, p *Pool) (rp.RelyingParty, error) {
	f.mu.Lock()
	r, ok := f.rps[p.ID]
	fresh := ok && time.Since(f.rpAt[p.ID]) < time.Hour
	f.mu.Unlock()
	if fresh {
		return r, nil
	}
	if p.UpstreamClientID == "" || len(p.upstreamSecretEnc) == 0 {
		return nil, errors.New("pool has no Shop upstream")
	}
	secret, err := f.s.keys.open(p.upstreamSecretEnc, "upstream:"+p.ID)
	if err != nil {
		return nil, err
	}
	r, err = rp.NewRelyingPartyOIDC(ctx, f.s.issuerFor(kindShop), p.UpstreamClientID, string(secret),
		f.s.issuerFor(p.ID)+fedCallbackPath, []string{oidc.ScopeOpenID}, rp.WithHTTPClient(f.hc),
		rp.WithVerifierOpts(rp.WithSupportedSigningAlgorithms(oidcES256), rp.WithNonce(nonceFrom)))
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.rps[p.ID], f.rpAt[p.ID] = r, time.Now()
	f.mu.Unlock()
	return r, nil
}

// The ID token's nonce must be the one this round trip sent (rp's verifier reads it from ctx).
type nonceKey struct{}

func nonceFrom(ctx context.Context) string {
	n, _ := ctx.Value(nonceKey{}).(string)
	return n
}

func fedError(w http.ResponseWriter, status int, code string) {
	core.WriteJSON(w, status, map[string]string{"error": code})
}

// fedStart: the "Sign in with Shop" step of a tenant pool's customer login.
func (s *Issuer) fedStart(w http.ResponseWriter, r *http.Request) {
	p := poolFrom(r.Context())
	if p.Kind != kindTenant {
		http.NotFound(w, r)
		return
	}
	if !s.limits.allowIP(clientIP(r)) {
		fedError(w, 429, "too_many_requests")
		return
	}
	id := r.URL.Query().Get("id")
	clientID, pending := s.pendingRequest(r.Context(), p.ID, id)
	if !pending || !s.isLoginClient(p, clientID) {
		fedError(w, 400, "invalid_auth_request")
		return
	}
	if !s.poolActive(r.Context(), p.ID) {
		fedError(w, 403, "pool_suspended")
		return
	}
	party, err := s.fed.relyingParty(r.Context(), p)
	if err != nil {
		s.log.Error("shop upstream", "pool", p.ID, "err", err)
		fedError(w, 502, "upstream_unavailable")
		return
	}
	state, verifier, nonce, binding := randToken(), randToken(), randToken(), randToken()
	bh := sha256.Sum256([]byte(binding))
	if _, err := s.db.Exec(r.Context(), `INSERT INTO idp_federation_states(id, pool_id, auth_request_id, verifier, nonce, binding_hash, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, sha256Hex(state), p.ID, id, verifier, nonce, bh[:], time.Now().Add(fedStateTTL)); err != nil {
		fedError(w, 500, "server_error")
		return
	}
	// The round trip is bound to this user agent: the callback must present the cookie, so a
	// victim lured into finishing someone else's started login can't complete it for them.
	http.SetCookie(w, &http.Cookie{
		Name: fedCookie, Value: binding, Path: "/oidc/" + p.ID + "/federation/", MaxAge: int(fedStateTTL.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: strings.HasPrefix(s.cfg.PublicURL, "https://"),
	})
	http.Redirect(w, r, rp.AuthURL(state, party, rp.WithCodeChallenge(oidc.NewSHACodeChallenge(verifier)),
		rp.AuthURLOpt(rp.WithURLParam("nonce", nonce))), http.StatusFound)
}

// fedCallback: back from the shop pool. The pool is the path's; the state must belong to it.
func (s *Issuer) fedCallback(w http.ResponseWriter, r *http.Request) {
	p := poolFrom(r.Context())
	ctx := r.Context()
	if p.Kind != kindTenant {
		http.NotFound(w, r)
		return
	}
	if !s.limits.allowIP(clientIP(r)) {
		fedError(w, 429, "too_many_requests")
		return
	}
	q := r.URL.Query()
	if q.Get("error") != "" || q.Get("code") == "" || q.Get("state") == "" {
		fedError(w, 400, "upstream_refused")
		return
	}
	cookie, err := r.Cookie(fedCookie)
	if err != nil {
		fedError(w, 400, "missing_binding")
		return
	}
	// Claimed once, and only with the cookie of the user agent that started it (a wrong cookie
	// doesn't burn the state).
	var authReq, verifier, nonce string
	bh := sha256.Sum256([]byte(cookie.Value))
	err = s.db.QueryRow(ctx, `UPDATE idp_federation_states SET used=true WHERE id=$1 AND pool_id=$2 AND binding_hash=$3 AND NOT used AND expires_at > now()
		RETURNING auth_request_id, verifier, nonce`, sha256Hex(q.Get("state")), p.ID, bh[:]).Scan(&authReq, &verifier, &nonce)
	if err != nil {
		fedError(w, 400, "invalid_state")
		return
	}
	if !s.poolActive(ctx, p.ID) {
		fedError(w, 403, "pool_suspended")
		return
	}
	party, err := s.fed.relyingParty(ctx, p)
	if err != nil {
		fedError(w, 502, "upstream_unavailable")
		return
	}
	// Back channel, before any transaction is open (no DB connection held across HTTP).
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](context.WithValue(ctx, nonceKey{}, nonce), q.Get("code"), party, rp.WithCodeVerifier(verifier))
	if err != nil || tokens.IDTokenClaims == nil {
		s.log.Warn("shop code exchange", "pool", p.ID, "err", err)
		fedError(w, 401, "upstream_login_failed")
		return
	}
	claims := tokens.IDTokenClaims
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 || claims.Subject == "" {
		fedError(w, 401, "upstream_login_failed")
		return
	}
	var uid string
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// Find or create the tenant identity linked to this shop subject: one per (pool, shop sub),
		// never matched by email (a local customer with the same email stays separate).
		var disabled bool
		if err := tx.QueryRow(ctx, `INSERT INTO idp_users(id, pool_id, upstream_pool, upstream_sub) VALUES ($1,$2,'shop',$3)
			ON CONFLICT (pool_id, upstream_pool, upstream_sub) DO UPDATE SET upstream_sub=EXCLUDED.upstream_sub RETURNING id, disabled_at IS NOT NULL`,
			db.NewID("idu"), p.ID, claims.Subject).Scan(&uid, &disabled); err != nil {
			return err
		}
		// A linked identity the merchant disabled stays disabled, whatever Shop says.
		if disabled {
			return errors.New("tenant identity disabled")
		}
		if s.cfg.OnShopLink != nil {
			if err := s.cfg.OnShopLink(db.WithTx(ctx, tx), p.MerchantID, qualify(kindShop, claims.Subject), qualify(p.ID, uid)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.Warn("shop link", "pool", p.ID, "err", err)
		fedError(w, 403, "link_refused")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: fedCookie, Value: "", Path: "/oidc/" + p.ID + "/federation/", MaxAge: -1})
	s.completeLogin(w, r, authReq, uid)
}

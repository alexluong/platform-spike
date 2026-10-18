package zitadel

// Token verification across many issuers (stack i). The token's unverified `iss` picks the pool
// from the directory (only known issuers); the pool's keys (Zitadel JWKS of that instance,
// fetched through the internal URL with its instance header) verify it. Keys are cached per
// pool: refreshed every keyRefresh, re-fetched early on an unknown kid (at most every
// kidRefetch), and the last good set is kept when a fetch fails, so tokens of a suspended
// (blocked) merchant still verify and get 403 merchant_suspended from the app instead of 401.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"

	"github.com/alexluong/platform-spike/go/internal/identity"
)

const (
	keyRefresh = 5 * time.Minute
	kidRefetch = 10 * time.Second
)

type keySet struct {
	x    *Instances
	pool *Pool

	mu      sync.Mutex
	keys    jose.JSONWebKeySet
	fetched time.Time
	tried   time.Time
}

func (k *keySet) fetch(ctx context.Context) error {
	var set jose.JSONWebKeySet
	if err := k.x.z.Call(ctx, nil, k.pool.at(), "GET", "/oauth/v2/keys", nil, &set); err != nil {
		return err
	}
	k.keys, k.fetched = set, time.Now()
	return nil
}

// VerifySignature implements oidc.KeySet.
func (k *keySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	kid := ""
	if len(jws.Signatures) > 0 {
		kid = jws.Signatures[0].Header.KeyID
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now()
	stale := now.Sub(k.fetched) > keyRefresh
	missing := len(k.keys.Key(kid)) == 0
	if (stale || missing) && now.Sub(k.tried) > kidRefetch {
		k.tried = now
		if err := k.fetch(ctx); err != nil && k.fetched.IsZero() {
			return nil, fmt.Errorf("jwks %s: %w", k.pool.Issuer, err)
		} // else: keep the last good set (static stability while Zitadel or the instance is down)
	}
	for _, key := range k.keys.Key(kid) {
		if out, err := jws.Verify(key); err == nil {
			return out, nil
		}
	}
	return nil, errors.New("no key verifies the token")
}

func (x *Instances) keysFor(p *Pool) *keySet {
	x.mu.Lock()
	defer x.mu.Unlock()
	ks := x.keys[p.Key]
	if ks == nil {
		ks = &keySet{x: x, pool: p}
		x.keys[p.Key] = ks
	}
	return ks
}

func unverifiedIssuer(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	_ = json.Unmarshal(b, &c)
	return c.Iss
}

// Verify (SPEC §14 P7 as in stack a, per pool): known issuer, RS256 signature by that pool's
// keys, aud contains the pool's login project, exp; an access token (not an ID token); the client
// is the pool's login app, or (platform pool only) a machine user of an app or agent.
func (x *Instances) Verify(ctx context.Context, bearer string) (identity.Token, error) {
	iss := unverifiedIssuer(bearer)
	if iss == "" {
		return identity.Token{}, fmt.Errorf("%w: no issuer", identity.ErrInvalidToken)
	}
	p, err := x.poolByIssuer(ctx, iss)
	if err != nil || p.Status != "active" {
		return identity.Token{}, fmt.Errorf("%w: unknown issuer %q", identity.ErrInvalidToken, iss)
	}
	v := oidc.NewVerifier(p.Issuer, x.keysFor(p), &oidc.Config{ClientID: p.ProjectID, SupportedSigningAlgs: []string{oidc.RS256}})
	tok, err := v.Verify(ctx, bearer)
	if err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	var cl accessClaims
	if err := tok.Claims(&cl); err != nil {
		return identity.Token{}, fmt.Errorf("%w: claims: %v", identity.ErrInvalidToken, err)
	}
	if cl.ClientID == "" || cl.AtHash != "" || cl.Nonce != "" || cl.Azp != "" || len(cl.Amr) > 0 {
		return identity.Token{}, fmt.Errorf("%w: not an access token", identity.ErrInvalidToken)
	}
	machine := p.Key == PoolPlatform && tok.Subject != "" && (strings.HasPrefix(cl.ClientID, "app_") || strings.HasPrefix(cl.ClientID, "ag_"))
	if cl.ClientID != p.ClientID && !machine {
		return identity.Token{}, fmt.Errorf("%w: client %q not allowed for %s", identity.ErrInvalidToken, cl.ClientID, p.Key)
	}
	return identity.Token{Subject: subject(p.Key, tok.Subject)}, nil
}

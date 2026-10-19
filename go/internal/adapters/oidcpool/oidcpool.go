// Package oidcpool is stack h2's identity adapter: stack h's in-app OpenID provider
// (zitadel/oidc pkg/op, state in the app's Postgres) with pools as rows (SPEC §16). Every pool
// (workforce, platform, shop, one tenant pool per merchant) is its own issuer at
// PUBLIC_URL/oidc/<pool>, with its own users, clients, codes, refresh tokens and signing keys.
// One op.Provider serves them all: the pool comes from the request path (checked against the
// directory) and the library reads the issuer from the request context. Identity writes
// (users, clients, a merchant's pool) join the request's transaction. Tokens are verified
// in-process: the pool from `iss` (exact match + directory), then that pool's keys.
package oidcpool

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/cors"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
)

//go:embed schema/*.sql
var schema embed.FS

// Migrate creates the issuer's tables (and the three platform-level pools) in the app's database.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return db.MigrateFS(ctx, pool, schema, "schema/*.sql")
}

type Config struct {
	PublicURL string // e.g. http://host:8098; issuers are PublicURL/oidc/<pool>; never from the request
	// InternalURL reaches this app from inside itself (back channel of Sign in with Shop: the
	// tenant pool calls the shop pool's discovery, token and JWKS endpoints over HTTP). Requests
	// to PublicURL's host are sent there; the issuer strings stay PublicURL's.
	InternalURL   string
	Secret        string // >= 32 chars: encrypts signing keys and upstream secrets, keys the library's crypto
	Audience      string // the API: access tokens carry it as aud
	LoginClientID string // first-party public client of the workforce, platform and shop pools
	ShopperClient string // first-party public client of a tenant pool's customers (storefront)
	RedirectURIs  []string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	// OnShopLink is called in the Sign in with Shop transaction (ctx carries it) after the tenant
	// identity is found or created: the app links its customer record (SPEC §16.5).
	OnShopLink identity.ShopLinker
}

type Issuer struct {
	cfg      Config
	db       *pgxpool.Pool
	log      *slog.Logger
	keys     *keyRing
	dir      *directory
	limits   *limits
	provider *op.Provider
	fed      *federation
}

func New(ctx context.Context, pool *pgxpool.Pool, cfg Config, log *slog.Logger) (*Issuer, error) {
	if len(cfg.Secret) < 32 {
		return nil, errors.New("oidcpool: secret must be at least 32 characters")
	}
	cfg.PublicURL = strings.TrimSuffix(cfg.PublicURL, "/")
	keys, err := newKeyRing(pool, cfg.Secret)
	if err != nil {
		return nil, err
	}
	for _, p := range []string{kindWorkforce, kindPlatform, kindShop} {
		if err := keys.ensure(ctx, p); err != nil {
			return nil, fmt.Errorf("oidcpool: signing key %s: %w", p, err)
		}
		// Fail at start, not on every token, when the keys don't decrypt (wrong ISSUER_SECRET).
		if _, err := keys.live(ctx, p, true); err != nil {
			return nil, fmt.Errorf("oidcpool: signing keys: %w", err)
		}
	}
	s := &Issuer{
		cfg: cfg, db: pool, log: log, keys: keys,
		dir:    &directory{db: pool, m: map[string]dirEntry{}},
		limits: newLimits(50, 200, limitWindow),
	}
	s.fed = newFederation(s)
	opts := []op.Option{
		op.WithAccessTokenKeySet(ctxKeySet{keys}),
		op.WithAccessTokenVerifierOpts(op.WithSupportedAccessTokenSigningAlgorithms(oidcES256)),
		op.WithIDTokenHintKeySet(ctxKeySet{keys}),
		op.WithIDTokenHintVerifierOpts(op.WithSupportedIDTokenHintSigningAlgorithms(oidcES256)),
		op.WithCORSOptions(&cors.Options{AllowOriginFunc: func(string) bool { return false }}),
	}
	if strings.HasPrefix(cfg.PublicURL, "http://") {
		opts = append(opts, op.WithAllowInsecure())
	}
	// The issuer per request: the pool route() put in ctx (from the path, via the directory).
	// Never Host / X-Forwarded-*.
	issuer := func(bool) (op.IssuerFromRequest, error) {
		return func(r *http.Request) string {
			if p := poolFrom(r.Context()); p != nil {
				return s.issuerFor(p.ID)
			}
			return ""
		}, nil
	}
	s.provider, err = op.NewProvider(&op.Config{
		CryptoKey:             sha256.Sum256([]byte("idp-op-crypto:" + cfg.Secret)),
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
	}, s, issuer, opts...)
	if err != nil {
		return nil, err
	}
	go s.sweep()
	return s, nil
}

const oidcES256 = "ES256"

// Mount serves every pool under /oidc/<pool>/ (provider endpoints, the login step, Sign in with Shop).
func (s *Issuer) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/oidc/", s.route)
}

// Verify (identity port): the pool from the token's `iss` (must be exactly PublicURL/oidc/<id> for
// a pool in the directory), then signature (ES256) against that pool's keys only, iss and exp
// (library), then ours: an access token (token_use), aud = the API, and a client this pool
// issues API tokens to (its login clients; machine clients only in the platform pool, sub ==
// client_id). The subject the app sees is "<pool>:<sub>"; tenant tokens carry the pool's
// merchant (from the directory, not a claim).
func (s *Issuer) Verify(ctx context.Context, bearer string) (identity.Token, error) {
	bad := func(err error) (identity.Token, error) {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	iss, err := unverifiedIssuer(bearer)
	if err != nil {
		return bad(err)
	}
	id, ok := strings.CutPrefix(iss, s.cfg.PublicURL+"/oidc/")
	if !ok {
		return bad(errors.New("unknown issuer"))
	}
	p, err := s.dir.get(ctx, id)
	if err != nil {
		return bad(errors.New("unknown issuer"))
	}
	v := op.NewAccessTokenVerifier(s.issuerFor(p.ID), poolKeySet{s.keys, p.ID}, op.WithSupportedAccessTokenSigningAlgorithms(oidcES256))
	cl, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, bearer, v)
	if err != nil {
		return bad(err)
	}
	switch {
	case cl.Claims["token_use"] != "access":
		err = errors.New("not an access token")
	case !slices.Contains(cl.Audience, s.cfg.Audience):
		err = errors.New("wrong audience")
	case cl.Subject == "":
		err = errors.New("no subject")
	case s.isLoginClient(p, cl.ClientID):
	case p.Kind == kindPlatform && cl.ClientID == cl.Subject && strings.HasPrefix(cl.Subject, "cli_"):
	default:
		err = fmt.Errorf("client %q not accepted for pool %s", cl.ClientID, p.ID)
	}
	if err != nil {
		return bad(err)
	}
	t := identity.Token{Subject: qualify(p.ID, cl.Subject)}
	if p.Kind == kindTenant {
		t.MerchantID = p.MerchantID
	}
	return t, nil
}

// unverifiedIssuer reads `iss` to pick the pool; nothing is trusted until the pool's keys verify it.
func unverifiedIssuer(token string) (string, error) {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return "", err
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &c); err != nil {
		return "", err
	}
	return c.Iss, nil
}

// isLoginClient: clientID is this pool's first-party login client (tenant pools: the storefront,
// since they hold customers only; platform-level pools: LoginClientID).
func (s *Issuer) isLoginClient(p *Pool, clientID string) bool {
	if p.Kind == kindTenant {
		return clientID == s.cfg.ShopperClient
	}
	return clientID == s.cfg.LoginClientID
}

// CreateClient (identity port): a machine client for an app or agent, in the platform pool, in
// the caller's transaction. The secret is returned once; only its hash is stored.
func (s *Issuer) CreateClient(ctx context.Context, name, merchantID string) (identity.Client, error) {
	id, secret := db.NewID("cli"), randToken()
	h := sha256.Sum256([]byte(secret))
	var mid *string
	if merchantID != "" {
		mid = &merchantID
	}
	if _, err := db.TxOr(ctx, s.db).Exec(ctx, `INSERT INTO idp_clients(id, pool_id, kind, name, merchant_id, secret_hash) VALUES ($1,'platform','machine',$2,$3,$4)`,
		id, name, mid, h[:]); err != nil {
		return identity.Client{}, err
	}
	return identity.Client{Subject: qualify(kindPlatform, id), ClientID: id, ClientSecret: secret}, nil
}

// DeleteClient (identity port): the secret stops minting tokens at once (caller's transaction).
func (s *Issuer) DeleteClient(ctx context.Context, clientID string) error {
	_, err := db.TxOr(ctx, s.db).Exec(ctx, `UPDATE idp_clients SET deleted_at=now() WHERE id=$1 AND pool_id='platform' AND kind='machine' AND deleted_at IS NULL`, clientID)
	return err
}

// DriverConfig: what the conformance driver needs (TEST_MODE). Nothing secret.
func (s *Issuer) DriverConfig() map[string]any {
	return map[string]any{
		"idp": "oidcpool", "issuerBase": s.cfg.PublicURL + "/oidc/", "clientId": s.cfg.LoginClientID,
		"customerClientId": s.cfg.ShopperClient,
		"redirectUri":      s.cfg.RedirectURIs[0], "audience": s.cfg.Audience,
	}
}

// Ping: the issuer is the app's DB.
func (s *Issuer) Ping(ctx context.Context) error { return s.db.Ping(ctx) }

// Rotate publishes a new signing key for the pool (every pool when poolID is ""), signs with it
// after publishAhead, and retires the current keys retireAfter later (bootstrap rotate-signing-key).
func Rotate(ctx context.Context, pool *pgxpool.Pool, secret, poolID string, publishAhead, retireAfter time.Duration) error {
	k, err := newKeyRing(pool, secret)
	if err != nil {
		return err
	}
	ids := []string{poolID}
	if poolID == "" {
		rows, err := pool.Query(ctx, `SELECT id FROM idp_pools ORDER BY id`)
		if err != nil {
			return err
		}
		if ids, err = collectStrings(rows); err != nil {
			return err
		}
	}
	for _, id := range ids {
		if err := k.rotate(ctx, id, publishAhead, retireAfter); err != nil {
			return fmt.Errorf("rotate %s: %w", id, err)
		}
	}
	return nil
}

// sweep deletes expired auth requests, federation states, refresh tokens and retired keys.
func (s *Issuer) sweep() {
	for range time.Tick(10 * time.Minute) {
		for _, q := range []string{
			`DELETE FROM idp_auth_requests WHERE expires_at < now() - interval '1 hour'`,
			`DELETE FROM idp_federation_states WHERE expires_at < now() - interval '1 hour'`,
			`DELETE FROM idp_refresh_tokens WHERE expires_at < now() - interval '1 day'`,
			`DELETE FROM idp_signing_keys WHERE retire_at < now() - interval '1 day'`,
		} {
			if _, err := s.db.Exec(context.Background(), q); err != nil {
				s.log.Warn("oidcpool sweep", "err", err)
			}
		}
	}
}

func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

var _ = url.QueryEscape

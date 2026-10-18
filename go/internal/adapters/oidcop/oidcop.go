// Package oidcop is stack h's identity adapter: an OpenID provider inside the app, built
// on zitadel/oidc's pkg/op (OpenID Certified), with users, machine clients, auth
// requests, refresh tokens and signing keys in the app's own Postgres. Identity writes
// (CreateUser, CreateClient, DeleteClient) join the request's transaction. Tokens are
// verified in-process against the same key ring, no JWKS fetch.
package oidcop

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/cors"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
)

//go:embed schema/*.sql
var schema embed.FS

// Migrate creates the issuer's tables in the app's database.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return db.MigrateFS(ctx, pool, schema, "schema/*.sql")
}

type Config struct {
	Issuer        string        // pinned issuer URL, e.g. http://host:8094/oidc; never taken from the request
	LoginURL      string        // the login step (/login on the app)
	Secret        string        // >= 32 chars: encrypts signing keys at rest, keys the library's crypto
	Audience      string        // the API: access tokens carry it as aud
	LoginClientID string        // the first-party public client (code + PKCE)
	RedirectURIs  []string      // its redirect URIs (loopback: any port, RFC 8252)
	AccessTTL     time.Duration // access tokens (stateless: also the revocation delay)
	RefreshTTL    time.Duration // refresh token family lifetime
}

type Issuer struct {
	cfg      Config
	db       *pgxpool.Pool
	log      *slog.Logger
	keys     *keyRing
	limits   *limits
	loginCl  *client
	provider *op.Provider
	verifier *op.AccessTokenVerifier
}

func New(ctx context.Context, pool *pgxpool.Pool, cfg Config, log *slog.Logger) (*Issuer, error) {
	if len(cfg.Secret) < 32 {
		return nil, errors.New("oidcop: secret must be at least 32 characters")
	}
	keys, err := newKeyRing(pool, cfg.Secret)
	if err != nil {
		return nil, err
	}
	if err := keys.ensure(ctx); err != nil {
		return nil, fmt.Errorf("oidcop: signing key: %w", err)
	}
	// Fail at start, not on every token, when the keys don't decrypt (wrong ISSUER_SECRET).
	if _, err := keys.live(ctx, true); err != nil {
		return nil, fmt.Errorf("oidcop: signing keys: %w", err)
	}
	s := &Issuer{
		cfg: cfg, db: pool, log: log, keys: keys,
		limits: newLimits(50, 200, limitWindow),
		loginCl: &client{
			id: cfg.LoginClientID, redirects: cfg.RedirectURIs, appType: op.ApplicationTypeNative,
			authMethod: oidc.AuthMethodNone, responses: []oidc.ResponseType{oidc.ResponseTypeCode},
			grants: []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}, loginURL: cfg.LoginURL,
		},
	}
	opts := []op.Option{
		op.WithAccessTokenKeySet(keys),
		op.WithAccessTokenVerifierOpts(op.WithSupportedAccessTokenSigningAlgorithms(string(oidcES256))),
		op.WithIDTokenHintKeySet(keys),
		op.WithIDTokenHintVerifierOpts(op.WithSupportedIDTokenHintSigningAlgorithms(string(oidcES256))),
		// The default CORS policy reflects any origin with credentials. No browser client here.
		op.WithCORSOptions(&cors.Options{AllowOriginFunc: func(string) bool { return false }}),
	}
	if strings.HasPrefix(cfg.Issuer, "http://") {
		opts = append(opts, op.WithAllowInsecure()) // dev stack on http
	}
	s.provider, err = op.NewProvider(&op.Config{
		CryptoKey:             sha256.Sum256([]byte("idp-op-crypto:" + cfg.Secret)),
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
	}, s, op.StaticIssuer(cfg.Issuer), opts...)
	if err != nil {
		return nil, err
	}
	s.verifier = op.NewAccessTokenVerifier(cfg.Issuer, keys, op.WithSupportedAccessTokenSigningAlgorithms(string(oidcES256)))
	go s.sweep()
	return s, nil
}

const oidcES256 = "ES256"

// Mount serves the provider under the issuer's path (e.g. /oidc/authorize, /oidc/oauth/token,
// /oidc/keys, /oidc/.well-known/openid-configuration) and the login step.
func (s *Issuer) Mount(mux *http.ServeMux) {
	u, _ := url.Parse(s.cfg.Issuer)
	prefix := strings.TrimSuffix(u.Path, "/")
	mux.Handle(prefix+"/", http.StripPrefix(prefix, s.limitToken(s.provider)))
	lu, _ := url.Parse(s.cfg.LoginURL)
	mux.HandleFunc(lu.Path, s.handleLogin)
}

// Verify (identity port, SPEC §14 P7): signature with the ES256 allowlist against the live
// keys, iss (pinned), exp (library); then ours: an access token (token_use; ID tokens
// share typ and aud), aud = the API, and the client: the login client (users) or the
// machine client itself (client_credentials: sub == client_id).
func (s *Issuer) Verify(ctx context.Context, bearer string) (identity.Token, error) {
	cl, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, bearer, s.verifier)
	if err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	switch {
	case cl.Claims["token_use"] != "access":
		err = errors.New("not an access token")
	case !slices.Contains(cl.Audience, s.cfg.Audience):
		err = errors.New("wrong audience")
	case cl.Subject == "" || (cl.ClientID != s.cfg.LoginClientID && cl.ClientID != cl.Subject):
		err = fmt.Errorf("client %q not accepted", cl.ClientID)
	}
	if err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	return identity.Token{Subject: cl.Subject}, nil
}

// CreateClient (identity port): a machine client for an app or agent, in the caller's
// transaction. The secret is returned once; only its hash is stored.
func (s *Issuer) CreateClient(ctx context.Context, name, merchantID string) (identity.Client, error) {
	id, secret := db.NewID("cli"), randToken()
	h := sha256.Sum256([]byte(secret))
	var mid *string
	if merchantID != "" {
		mid = &merchantID
	}
	if _, err := db.TxOr(ctx, s.db).Exec(ctx, `INSERT INTO idp_clients(id, name, merchant_id, secret_hash) VALUES ($1,$2,$3,$4)`,
		id, name, mid, h[:]); err != nil {
		return identity.Client{}, err
	}
	return identity.Client{Subject: id, ClientID: id, ClientSecret: secret}, nil
}

// DeleteClient (identity port): the secret stops minting tokens at once (in the caller's
// transaction); tokens already issued live out AccessTTL.
func (s *Issuer) DeleteClient(ctx context.Context, clientID string) error {
	_, err := db.TxOr(ctx, s.db).Exec(ctx, `UPDATE idp_clients SET deleted_at=now() WHERE id=$1 AND deleted_at IS NULL`, clientID)
	return err
}

// DriverConfig: what the conformance driver needs (TEST_MODE). Nothing secret.
func (s *Issuer) DriverConfig() map[string]any {
	return map[string]any{
		"idp": "oidcop", "issuer": s.cfg.Issuer, "clientId": s.cfg.LoginClientID,
		"redirectUri": s.cfg.RedirectURIs[0], "audience": s.cfg.Audience,
	}
}

// Ping: the issuer is the app's DB.
func (s *Issuer) Ping(ctx context.Context) error { return s.db.Ping(ctx) }

// Rotate publishes a new signing key now, signs with it after publishAhead, and retires the
// current keys after the tokens they signed have expired (bootstrap rotate-signing-key).
func Rotate(ctx context.Context, pool *pgxpool.Pool, secret string, publishAhead, retireAfter time.Duration) error {
	k, err := newKeyRing(pool, secret)
	if err != nil {
		return err
	}
	return k.rotate(ctx, publishAhead, retireAfter)
}

// sweep deletes expired auth requests, refresh tokens and retired keys.
func (s *Issuer) sweep() {
	for range time.Tick(10 * time.Minute) {
		for _, q := range []string{
			`DELETE FROM idp_auth_requests WHERE expires_at < now() - interval '1 hour'`,
			`DELETE FROM idp_refresh_tokens WHERE expires_at < now() - interval '1 day'`,
			`DELETE FROM idp_signing_keys WHERE retire_at < now() - interval '1 day'`,
		} {
			if _, err := s.db.Exec(context.Background(), q); err != nil {
				s.log.Warn("oidcop sweep", "err", err)
			}
		}
	}
}

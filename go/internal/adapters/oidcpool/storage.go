package oidcpool

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/alexluong/platform-spike/go/internal/db"
)

// This file is the op.Storage contract (plus op.ClientCredentialsStorage) on the app's
// Postgres. zitadel/oidc does the protocol: request parsing and validation, exact
// redirect matching, PKCE verification, client authentication, token and JWKS encoding,
// JWT signing, discovery. We decide what is stored, for how long, and who may do what.

const (
	authRequestTTL = 10 * time.Minute
	codeTTL        = time.Minute
	idTokenTTL     = 5 * time.Minute
)

var errNotFound = errors.New("not found")

// pid: the pool the request's path named (route); "" outside a pool route, which matches nothing.
func pid(ctx context.Context) string {
	if p := poolFrom(ctx); p != nil {
		return p.ID
	}
	return ""
}

func collectStrings(rows pgx.Rows) ([]string, error) {
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ---- auth requests and codes ----

type authRequest struct {
	ID           string                   `json:"-"`
	ClientID     string                   `json:"clientId"`
	RedirectURI  string                   `json:"redirectUri"`
	Scopes       []string                 `json:"scopes"`
	State        string                   `json:"state"`
	Nonce        string                   `json:"nonce"`
	ResponseType oidc.ResponseType        `json:"responseType"`
	ResponseMode oidc.ResponseMode        `json:"responseMode"`
	Challenge    string                   `json:"challenge"`
	Method       oidc.CodeChallengeMethod `json:"method"`
	Audience     []string                 `json:"audience"`
	UserID       string                   `json:"-"`
	AuthTime     time.Time                `json:"-"`
	IsDone       bool                     `json:"-"`
}

func (a *authRequest) GetID() string                      { return a.ID }
func (a *authRequest) GetACR() string                     { return "" }
func (a *authRequest) GetAMR() []string                   { return []string{"pwd"} }
func (a *authRequest) GetAudience() []string              { return a.Audience }
func (a *authRequest) GetAuthTime() time.Time             { return a.AuthTime }
func (a *authRequest) GetClientID() string                { return a.ClientID }
func (a *authRequest) GetNonce() string                   { return a.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return a.ResponseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return a.ResponseMode }
func (a *authRequest) GetScopes() []string                { return a.Scopes }
func (a *authRequest) GetState() string                   { return a.State }
func (a *authRequest) GetSubject() string                 { return a.UserID }
func (a *authRequest) Done() bool                         { return a.IsDone }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return &oidc.CodeChallenge{Challenge: a.Challenge, Method: a.Method}
}

// CreateAuthRequest stores a request the library has validated (client, exact redirect,
// response type, scopes). Our policy on top: code flow with PKCE S256 only. The library
// accepts plain PKCE and no PKCE at /authorize (it requires PKCE only at /token, for
// public clients). Refusing here keeps every stored request PKCE-bound.
func (s *Issuer) CreateAuthRequest(ctx context.Context, r *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	if r.ResponseType != oidc.ResponseTypeCode {
		return nil, oidc.ErrUnauthorizedClient().WithDescription("only response_type=code")
	}
	if r.CodeChallenge == "" || r.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE with S256 is required")
	}
	a := &authRequest{
		ID: randToken(), ClientID: r.ClientID, RedirectURI: r.RedirectURI, Scopes: r.Scopes, State: r.State,
		Nonce: r.Nonce, ResponseType: r.ResponseType, ResponseMode: r.ResponseMode,
		Challenge: r.CodeChallenge, Method: r.CodeChallengeMethod, Audience: []string{s.cfg.Audience},
	}
	// A federation client (a tenant pool at the shop pool) gets tokens for itself only, never
	// for the API: the Shop access token it receives can't be replayed at /api.
	if p := poolFrom(ctx); p != nil && s.loginGroup(p, r.ClientID) == "" {
		a.Audience = []string{r.ClientID}
	}
	b, _ := json.Marshal(a)
	_, err := s.db.Exec(ctx, `INSERT INTO idp_auth_requests(id, pool_id, request, expires_at) VALUES ($1,$2,$3,$4)`, a.ID, pid(ctx), b, time.Now().Add(authRequestTTL))
	return a, err
}

func scanAuthRequest(row pgx.Row) (op.AuthRequest, error) {
	a := &authRequest{}
	var raw []byte
	var uid *string
	var at *time.Time
	if err := row.Scan(&a.ID, &raw, &uid, &at, &a.IsDone); errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	} else if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, a); err != nil {
		return nil, err
	}
	if uid != nil {
		a.UserID = *uid
	}
	if at != nil {
		a.AuthTime = *at
	}
	return a, nil
}

const authRequestCols = `id, request, user_id, auth_time, done`

func (s *Issuer) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return scanAuthRequest(s.db.QueryRow(ctx, `SELECT `+authRequestCols+` FROM idp_auth_requests WHERE id=$1 AND pool_id=$2 AND expires_at > now()`, id, pid(ctx)))
}

// AuthRequestByCode claims the code: the first caller flips code_used, everyone after
// gets invalid_grant. The library reads, then deletes after issuing tokens, so a plain
// read would let parallel /token calls redeem one code several times (review-g #7).
func (s *Issuer) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	return scanAuthRequest(s.db.QueryRow(ctx, `UPDATE idp_auth_requests SET code_used=true
		WHERE code=$1 AND pool_id=$2 AND NOT code_used AND done AND expires_at > now() RETURNING `+authRequestCols, code, pid(ctx)))
}

// SaveAuthCode: one code per request; a second callback visit gets an error.
func (s *Issuer) SaveAuthCode(ctx context.Context, id, code string) error {
	tag, err := s.db.Exec(ctx, `UPDATE idp_auth_requests SET code=$2, expires_at=least(expires_at, now() + make_interval(secs => $3))
		WHERE id=$1 AND pool_id=$4 AND done AND code IS NULL AND expires_at > now()`, id, code, codeTTL.Seconds(), pid(ctx))
	if err == nil && tag.RowsAffected() != 1 {
		err = errors.New("auth request not found, not done, or already has a code")
	}
	return err
}

func (s *Issuer) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM idp_auth_requests WHERE id=$1 AND pool_id=$2`, id, pid(ctx))
	return err
}

// ---- tokens ----

// clientTokenRequest: client_credentials. sub = the client.
type clientTokenRequest struct {
	sub string
	aud []string
}

func (c *clientTokenRequest) GetSubject() string    { return c.sub }
func (c *clientTokenRequest) GetAudience() []string { return c.aud }
func (c *clientTokenRequest) GetScopes() []string   { return nil }

// CreateAccessToken: access tokens are self-contained JWTs (the library signs them); we
// only choose the id and lifetime. Nothing stored, so nothing to revoke: they live AccessTTL.
func (s *Issuer) CreateAccessToken(context.Context, op.TokenRequest) (string, time.Time, error) {
	return db.NewID("at"), time.Now().Add(s.cfg.AccessTTL), nil
}

type refreshRequest struct {
	userID, clientID      string
	scopes, audience, amr []string
	authTime              time.Time
}

func (r *refreshRequest) GetAMR() []string                 { return r.amr }
func (r *refreshRequest) GetAudience() []string            { return r.audience }
func (r *refreshRequest) GetAuthTime() time.Time           { return r.authTime }
func (r *refreshRequest) GetClientID() string              { return r.clientID }
func (r *refreshRequest) GetScopes() []string              { return r.scopes }
func (r *refreshRequest) GetSubject() string               { return r.userID }
func (r *refreshRequest) SetCurrentScopes(scopes []string) { r.scopes = scopes }

// CreateAccessAndRefreshTokens: a login with offline_access starts a token family; a
// refresh rotates (the old token is marked rotated in the same statement that checks it,
// so two parallel refreshes can't both succeed). The family's expiry is fixed at login.
func (s *Issuer) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, current string) (string, string, time.Time, error) {
	next := randToken()
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		family, expires := db.NewID("rtf"), time.Now().Add(s.cfg.RefreshTTL)
		if current != "" {
			err := tx.QueryRow(ctx, `UPDATE idp_refresh_tokens SET rotated_at=now()
				WHERE id=$1 AND pool_id=$2 AND rotated_at IS NULL AND revoked_at IS NULL AND expires_at > now() RETURNING family, expires_at`,
				sha256Hex(current), pid(ctx)).Scan(&family, &expires)
			if errors.Is(err, pgx.ErrNoRows) {
				return oidc.ErrInvalidGrant()
			} else if err != nil {
				return err
			}
		}
		var r refreshRequest
		switch t := req.(type) {
		case *authRequest:
			r = refreshRequest{userID: t.UserID, clientID: t.ClientID, scopes: t.Scopes, audience: t.Audience, amr: t.GetAMR(), authTime: t.AuthTime}
		case *refreshRequest:
			r = *t
		default:
			return errors.New("refresh tokens are only issued to the login client")
		}
		_, err := tx.Exec(ctx, `INSERT INTO idp_refresh_tokens(id, pool_id, family, user_id, client_id, scopes, audience, amr, auth_time, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, sha256Hex(next), pid(ctx), family, r.userID, r.clientID, r.scopes, r.audience, r.amr, r.authTime, expires)
		return err
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	return db.NewID("at"), next, time.Now().Add(s.cfg.AccessTTL), nil
}

// TokenRequestByRefreshToken: a live token of an enabled user. Presenting a token that was
// already rotated means it leaked (or the client raced itself): the family is revoked.
func (s *Issuer) TokenRequestByRefreshToken(ctx context.Context, token string) (op.RefreshTokenRequest, error) {
	var r refreshRequest
	var family string
	var rotated, revoked, userOK bool
	err := s.db.QueryRow(ctx, `SELECT t.family, t.user_id, t.client_id, t.scopes, t.audience, t.amr, t.auth_time,
			t.rotated_at IS NOT NULL, t.revoked_at IS NOT NULL OR t.expires_at <= now(), u.disabled_at IS NULL AND p.status = 'active'
		FROM idp_refresh_tokens t JOIN idp_users u ON u.id = t.user_id AND u.pool_id = t.pool_id JOIN idp_pools p ON p.id = t.pool_id
		WHERE t.id=$1 AND t.pool_id=$2`, sha256Hex(token), pid(ctx)).
		Scan(&family, &r.userID, &r.clientID, &r.scopes, &r.audience, &r.amr, &r.authTime, &rotated, &revoked, &userOK)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	} else if err != nil {
		return nil, err
	}
	if rotated && !revoked {
		_, _ = s.db.Exec(ctx, `UPDATE idp_refresh_tokens SET revoked_at=now() WHERE family=$1 AND revoked_at IS NULL`, family)
		s.log.Warn("refresh token reuse: family revoked", "user", r.userID)
	}
	if rotated || revoked || !userOK {
		return nil, errNotFound
	}
	return &r, nil
}

func (s *Issuer) TerminateSession(ctx context.Context, userID, clientID string) error {
	_, err := s.db.Exec(ctx, `UPDATE idp_refresh_tokens SET revoked_at=now() WHERE user_id=$1 AND client_id=$2 AND pool_id=$3 AND revoked_at IS NULL`, userID, clientID, pid(ctx))
	return err
}

func (s *Issuer) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	var userID string
	err := s.db.QueryRow(ctx, `SELECT user_id FROM idp_refresh_tokens WHERE id=$1 AND client_id=$2 AND pool_id=$3`, sha256Hex(token), clientID, pid(ctx)).Scan(&userID)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return userID, sha256Hex(token), nil
}

// RevokeToken (/revoke): a refresh token (the library passes our hash id from
// GetRefreshTokenInfo, or the raw token) revokes its family. Access tokens are stateless
// JWTs and can't be revoked (RFC 7009 lets us answer 200 anyway); they expire in AccessTTL.
func (s *Issuer) RevokeToken(ctx context.Context, tokenOrID, _, clientID string) *oidc.Error {
	if _, err := s.db.Exec(ctx, `UPDATE idp_refresh_tokens SET revoked_at=now() WHERE revoked_at IS NULL AND family=
		(SELECT family FROM idp_refresh_tokens WHERE id IN ($1, $2) AND client_id=$3 AND pool_id=$4)`, tokenOrID, sha256Hex(tokenOrID), clientID, pid(ctx)); err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	return nil
}

// ---- keys ----

func (s *Issuer) SigningKey(ctx context.Context) (op.SigningKey, error) {
	k, err := s.keys.signing(ctx, pid(ctx))
	return signingKey{k}, err
}

func (s *Issuer) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.ES256}, nil
}

func (s *Issuer) KeySet(ctx context.Context) ([]op.Key, error) {
	if pid(ctx) == "" {
		return nil, errNotFound
	}
	keys, err := s.keys.live(ctx, pid(ctx), false)
	out := make([]op.Key, len(keys))
	for i, k := range keys {
		out[i] = publicKey{k}
	}
	return out, err
}

// ---- clients ----

// client implements op.Client for every kind: first-party login clients (public, code + PKCE,
// loopback redirects; virtual, per pool kind), federation clients (a tenant pool's confidential
// client at the shop pool, one redirect URI) and machine clients (client_credentials only).
type client struct {
	id         string
	redirects  []string
	appType    op.ApplicationType
	authMethod oidc.AuthMethod
	responses  []oidc.ResponseType
	grants     []oidc.GrantType
	loginURL   string
}

func (c *client) GetID() string                        { return c.id }
func (c *client) RedirectURIs() []string               { return c.redirects }
func (c *client) PostLogoutRedirectURIs() []string     { return nil }
func (c *client) ApplicationType() op.ApplicationType  { return c.appType }
func (c *client) AuthMethod() oidc.AuthMethod          { return c.authMethod }
func (c *client) ResponseTypes() []oidc.ResponseType   { return c.responses }
func (c *client) GrantTypes() []oidc.GrantType         { return c.grants }
func (c *client) LoginURL(id string) string            { return c.loginURL + "?id=" + url.QueryEscape(id) }
func (c *client) AccessTokenType() op.AccessTokenType  { return op.AccessTokenTypeJWT }
func (c *client) IDTokenLifetime() time.Duration       { return idTokenTTL }
func (c *client) DevMode() bool                        { return false }
func (c *client) IsScopeAllowed(string) bool           { return false }
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *client) ClockSkew() time.Duration             { return 0 }
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

func machineClient(id string) *client {
	return &client{id: id, appType: op.ApplicationTypeWeb, authMethod: oidc.AuthMethodBasic,
		grants: []oidc.GrantType{oidc.GrantTypeClientCredentials}}
}

func (s *Issuer) loginClient(p *Pool, id string) *client {
	return &client{
		id: id, redirects: s.cfg.RedirectURIs, appType: op.ApplicationTypeNative,
		authMethod: oidc.AuthMethodNone, responses: []oidc.ResponseType{oidc.ResponseTypeCode},
		grants: []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}, loginURL: s.issuerFor(p.ID) + loginPath,
	}
}

func (s *Issuer) federationClient(p *Pool, id, redirect string) *client {
	return &client{
		id: id, redirects: []string{redirect}, appType: op.ApplicationTypeWeb, authMethod: oidc.AuthMethodBasic,
		responses: []oidc.ResponseType{oidc.ResponseTypeCode}, grants: []oidc.GrantType{oidc.GrantTypeCode},
		loginURL: s.issuerFor(p.ID) + loginPath,
	}
}

// GetClientByClientID: only clients of the request's pool exist.
func (s *Issuer) GetClientByClientID(ctx context.Context, id string) (op.Client, error) {
	p := poolFrom(ctx)
	if p == nil {
		return nil, errNotFound
	}
	if s.loginGroup(p, id) != "" {
		return s.loginClient(p, id), nil
	}
	var kind string
	var redirect *string
	err := s.db.QueryRow(ctx, `SELECT kind, redirect_uri FROM idp_clients WHERE id=$1 AND pool_id=$2 AND deleted_at IS NULL`, id, p.ID).Scan(&kind, &redirect)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	} else if err != nil {
		return nil, err
	}
	if kind == "federation" && redirect != nil {
		return s.federationClient(p, id, *redirect), nil
	}
	return machineClient(id), nil
}

// checkSecret: secrets are 256-bit random, so SHA-256 is enough (no slow hash). An unknown or
// deleted client, or one of another pool or kind, compares against a zero hash, same work.
func (s *Issuer) checkSecret(ctx context.Context, id, secret, kind string) error {
	want := make([]byte, sha256.Size)
	err := s.db.QueryRow(ctx, `SELECT secret_hash FROM idp_clients WHERE id=$1 AND pool_id=$2 AND kind=$3 AND deleted_at IS NULL`, id, pid(ctx), kind).Scan(&want)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	got := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(got[:], want) != 1 || err != nil {
		return errors.New("invalid client credentials")
	}
	return nil
}

// AuthorizeClientIDSecret: confidential clients at /token for the code grant (federation clients).
func (s *Issuer) AuthorizeClientIDSecret(ctx context.Context, id, secret string) error {
	return s.checkSecret(ctx, id, secret, "federation")
}

// ClientCredentials: machine clients only (federation clients have no client_credentials grant).
func (s *Issuer) ClientCredentials(ctx context.Context, id, secret string) (op.Client, error) {
	if err := s.checkSecret(ctx, id, secret, "machine"); err != nil {
		return nil, err
	}
	return machineClient(id), nil
}

func (s *Issuer) ClientCredentialsTokenRequest(_ context.Context, id string, _ []string) (op.TokenRequest, error) {
	return &clientTokenRequest{sub: id, aud: []string{s.cfg.Audience}}, nil
}

// ---- claims, userinfo, and what we don't offer ----

// GetPrivateClaimsFromScopes runs for access tokens only (not ID tokens). The library
// stamps typ "JWT" on both and gives both our audience, so this claim is how the verifier
// tells them apart (RFC 9068's typ at+jwt isn't available).
func (s *Issuer) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return map[string]any{"token_use": "access"}, nil
}

// SetUserinfoFromScopes: the library copies this UserInfo over the ID token's claims
// (claims.SetUserInfo), subject included. Left empty, every ID token goes out with no `sub`
// (stack h had that bug unnoticed: nothing read its ID tokens; Sign in with Shop does).
func (s *Issuer) SetUserinfoFromScopes(_ context.Context, ui *oidc.UserInfo, userID, _ string, _ []string) error {
	ui.Subject = userID
	return nil
}

func (s *Issuer) SetUserinfoFromToken(ctx context.Context, ui *oidc.UserInfo, _, subject, _ string) error {
	ui.Subject = subject
	var email *string
	err := s.db.QueryRow(ctx, `SELECT email FROM idp_users WHERE id=$1 AND pool_id=$2 AND disabled_at IS NULL`, subject, pid(ctx)).Scan(&email)
	if email != nil {
		ui.Email = *email
	}
	return err
}

// Not offered: introspection (tokens are JWTs the app verifies in-process), and the JWT
// bearer grant (RFC 7523), which the library advertises and routes unconditionally; with
// no keys returned here it can never succeed.
func (s *Issuer) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return errors.New("introspection not offered")
}
func (s *Issuer) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("jwt bearer grant not offered")
}
func (s *Issuer) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("jwt bearer grant not offered")
}

func (s *Issuer) Health(ctx context.Context) error { return s.db.Ping(ctx) }

var (
	_ op.Storage                  = (*Issuer)(nil)
	_ op.ClientCredentialsStorage = (*Issuer)(nil)
)

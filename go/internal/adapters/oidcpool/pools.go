package oidcpool

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
)

// Pools (SPEC §16.1). Each pool is an issuer at PUBLIC_URL/oidc/<pool id>: a path segment on the
// app's one host, so one TLS name serves every issuer, discovery works per pool
// (/oidc/<pool>/.well-known/openid-configuration), and the issuer string never comes from Host or
// X-Forwarded-* headers. The pool is resolved from that path against the directory (idp_pools) on
// the issuer side, and from the token's `iss` (exact match, then the directory) on the API side.

const (
	kindWorkforce = "workforce"
	kindPlatform  = "platform"
	kindShop      = "shop"
	kindTenant    = "tenant"

	groupDefault   = "default"   // workforce, platform, shop
	groupStaff     = "staff"     // a tenant pool's staff
	groupCustomers = "customers" // a tenant pool's customers

	dirTTL = 30 * time.Second
)

// Pool is a directory entry. Status is advisory in the cache: login, refresh and Sign in with
// Shop re-read it from the DB.
type Pool struct {
	ID, Kind, MerchantID, Status string
	UpstreamClientID             string
	upstreamSecretEnc            []byte
}

type poolCtxKey struct{}

func withPool(ctx context.Context, p *Pool) context.Context {
	return context.WithValue(ctx, poolCtxKey{}, p)
}

func poolFrom(ctx context.Context) *Pool {
	p, _ := ctx.Value(poolCtxKey{}).(*Pool)
	return p
}

// directory caches idp_pools by id. A miss reads the DB (a pool created a moment ago on another
// instance is found at once); entries expire after dirTTL.
type directory struct {
	db *pgxpool.Pool
	mu sync.Mutex
	m  map[string]dirEntry
}

type dirEntry struct {
	p  *Pool
	at time.Time
}

const poolCols = `id, kind, coalesce(merchant_id,''), status, coalesce(upstream_client_id,''), upstream_secret_enc`

func scanPool(row pgx.Row) (*Pool, error) {
	p := &Pool{}
	err := row.Scan(&p.ID, &p.Kind, &p.MerchantID, &p.Status, &p.UpstreamClientID, &p.upstreamSecretEnc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	return p, err
}

// validPoolID: the path segment's shape, checked before any DB read.
func validPoolID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (d *directory) get(ctx context.Context, id string) (*Pool, error) {
	if !validPoolID(id) {
		return nil, errNotFound
	}
	d.mu.Lock()
	e, ok := d.m[id]
	d.mu.Unlock()
	if ok && time.Since(e.at) < dirTTL {
		return e.p, nil
	}
	p, err := scanPool(d.db.QueryRow(ctx, `SELECT `+poolCols+` FROM idp_pools WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.m[id] = dirEntry{p, time.Now()}
	d.mu.Unlock()
	return p, nil
}

func (d *directory) forget(id string) {
	d.mu.Lock()
	delete(d.m, id)
	d.mu.Unlock()
}

// status reads a pool's status fresh (suspension takes effect on the next login on every instance).
func (s *Issuer) poolActive(ctx context.Context, id string) bool {
	var st string
	err := s.db.QueryRow(ctx, `SELECT status FROM idp_pools WHERE id=$1`, id).Scan(&st)
	return err == nil && st == "active"
}

func (s *Issuer) issuerFor(poolID string) string { return s.cfg.PublicURL + "/oidc/" + poolID }

// poolForKind: where CreateUser puts the core principal kinds (SPEC §16.1 core mapping).
func poolForKind(kind string) (string, error) {
	switch kind {
	case "platform":
		return kindWorkforce, nil
	case "user":
		return kindPlatform, nil
	case "customer":
		return kindShop, nil
	}
	return "", errors.New("oidcpool: unknown kind " + kind)
}

// qualify: the identity port's subject is unique across pools ("<pool>:<sub>"), so a token is
// only ever mapped to a principal of the pool that issued it.
func qualify(poolID, sub string) string { return poolID + ":" + sub }

// ---- tenant pools (identity.TenantPools) ----

// ProvisionMerchant creates the merchant's tenant pool in the caller's transaction (SPEC §16.3):
// the pool row, its first signing key, and its federation client at the shop pool with the
// client's secret kept (encrypted) on the pool. Rolled back with the merchant; nothing outside the DB,
// so the pool is ready at commit.
func (s *Issuer) ProvisionMerchant(ctx context.Context, merchantID string) (bool, error) {
	return true, s.provisionMerchant(ctx, merchantID)
}

func (s *Issuer) provisionMerchant(ctx context.Context, merchantID string) error {
	q := db.TxOr(ctx, s.db)
	id, fedID, secret := db.NewID("pl"), db.NewID("fed"), randToken()
	h := sha256.Sum256([]byte(secret))
	if _, err := q.Exec(ctx, `INSERT INTO idp_pools(id, kind, merchant_id, upstream_client_id, upstream_secret_enc) VALUES ($1,'tenant',$2,$3,$4)`,
		id, merchantID, fedID, s.keys.seal([]byte(secret), "upstream:"+id)); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `INSERT INTO idp_clients(id, pool_id, kind, name, merchant_id, secret_hash, redirect_uri) VALUES ($1,'shop','federation',$2,$3,$4,$5)`,
		fedID, "Sign in with Shop for "+id, merchantID, h[:], s.issuerFor(id)+fedCallbackPath); err != nil {
		return err
	}
	return s.keys.insert(ctx, q, id, time.Now())
}

// SetMerchantSuspended: a suspended merchant's tenant pool refuses logins, Sign in with Shop and
// refreshes (SPEC §16.6 rule 8). In the caller's transaction, with the merchant's status.
func (s *Issuer) SetMerchantSuspended(ctx context.Context, merchantID string, suspended bool) error {
	st := "active"
	if suspended {
		st = "suspended"
	}
	var id string
	err := db.TxOr(ctx, s.db).QueryRow(ctx, `UPDATE idp_pools SET status=$2 WHERE merchant_id=$1 RETURNING id`, merchantID, st).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // a merchant created before pools existed
	}
	if err == nil {
		s.dir.forget(id)
	}
	return err
}

// PoolIdentity: the tenant issuer a storefront or admin UI starts a login at (SPEC §16.3).
func (s *Issuer) PoolIdentity(ctx context.Context, merchantID string) (map[string]any, error) {
	var id string
	err := db.TxOr(ctx, s.db).QueryRow(ctx, `SELECT id FROM idp_pools WHERE merchant_id=$1`, merchantID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, identity.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return map[string]any{"issuer": s.issuerFor(id)}, nil
}

// CreateTenantUser: a password identity in the merchant's tenant pool, staff (kind user) or
// customers (kind customer), in the caller's transaction (SPEC §16.4).
func (s *Issuer) CreateTenantUser(ctx context.Context, merchantID, email, password, kind string) (string, error) {
	group := map[string]string{"user": groupStaff, "customer": groupCustomers}[kind]
	if group == "" {
		return "", errors.New("oidcpool: tenant users are user or customer")
	}
	q := db.TxOr(ctx, s.db)
	var poolID string
	if err := q.QueryRow(ctx, `SELECT id FROM idp_pools WHERE merchant_id=$1`, merchantID).Scan(&poolID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", identity.ErrNotFound
		}
		return "", err
	}
	id := db.NewID("idu")
	if _, err := q.Exec(ctx, `INSERT INTO idp_users(id, pool_id, user_group, email, password_hash) VALUES ($1,$2,$3,$4,$5)`,
		id, poolID, group, normEmail(email), hashPassword(password)); err != nil {
		return "", err
	}
	return qualify(poolID, id), nil
}

// ---- HTTP: /oidc/<pool>/... ----

const (
	loginPath       = "/login"
	shopLoginPath   = "/login/shop"
	fedCallbackPath = "/federation/shop/callback"
)

// route serves every pool under /oidc/<pool>/: the pool comes from the path, looked up in the
// directory (unknown → 404); the provider sees the rest of the path with the pool in ctx, and
// derives the issuer from that pool, never from the request's host.
func (s *Issuer) route(w http.ResponseWriter, r *http.Request) {
	// Encoded paths are refused: the pool segment and the library's routes must mean the same
	// thing to us and to the router (review-g encoded-path gate).
	if r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/oidc/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	id, sub, _ := strings.Cut(rest, "/")
	p, err := s.dir.get(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx := op.ContextWithIssuer(withPool(r.Context(), p), s.issuerFor(p.ID))
	r = r.WithContext(ctx)
	switch "/" + sub {
	case loginPath:
		s.handleLogin(w, r)
		return
	case shopLoginPath:
		s.fedStart(w, r)
		return
	case fedCallbackPath:
		s.fedCallback(w, r)
		return
	}
	r2 := r.Clone(ctx)
	r2.URL.Path = "/" + sub
	s.limitToken(s.provider).ServeHTTP(w, r2)
}

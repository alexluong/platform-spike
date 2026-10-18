package zitadel

// Instance-per-merchant mode (IDP=zitadel-instances, stack i, SPEC §16).
//
// One Zitadel deployment, many instances (rows in one Postgres):
//   - workforce: the first instance (org "staff"): platform staff.
//   - platform:  orgs "accounts" (merchant owners, partners; also the apps' and agents'
//                machine users) and "shop" (Shop buyers).
//   - one instance per merchant, created when the merchant is (outbox event merchant.created,
//     background consumer): orgs "staff" and "customers", a login project/app, and a generic
//     OIDC IdP "Shop" on "customers" pointing at the platform instance (Sign in with Shop),
//     with a matching OIDC app per merchant in the platform instance.
//
// The app is the gateway: each pool has a public host <label>.<ID_DOMAIN>:<ID_PORT>, which is
// also its issuer (http://<public host>). The gateway (gateway.go) maps the host to the pool's
// instance domain from the directory (table zitadel_pools) and forwards to Zitadel with
// x-zitadel-instance-host (which instance) and x-zitadel-public-host (issuer, URLs); Zitadel
// accepts the public host because it is a trusted domain of that instance. The app's own calls
// go straight to Zitadel's internal URL with the same headers, authenticated as system API
// users (system.go). Tokens from every pool are verified against that pool's keys (verify.go).

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema/*.sql
var schemaFS embed.FS

// MigrateInstances creates the directory table (bootstrap).
func MigrateInstances(ctx context.Context, pool *pgxpool.Pool) error {
	return db.MigrateFS(ctx, pool, schemaFS, "schema/*.sql")
}

// Pool keys.
const (
	PoolWorkforce = "workforce"
	PoolPlatform  = "platform"
)

// MerchantPool is the directory key of a merchant's pool.
func MerchantPool(merchantID string) string { return "m:" + merchantID }

// InstancesConfig is read from env by the composition roots.
type InstancesConfig struct {
	ZitadelURL     string // internal, e.g. http://i-zitadel:8080
	ExternalDomain string // Zitadel's ExternalDomain = the workforce instance's domain
	ExternalOrigin string // http://<ExternalDomain>:<ExternalPort>: audience of system API tokens
	KeysDir        string
	IDDomain       string // public pool hosts are <label>.<IDDomain>:<IDPort>
	IDPort         string
	RedirectURI    string // the login driver's redirect URI (registered on every login app)
}

// Pool is one directory row.
type Pool struct {
	Key            string
	MerchantID     string
	Label          string
	InstanceDomain string
	PublicHost     string
	Issuer         string
	InstanceID     string
	Orgs           map[string]string
	ProjectID      string
	ClientID       string
	ShopIdPID      string
	Status         string // provisioning | active
	Blocked        bool
}

// Instances implements identity.Verifier, identity.Provisioner, identity.Pools, the outbox
// consumers for pool lifecycle (provision, block/unblock), and the gateway.
type Instances struct {
	cfg InstancesConfig
	z   *Zitadel
	db  *pgxpool.Pool
	log *slog.Logger

	// OnReady: the merchant's pool is active (composition root: platform.MarkPoolReady).
	OnReady func(ctx context.Context, merchantID string) error
	// OnShopLink: a merchant-pool identity signed in with a Shop account (composition root:
	// customers.LinkShop). Subjects are the app-side (pool-qualified) ones.
	OnShopLink func(ctx context.Context, merchantID, shopSubject, tenantSubject string) error

	mu      sync.RWMutex
	byKey   map[string]*Pool
	byIss   map[string]*Pool
	byLabel map[string]*Pool
	keys    map[string]*keySet // per pool key
}

func NewInstances(cfg InstancesConfig, pool *pgxpool.Pool, log *slog.Logger) (*Instances, error) {
	z, err := NewZitadel(cfg.ZitadelURL, cfg.ExternalDomain, cfg.ExternalOrigin, cfg.KeysDir)
	if err != nil {
		return nil, err
	}
	return &Instances{cfg: cfg, z: z, db: pool, log: log,
		byKey: map[string]*Pool{}, byIss: map[string]*Pool{}, byLabel: map[string]*Pool{}, keys: map[string]*keySet{}}, nil
}

// naming

func (x *Instances) label(key string) string {
	if mid, ok := strings.CutPrefix(key, "m:"); ok {
		return "m-" + strings.ReplaceAll(strings.TrimPrefix(mid, "m_"), "_", "-")
	}
	return key
}

func (x *Instances) newPool(key, merchantID string) *Pool {
	l := x.label(key)
	host := l + "." + x.cfg.IDDomain + ":" + x.cfg.IDPort
	dom := l + ".zitadel.internal"
	if key == PoolWorkforce {
		dom = x.cfg.ExternalDomain
	}
	return &Pool{Key: key, MerchantID: merchantID, Label: l, InstanceDomain: dom, PublicHost: host,
		Issuer: "http://" + host, Orgs: map[string]string{}, Status: "provisioning"}
}

func (p *Pool) at() At { return At{InstanceHost: p.InstanceDomain, PublicHost: p.PublicHost} }

// trustedDomain: Zitadel compares the public host's hostname (no port) with the instance's
// trusted domains.
func (p *Pool) trustedDomain() string { h, _, _ := strings.Cut(p.PublicHost, ":"); return h }

// directory

const poolCols = `pool, coalesce(merchant_id,''), label, instance_domain, public_host, issuer, coalesce(instance_id,''),
	orgs, coalesce(project_id,''), coalesce(client_id,''), coalesce(shop_idp_id,''), status, blocked`

func scanPool(row pgx.Row) (*Pool, error) {
	var p Pool
	var orgs []byte
	if err := row.Scan(&p.Key, &p.MerchantID, &p.Label, &p.InstanceDomain, &p.PublicHost, &p.Issuer, &p.InstanceID,
		&orgs, &p.ProjectID, &p.ClientID, &p.ShopIdPID, &p.Status, &p.Blocked); err != nil {
		return nil, err
	}
	p.Orgs = map[string]string{}
	_ = json.Unmarshal(orgs, &p.Orgs)
	return &p, nil
}

func (x *Instances) loadPool(ctx context.Context, where string, arg any) (*Pool, error) {
	p, err := scanPool(x.db.QueryRow(ctx, `SELECT `+poolCols+` FROM zitadel_pools WHERE `+where, arg))
	if err != nil {
		return nil, err
	}
	if p.Status == "active" { // only active pools are cached: their routing data no longer changes
		x.mu.Lock()
		x.byKey[p.Key], x.byIss[p.Issuer], x.byLabel[p.Label] = p, p, p
		x.mu.Unlock()
	}
	return p, nil
}

// PoolByKey / ByIssuer / ByLabel: the directory, cached in memory (active pools), read from the
// DB on a miss. Blocked state is not cached: Zitadel enforces it.
func (x *Instances) PoolByKey(ctx context.Context, key string) (*Pool, error) {
	x.mu.RLock()
	p := x.byKey[key]
	x.mu.RUnlock()
	if p != nil {
		return p, nil
	}
	return x.loadPool(ctx, "pool=$1", key)
}

func (x *Instances) poolByIssuer(ctx context.Context, iss string) (*Pool, error) {
	x.mu.RLock()
	p := x.byIss[iss]
	x.mu.RUnlock()
	if p != nil {
		return p, nil
	}
	return x.loadPool(ctx, "issuer=$1", iss)
}

func (x *Instances) poolByLabel(ctx context.Context, label string) (*Pool, error) {
	x.mu.RLock()
	p := x.byLabel[label]
	x.mu.RUnlock()
	if p != nil {
		return p, nil
	}
	return x.loadPool(ctx, "label=$1", label)
}

func (x *Instances) ensureRow(ctx context.Context, p *Pool) error {
	_, err := x.db.Exec(ctx, `INSERT INTO zitadel_pools(pool, merchant_id, label, instance_domain, public_host, issuer)
		VALUES ($1, nullif($2,''), $3, $4, $5, $6) ON CONFLICT (pool) DO NOTHING`,
		p.Key, p.MerchantID, p.Label, p.InstanceDomain, p.PublicHost, p.Issuer)
	return err
}

func (x *Instances) save(ctx context.Context, p *Pool) error {
	orgs, _ := json.Marshal(p.Orgs)
	_, err := x.db.Exec(ctx, `UPDATE zitadel_pools SET instance_id=nullif($2,''), orgs=$3, project_id=nullif($4,''),
		client_id=nullif($5,''), shop_idp_id=nullif($6,'') WHERE pool=$1`,
		p.Key, p.InstanceID, orgs, p.ProjectID, p.ClientID, p.ShopIdPID)
	return err
}

// provisioning

// CreateInstance (system API), idempotent by domain. Returns the instance id.
func (x *Instances) createInstance(ctx context.Context, p *Pool, firstOrg string) (string, error) {
	sys := At{InstanceHost: x.z.SystemHost}
	var found struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := x.z.Call(ctx, x.z.Provisioner, sys, "POST", "/system/v1/instances/_search",
		map[string]any{"queries": []any{map[string]any{"domainQuery": map[string]any{"domains": []string{p.InstanceDomain}}}}}, &found); err != nil {
		return "", err
	}
	if len(found.Result) > 0 {
		return found.Result[0].ID, nil
	}
	var out struct {
		InstanceID string `json:"instanceId"`
	}
	err := x.z.Call(ctx, x.z.Provisioner, sys, "POST", "/system/v1/instances/_create", map[string]any{
		"instanceName": p.Label, "firstOrgName": firstOrg, "customDomain": p.InstanceDomain,
		// The owner oneof is required; the app never uses this machine user (the system users
		// act on every instance).
		"machine": map[string]any{"userName": "owner", "name": "owner"},
	}, &out)
	return out.InstanceID, err
}

// waitInstance polls until the new instance answers on its domain (projection lag) and returns
// its default (first) org id.
func (x *Instances) waitInstance(ctx context.Context, p *Pool) (string, error) {
	var last error
	for i := 0; i < 300; i++ {
		var o struct {
			Org struct {
				ID string `json:"id"`
			} `json:"org"`
		}
		last = x.z.Call(ctx, x.z.Provisioner, At{InstanceHost: p.InstanceDomain}, "GET", "/admin/v1/orgs/default", nil, &o)
		if last == nil && o.Org.ID != "" {
			return o.Org.ID, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("instance %s not answering: %w", p.InstanceDomain, last)
}

func (x *Instances) addTrustedDomain(ctx context.Context, p *Pool) error {
	err := x.z.Call(ctx, x.z.Provisioner, At{InstanceHost: p.InstanceDomain}, "POST", "/admin/v1/trusted_domains",
		map[string]any{"domain": p.trustedDomain()}, nil)
	if err != nil && !isCode(err, "already_exists") && !strings.Contains(err.Error(), "AlreadyExists") {
		return err
	}
	return nil
}

func (x *Instances) ensureOrg(ctx context.Context, p *Pool, name string) (string, error) {
	if id := p.Orgs[name]; id != "" {
		return id, nil
	}
	at := At{InstanceHost: p.InstanceDomain}
	var found struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := x.z.Call(ctx, x.z.Provisioner, at, "POST", "/admin/v1/orgs/_search",
		map[string]any{"queries": []any{map[string]any{"nameQuery": map[string]any{"name": name, "method": "TEXT_QUERY_METHOD_EQUALS"}}}}, &found); err != nil {
		return "", err
	}
	if len(found.Result) > 0 {
		return found.Result[0].ID, nil
	}
	var out struct {
		OrganizationID string `json:"organizationId"`
	}
	err := x.z.Call(ctx, x.z.Provisioner, at, "POST", "/zitadel.org.v2.OrganizationService/AddOrganization", map[string]any{"name": name}, &out)
	return out.OrganizationID, err
}

// mgmt calls the v1 management API in an org of the pool's instance.
func (x *Instances) mgmt(ctx context.Context, p *Pool, orgID, method, path string, body, out any) error {
	return x.z.callOrg(ctx, x.z.Provisioner, At{InstanceHost: p.InstanceDomain}, orgID, method, path, body, out)
}

func nameQuery(name string) map[string]any {
	return map[string]any{"queries": []any{map[string]any{"nameQuery": map[string]any{"name": name, "method": "TEXT_QUERY_METHOD_EQUALS"}}}}
}

func (x *Instances) ensureProject(ctx context.Context, p *Pool, orgID, name string) (string, error) {
	var found struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := x.mgmt(ctx, p, orgID, "POST", "/management/v1/projects/_search", nameQuery(name), &found); err != nil {
		return "", err
	}
	if len(found.Result) > 0 {
		return found.Result[0].ID, nil
	}
	var out struct {
		ID string `json:"id"`
	}
	err := x.mgmt(ctx, p, orgID, "POST", "/management/v1/projects", map[string]any{"name": name}, &out)
	return out.ID, err
}

type oidcApp struct {
	ID, ClientID, ClientSecret string
}

// ensureOIDCApp finds the app by name or creates it. confidential: client secret (BASIC);
// a found app gets a new secret (the old one is not stored anywhere).
func (x *Instances) ensureOIDCApp(ctx context.Context, p *Pool, orgID, projectID, name string, redirect string, confidential bool) (oidcApp, error) {
	var found struct {
		Result []struct {
			ID         string `json:"id"`
			OIDCConfig struct {
				ClientID string `json:"clientId"`
			} `json:"oidcConfig"`
		} `json:"result"`
	}
	if err := x.mgmt(ctx, p, orgID, "POST", "/management/v1/projects/"+projectID+"/apps/_search", nameQuery(name), &found); err != nil {
		return oidcApp{}, err
	}
	if len(found.Result) > 0 {
		a := oidcApp{ID: found.Result[0].ID, ClientID: found.Result[0].OIDCConfig.ClientID}
		if confidential {
			var s struct {
				ClientSecret string `json:"clientSecret"`
			}
			if err := x.mgmt(ctx, p, orgID, "POST", "/management/v1/projects/"+projectID+"/apps/"+a.ID+"/oidc_config/_generate_client_secret", map[string]any{}, &s); err != nil {
				return oidcApp{}, err
			}
			a.ClientSecret = s.ClientSecret
		}
		return a, nil
	}
	body := map[string]any{
		"name":            name,
		"redirectUris":    []string{redirect},
		"responseTypes":   []string{"OIDC_RESPONSE_TYPE_CODE"},
		"grantTypes":      []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE"},
		"accessTokenType": "OIDC_TOKEN_TYPE_JWT",
		"devMode":         true, // http redirect URIs (dev)
		"version":         "OIDC_VERSION_1_0",
	}
	if confidential {
		body["appType"], body["authMethodType"] = "OIDC_APP_TYPE_WEB", "OIDC_AUTH_METHOD_TYPE_BASIC"
		body["idTokenUserinfoAssertion"] = true // profile + email in the ID token (the IdP maps it)
	} else {
		body["appType"], body["authMethodType"] = "OIDC_APP_TYPE_USER_AGENT", "OIDC_AUTH_METHOD_TYPE_NONE" // PKCE
	}
	var out struct {
		AppID        string `json:"appId"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	err := x.mgmt(ctx, p, orgID, "POST", "/management/v1/projects/"+projectID+"/apps/oidc", body, &out)
	return oidcApp{ID: out.AppID, ClientID: out.ClientID, ClientSecret: out.ClientSecret}, err
}

// ensureLogin: the pool's login project and PKCE app (what a login UI / storefront holds).
func (x *Instances) ensureLogin(ctx context.Context, p *Pool, orgID string) error {
	if p.ClientID != "" {
		return nil
	}
	pid, err := x.ensureProject(ctx, p, orgID, "login")
	if err != nil {
		return err
	}
	app, err := x.ensureOIDCApp(ctx, p, orgID, pid, "login", x.cfg.RedirectURI, false)
	if err != nil {
		return err
	}
	p.ProjectID, p.ClientID = pid, app.ClientID
	return nil
}

// BootstrapInstances provisions the workforce and platform pools (idempotent).
func (x *Instances) BootstrapInstances(ctx context.Context) error {
	// workforce: the first instance, created by Zitadel's setup (first org "staff").
	w := x.newPool(PoolWorkforce, "")
	if err := x.ensureRow(ctx, w); err != nil {
		return err
	}
	w, err := x.PoolByKey(ctx, PoolWorkforce)
	if err != nil {
		return err
	}
	if w.Orgs["staff"] == "" {
		if w.Orgs["staff"], err = x.waitInstance(ctx, w); err != nil {
			return err
		}
	}
	if err := x.addTrustedDomain(ctx, w); err != nil {
		return err
	}
	if err := x.ensureLogin(ctx, w, w.Orgs["staff"]); err != nil {
		return err
	}
	if err := x.save(ctx, w); err != nil {
		return err
	}
	if err := x.markActive(ctx, w); err != nil {
		return err
	}

	// platform: orgs accounts (first) and shop.
	p := x.newPool(PoolPlatform, "")
	if err := x.ensureRow(ctx, p); err != nil {
		return err
	}
	if p, err = x.PoolByKey(ctx, PoolPlatform); err != nil {
		return err
	}
	if p.InstanceID == "" {
		if p.InstanceID, err = x.createInstance(ctx, p, "accounts"); err != nil {
			return err
		}
		if err := x.save(ctx, p); err != nil {
			return err
		}
	}
	if p.Orgs["accounts"] == "" {
		if p.Orgs["accounts"], err = x.waitInstance(ctx, p); err != nil {
			return err
		}
	}
	if p.Orgs["shop"], err = x.ensureOrg(ctx, p, "shop"); err != nil {
		return err
	}
	if err := x.addTrustedDomain(ctx, p); err != nil {
		return err
	}
	if err := x.ensureLogin(ctx, p, p.Orgs["accounts"]); err != nil {
		return err
	}
	if err := x.save(ctx, p); err != nil {
		return err
	}
	return x.markActive(ctx, p)
}

func (x *Instances) markActive(ctx context.Context, p *Pool) error {
	_, err := x.db.Exec(ctx, `UPDATE zitadel_pools SET status='active', ready_at=coalesce(ready_at, now()) WHERE pool=$1`, p.Key)
	return err
}

// provisionMerchant creates the merchant's instance from the template, step by step. Every
// step is idempotent and its result is saved, so a retry (the outbox relay retries a failed
// row forever) continues where the last attempt stopped.
func (x *Instances) provisionMerchant(ctx context.Context, mid string) error {
	key := MerchantPool(mid)
	if err := x.ensureRow(ctx, x.newPool(key, mid)); err != nil {
		return err
	}
	p, err := x.PoolByKey(ctx, key)
	if err != nil {
		return err
	}
	if p.Status == "active" {
		return nil
	}
	plat, err := x.PoolByKey(ctx, PoolPlatform)
	if err != nil {
		return err
	}
	if p.InstanceID == "" {
		if p.InstanceID, err = x.createInstance(ctx, p, "staff"); err != nil {
			return fmt.Errorf("create instance: %w", err)
		}
		if err := x.save(ctx, p); err != nil {
			return err
		}
	}
	if p.Orgs["staff"] == "" {
		if p.Orgs["staff"], err = x.waitInstance(ctx, p); err != nil {
			return err
		}
	}
	if p.Orgs["customers"], err = x.ensureOrg(ctx, p, "customers"); err != nil {
		return fmt.Errorf("customers org: %w", err)
	}
	if err := x.save(ctx, p); err != nil {
		return err
	}
	if err := x.addTrustedDomain(ctx, p); err != nil {
		return fmt.Errorf("trusted domain: %w", err)
	}
	if err := x.ensureLogin(ctx, p, p.Orgs["staff"]); err != nil {
		return fmt.Errorf("login app: %w", err)
	}
	if err := x.save(ctx, p); err != nil {
		return err
	}
	if p.ShopIdPID == "" {
		// The Shop side: an OIDC app in the platform instance for this merchant (its redirect
		// is this merchant's IdP callback), then the generic OIDC IdP on "customers".
		fed, err := x.ensureProject(ctx, plat, plat.Orgs["shop"], "shop-federation")
		if err != nil {
			return fmt.Errorf("shop project: %w", err)
		}
		app, err := x.ensureOIDCApp(ctx, plat, plat.Orgs["shop"], fed, "shop-"+p.Label, "http://"+p.PublicHost+"/idps/callback", true)
		if err != nil {
			return fmt.Errorf("shop app: %w", err)
		}
		var idp struct {
			ID string `json:"id"`
		}
		if err := x.mgmt(ctx, p, p.Orgs["customers"], "POST", "/management/v1/idps/generic_oidc", map[string]any{
			"name": "Shop", "issuer": plat.Issuer, "clientId": app.ClientID, "clientSecret": app.ClientSecret,
			// The org scope restricts the upstream login to Shop buyers (Zitadel refuses to link
			// a session of another org to the auth request).
			"scopes":           []string{"openid", "profile", "email", "urn:zitadel:iam:org:id:" + plat.Orgs["shop"]},
			"isIdTokenMapping": true,
			"providerOptions":  map[string]any{"isLinkingAllowed": true, "isCreationAllowed": true, "isAutoCreation": false, "isAutoUpdate": true},
		}, &idp); err != nil {
			return fmt.Errorf("shop idp: %w", err)
		}
		p.ShopIdPID = idp.ID
		if err := x.save(ctx, p); err != nil {
			return err
		}
	}
	// Last: apply the merchant's desired block state (it may have been suspended meanwhile)
	// under the row lock that suspend/reinstate take too, then go active.
	tx, err := x.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var blocked bool
	if err := tx.QueryRow(ctx, `SELECT blocked FROM zitadel_pools WHERE pool=$1 FOR UPDATE`, key).Scan(&blocked); err != nil {
		return err
	}
	if blocked {
		if err := x.setBlocked(ctx, p, true); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE zitadel_pools SET status='active', ready_at=now() WHERE pool=$1`, key); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if x.OnReady != nil {
		return x.OnReady(ctx, mid)
	}
	return nil
}

// setBlocked: SetLimits block. A blocked instance refuses every request except the system
// API: logins, token requests, JWKS. Already-issued tokens still verify with cached keys.
func (x *Instances) setBlocked(ctx context.Context, p *Pool, block bool) error {
	return x.z.Call(ctx, x.z.Provisioner, At{InstanceHost: x.z.SystemHost}, "PUT", "/system/v1/instances/"+p.InstanceID+"/limits",
		map[string]any{"block": block}, nil)
}

// blockMerchant (suspend/reinstate): record the desired state; apply it now if the instance
// exists (else provisioning applies it at the end).
func (x *Instances) blockMerchant(ctx context.Context, mid string, block bool) error {
	tx, err := x.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	p, err := scanPool(tx.QueryRow(ctx, `UPDATE zitadel_pools SET blocked=$2 WHERE pool=$1 RETURNING `+poolCols, MerchantPool(mid), block))
	if errors.Is(err, pgx.ErrNoRows) {
		// No row yet: provisioning hasn't started. Create it with the desired state.
		np := x.newPool(MerchantPool(mid), mid)
		if _, err := tx.Exec(ctx, `INSERT INTO zitadel_pools(pool, merchant_id, label, instance_domain, public_host, issuer, blocked)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (pool) DO UPDATE SET blocked=excluded.blocked`,
			np.Key, mid, np.Label, np.InstanceDomain, np.PublicHost, np.Issuer, block); err != nil {
			return err
		}
		return tx.Commit(ctx)
	} else if err != nil {
		return err
	}
	if p.Status == "active" {
		if err := x.setBlocked(ctx, p, block); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// PoolEvents: what the provisioning consumer takes (background: provisioning takes seconds).
func PoolEvents(t string) bool { return t == authz.EvMerchantCreated }

// PoolStateEvents: what the pool state consumer takes (drained in the request: when suspend
// answers, the merchant's pool already refuses logins).
func PoolStateEvents(t string) bool {
	return t == authz.EvMerchantSuspended || t == authz.EvMerchantReinstated
}

// Provisioner and PoolState are the two outbox consumers (authz.RelationSync).
func (x *Instances) Provisioner() authz.RelationSync { return syncFunc(x.applyProvision) }
func (x *Instances) PoolState() authz.RelationSync   { return syncFunc(x.applyState) }

type syncFunc func(context.Context, authz.Event) error

func (f syncFunc) Apply(ctx context.Context, ev authz.Event) error { return f(ctx, ev) }

func classify(err error) error {
	var ae *APIError
	if errors.As(err, &ae) && ae.permanent() {
		return fmt.Errorf("%w: %w", authz.ErrPermanent, err)
	}
	return err
}

func (x *Instances) applyProvision(ctx context.Context, ev authz.Event) error {
	if ev.Type != authz.EvMerchantCreated {
		return nil
	}
	t := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := x.provisionMerchant(ctx, ev.MerchantID); err != nil {
		x.log.Warn("provision merchant pool", "merchant", ev.MerchantID, "err", err)
		return classify(err)
	}
	x.log.Info("merchant pool provisioned", "merchant", ev.MerchantID, "took", time.Since(t))
	return nil
}

func (x *Instances) applyState(ctx context.Context, ev authz.Event) error {
	switch ev.Type {
	case authz.EvMerchantSuspended:
		return classify(x.blockMerchant(ctx, ev.MerchantID, true))
	case authz.EvMerchantReinstated:
		return classify(x.blockMerchant(ctx, ev.MerchantID, false))
	}
	return nil
}

// identity port

// subject: the app-side subject, qualified by pool (Zitadel ids are per deployment, but a
// subject is only meaningful with its issuer).
func subject(pool, sub string) string { return pool + "|" + sub }

func (x *Instances) createHuman(ctx context.Context, p *Pool, org, username, email, password string) (string, error) {
	var out struct {
		UserID string `json:"userId"`
	}
	err := x.z.Call(ctx, x.z.Provisioner, At{InstanceHost: p.InstanceDomain}, "POST", "/v2/users/human", map[string]any{
		"username":     username,
		"organization": map[string]any{"orgId": org},
		"profile":      map[string]any{"givenName": "Test", "familyName": "User"},
		"email":        map[string]any{"email": email, "isVerified": true},
		"password":     map[string]any{"password": password, "changeRequired": false},
	}, &out)
	return out.UserID, err
}

// CreateUser: platform-level identities (SPEC §16.1 core mapping).
func (x *Instances) CreateUser(ctx context.Context, email, password, kind string) (string, error) {
	poolKey, org := PoolPlatform, "accounts"
	switch kind {
	case "platform":
		poolKey, org = PoolWorkforce, "staff"
	case "customer":
		org = "shop"
	}
	p, err := x.PoolByKey(ctx, poolKey)
	if err != nil {
		return "", err
	}
	// Usernames are unique per instance: the platform instance holds accounts and Shop
	// buyers, so the same email can't be both unless the username differs. Prefix the org.
	username := email
	if poolKey == PoolPlatform {
		username = org + "." + email
	}
	id, err := x.createHuman(ctx, p, p.Orgs[org], username, email, password)
	if err != nil {
		return "", err
	}
	return subject(poolKey, id), nil
}

// CreatePoolUser: SPEC §16.4, an identity in the merchant's own instance.
func (x *Instances) CreatePoolUser(ctx context.Context, merchantID, email, password, kind string) (string, error) {
	p, err := x.PoolByKey(ctx, MerchantPool(merchantID))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && p.Status != "active") {
		return "", fmt.Errorf("merchant %s: identity pool not ready", merchantID)
	} else if err != nil {
		return "", err
	}
	org := "staff"
	if kind == "customer" {
		org = "customers"
	}
	id, err := x.createHuman(ctx, p, p.Orgs[org], org+"."+email, email, password)
	if err != nil {
		return "", err
	}
	return subject(p.Key, id), nil
}

// PoolIdentity: what a storefront or admin UI needs to start a login at the merchant's pool
// (GET /api/merchants/:mid/identity).
func (x *Instances) PoolIdentity(ctx context.Context, merchantID string) (map[string]any, error) {
	p, err := x.PoolByKey(ctx, MerchantPool(merchantID))
	if err != nil {
		return nil, err
	}
	return map[string]any{"issuer": p.Issuer, "clientId": p.ClientID, "projectId": p.ProjectID, "orgs": p.Orgs, "status": p.Status}, nil
}

// CreateClient: apps and agents are machine users in the platform instance (org accounts).
// Agents could live in their merchant's instance (suspension would then cut their tokens at the
// IdP too), but then every client_credentials caller needs the merchant's token endpoint.
func (x *Instances) CreateClient(ctx context.Context, name, _ string) (identity.Client, error) {
	p, err := x.PoolByKey(ctx, PoolPlatform)
	if err != nil {
		return identity.Client{}, err
	}
	at := At{InstanceHost: p.InstanceDomain}
	username := name + "-" + randHex(4)
	var user struct {
		ID string `json:"id"`
	}
	if err := x.z.Call(ctx, x.z.Provisioner, at, "POST", "/v2/users/new", map[string]any{
		"organizationId": p.Orgs["accounts"],
		"username":       username,
		"machine":        map[string]any{"name": name, "accessTokenType": "ACCESS_TOKEN_TYPE_JWT"},
	}, &user); err != nil {
		return identity.Client{}, err
	}
	var sec struct {
		ClientSecret string `json:"clientSecret"`
	}
	if err := x.z.Call(ctx, x.z.Provisioner, at, "POST", "/v2/users/"+user.ID+"/secret", map[string]any{}, &sec); err != nil {
		return identity.Client{}, err
	}
	return identity.Client{Subject: subject(PoolPlatform, user.ID), ClientID: username, ClientSecret: sec.ClientSecret}, nil
}

func (x *Instances) DeleteClient(context.Context, string) error { return identity.ErrNotSupported }

// Ping: Zitadel is up.
func (x *Instances) Ping(ctx context.Context) error {
	return x.z.Call(ctx, nil, At{InstanceHost: x.z.SystemHost}, "GET", "/debug/ready", nil, nil)
}

// DriverConfig (TEST_MODE): the platform-level login targets a login UI would hold.
func (x *Instances) DriverConfig() map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := map[string]any{"idp": "zitadel-instances", "redirectUri": x.cfg.RedirectURI}
	for kind, t := range map[string][2]string{"platform": {PoolWorkforce, "staff"}, "user": {PoolPlatform, "accounts"}, "customer": {PoolPlatform, "shop"}} {
		p, err := x.PoolByKey(ctx, t[0])
		if err != nil {
			continue
		}
		out[kind] = map[string]any{"issuer": p.Issuer, "clientId": p.ClientID, "projectId": p.ProjectID, "orgId": p.Orgs[t[1]]}
	}
	return out
}

func (z *Zitadel) callOrg(ctx context.Context, as *sysUser, at At, orgID, method, path string, body, out any) error {
	return z.call(ctx, as, at, map[string]string{"x-zitadel-orgid": orgID}, method, path, body, out)
}

// hostOf: "a.b:8096" from an issuer URL.
func hostOf(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return u.Host
}

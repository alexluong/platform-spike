// Command server is the composition root: config → adapters → modules, by hand.
// Stack a: IDP=zitadel AUTHZ=spicedb. Stack b: IDP=ory AUTHZ=openfga.
// Stack f: IDP=logto AUTHZ=spicedb.
// Stack h: IDP=oidcop AUTHZ=spicedb (the OpenID provider runs inside this server, on the app DB).
// Stack h2: IDP=oidcpool AUTHZ=spicedb (h with pools as rows, one issuer per pool).
// Stack a2: IDP=zitadel-orgs AUTHZ=spicedb (an organization per merchant; the IdP is a
// second outbox consumer).
// Stack i: IDP=zitadel-instances AUTHZ=spicedb (a Zitadel instance per merchant; the app is
// the identity gateway; pool provisioning and block state are outbox consumers).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alexluong/platform-spike/go/internal/adapters/logto"
	"github.com/alexluong/platform-spike/go/internal/adapters/oidcop"
	"github.com/alexluong/platform-spike/go/internal/adapters/oidcpool"
	"github.com/alexluong/platform-spike/go/internal/adapters/openfga"
	"github.com/alexluong/platform-spike/go/internal/adapters/ory"
	"github.com/alexluong/platform-spike/go/internal/adapters/spicedb"
	"github.com/alexluong/platform-spike/go/internal/adapters/zitadel"
	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
	"github.com/alexluong/platform-spike/go/internal/modules/agents"
	"github.com/alexluong/platform-spike/go/internal/modules/apps"
	"github.com/alexluong/platform-spike/go/internal/modules/catalog"
	"github.com/alexluong/platform-spike/go/internal/modules/customers"
	"github.com/alexluong/platform-spike/go/internal/modules/delivery"
	"github.com/alexluong/platform-spike/go/internal/modules/me"
	"github.com/alexluong/platform-spike/go/internal/modules/merchants"
	"github.com/alexluong/platform-spike/go/internal/modules/orders"
	"github.com/alexluong/platform-spike/go/internal/modules/payments"
	"github.com/alexluong/platform-spike/go/internal/modules/platform"
	"github.com/alexluong/platform-spike/go/internal/modules/roles"
	"github.com/alexluong/platform-spike/go/internal/modules/stores"
	"github.com/alexluong/platform-spike/go/internal/modules/testsupport"
	"github.com/alexluong/platform-spike/go/internal/outbox"
	"github.com/jackc/pgx/v5/pgxpool"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type pinger interface{ Ping(context.Context) error }

// idp is what the app needs from an identity adapter.
type idp interface {
	identity.Verifier
	identity.Provisioner
	pinger
	DriverConfig() map[string]any
}

// engine is what the app needs from an authz adapter.
type engine interface {
	authz.Authorizer
	authz.RelationSync
	pinger
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, env("DATABASE_URL", "postgres://app:app@localhost:5432/app"))
	if err != nil {
		return err
	}
	defer pool.Close()

	var id idp
	var idSync *outbox.Relay // identity sync: IdPs that own tenancy consume the outbox too
	var extraRelays outbox.Relays
	var gateway func(http.Handler) http.Handler // stack i: identity hosts in front of the API
	switch env("IDP", "zitadel") {
	case "zitadel-instances":
		x, err := zitadel.NewInstances(instancesConfig(), pool, log)
		if err != nil {
			return err
		}
		x.OnReady = func(ctx context.Context, mid string) error { return platform.MarkPoolReady(ctx, pool, mid) }
		x.OnShopLink = customers.ShopLinker(pool)
		id, gateway = x, x.Gateway
		extraRelays = outbox.Relays{
			// Provisioning: background (the merchant shows "provisioning"), merchants in parallel.
			{DB: pool, Sync: x.Provisioner(), Log: log, Consumer: "pool", Lock: 779, Partitioned: true, Background: true,
				Workers: envInt("PROVISION_WORKERS", 8), Accepts: zitadel.PoolEvents},
			// Block/unblock on suspend/reinstate: drained in the request.
			{DB: pool, Sync: x.PoolState(), Log: log, Consumer: "pool-state", Lock: 780, Partitioned: true, Accepts: zitadel.PoolStateEvents},
		}
	case "zitadel", "zitadel-orgs":
		var cfg zitadel.Config
		if err := readJSON(env("STACK_CONFIG", "/bootstrap/stack.json"), &cfg); err != nil {
			return err
		}
		z := zitadel.New(ctx, cfg)
		id = z
		if cfg.Orgs {
			idSync = &outbox.Relay{DB: pool, Sync: z, Log: log, Consumer: "identity", Lock: 778, Partitioned: true, Accepts: zitadel.SyncsEvent}
		}
	case "ory":
		var cfg ory.Config
		if err := readJSON(env("STACK_CONFIG", "/bootstrap/stack.json"), &cfg); err != nil {
			return err
		}
		id = ory.New(ctx, cfg)
	case "logto":
		var cfg logto.Config
		if err := readJSON(env("STACK_CONFIG", "/bootstrap/stack.json"), &cfg); err != nil {
			return err
		}
		id = logto.New(ctx, cfg)
	case "oidcop":
		cfg, err := oidcopConfig()
		if err != nil {
			return err
		}
		if id, err = oidcop.New(ctx, pool, cfg, log); err != nil {
			return err
		}
	case "oidcpool":
		cfg, err := oidcpoolConfig()
		if err != nil {
			return err
		}
		cfg.OnShopLink = customers.ShopLinker(pool)
		if id, err = oidcpool.New(ctx, pool, cfg, log); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown IDP %q", os.Getenv("IDP"))
	}

	var eng engine
	switch env("AUTHZ", "spicedb") {
	case "spicedb":
		c, err := spicedb.New(env("SPICEDB_ENDPOINT", "spicedb:50051"), env("SPICEDB_KEY", ""))
		if err != nil {
			return err
		}
		eng = c
	case "openfga":
		c, err := openfga.New(ctx, env("OPENFGA_URL", "http://openfga:8080"))
		if err != nil {
			return err
		}
		eng = c
	default:
		return fmt.Errorf("unknown AUTHZ %q", os.Getenv("AUTHZ"))
	}

	relays := outbox.Relays{{DB: pool, Sync: eng, Log: log}}
	if idSync != nil {
		relays = append(relays, idSync)
	}
	relays = append(relays, extraRelays...)
	if err := enqueueSystemRoles(ctx, pool, relays[0]); err != nil {
		return err
	}

	exec := &core.Executor{
		DB:    pool,
		Authn: &core.Authenticator{Verifier: id, DB: pool},
		Authz: eng,
		Relay: relays,
		Log:   log,
		Now:   time.Now,
	}

	var reg core.Registry
	// Round 4 (SPEC §16): an adapter with a pool per merchant turns on partners (several
	// memberships) and Shop-linked customer records. Off: a/a2/b/f/h behave as in round 3.
	pools, _ := id.(identity.TenantPools)
	multi := pools != nil
	reg.Add(&platform.Module{IdP: id, MultiMerchant: multi})
	reg.Add(&merchants.Module{MultiMerchant: multi, Pools: pools})
	reg.Add(&roles.Module{})
	reg.Add(&stores.Module{})
	reg.Add(&catalog.Module{})
	reg.Add(&orders.Module{ShopLinks: multi})
	reg.Add(&payments.Module{})
	reg.Add(&delivery.Module{})
	reg.Add(&apps.Module{})
	reg.Add(&agents.Module{IdP: id})
	reg.Add(&me.Module{})
	if os.Getenv("TEST_MODE") == "1" {
		reg.Add(&testsupport.Module{Secret: os.Getenv("TEST_SECRET"), IdP: id, DriverConfig: id.DriverConfig()})
	}

	mux := http.NewServeMux()
	reg.Mount(mux, exec)
	if m, ok := id.(interface{ Mount(*http.ServeMux) }); ok {
		m.Mount(mux) // an in-app issuer serves its endpoints on the app's port
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		for name, check := range map[string]func(context.Context) error{"db": pool.Ping, "authz": eng.Ping, "idp": id.Ping} {
			if err := check(ctx); err != nil {
				core.WriteJSON(w, 503, map[string]any{"status": "unhealthy", "component": name, "error": err.Error()})
				return
			}
		}
		core.WriteJSON(w, 200, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { core.WriteError(w, core.ErrNotFound) })

	relays.Run(ctx, time.Second)

	var handler http.Handler = mux
	if gateway != nil {
		handler = gateway(mux) // identity hosts → Zitadel / login stand-in; the rest → API
	}
	srv := &http.Server{Addr: ":" + env("PORT", "8081"), Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("listening", "addr", srv.Addr, "ops", len(reg.Ops()))
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// enqueueSystemRoles writes the system roles to the outbox and drains (retrying
// until the engine answers), so all engine writes take the outbox path.
func enqueueSystemRoles(ctx context.Context, pool *pgxpool.Pool, relay *outbox.Relay) error {
	for _, ev := range roles.SystemRoleEvents() {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, `INSERT INTO outbox(event) VALUES ($1)`, b); err != nil {
			return err
		}
	}
	var err error
	for i := 0; i < 60; i++ {
		if err = relay.Drain(ctx); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("sync system roles: %w", err)
}

// oidcopConfig: stack h's issuer, from env. PUBLIC_URL is the name clients use; the issuer
// is pinned to it (never derived from Host / X-Forwarded-*).
func oidcopConfig() (oidcop.Config, error) {
	public := strings.TrimSuffix(env("PUBLIC_URL", "http://cs-ws.lab.alexluong.com:8094"), "/")
	access, err := time.ParseDuration(env("ACCESS_TOKEN_TTL", "15m"))
	if err != nil {
		return oidcop.Config{}, err
	}
	refresh, err := time.ParseDuration(env("REFRESH_TOKEN_TTL", "24h"))
	if err != nil {
		return oidcop.Config{}, err
	}
	return oidcop.Config{
		Issuer: public + "/oidc", LoginURL: public + "/login", Secret: os.Getenv("ISSUER_SECRET"),
		Audience: env("API_AUDIENCE", "platform-api"), LoginClientID: env("LOGIN_CLIENT_ID", "platform-cli"),
		RedirectURIs: strings.Split(env("DRIVER_REDIRECT_URI", "http://127.0.0.1/callback"), ","),
		AccessTTL:    access, RefreshTTL: refresh,
	}, nil
}

// oidcpoolConfig: stack h2's issuers, from env. Each pool's issuer is PUBLIC_URL/oidc/<pool>,
// never derived from Host / X-Forwarded-*.
func oidcpoolConfig() (oidcpool.Config, error) {
	public := strings.TrimSuffix(env("PUBLIC_URL", "http://cs-ws.lab.alexluong.com:8098"), "/")
	access, err := time.ParseDuration(env("ACCESS_TOKEN_TTL", "15m"))
	if err != nil {
		return oidcpool.Config{}, err
	}
	refresh, err := time.ParseDuration(env("REFRESH_TOKEN_TTL", "24h"))
	if err != nil {
		return oidcpool.Config{}, err
	}
	return oidcpool.Config{
		PublicURL: public, InternalURL: env("INTERNAL_URL", "http://localhost:"+env("PORT", "8098")),
		Secret: os.Getenv("ISSUER_SECRET"), Audience: env("API_AUDIENCE", "platform-api"),
		LoginClientID: env("LOGIN_CLIENT_ID", "platform-cli"), StaffClientID: env("STAFF_CLIENT_ID", "merchant-admin"),
		ShopperClient: env("CUSTOMER_CLIENT_ID", "storefront"),
		RedirectURIs:  strings.Split(env("DRIVER_REDIRECT_URI", "http://127.0.0.1/callback"), ","),
		AccessTTL:     access, RefreshTTL: refresh,
	}, nil
}

// instancesConfig: stack i, from env (shared with the bootstrap).
func instancesConfig() zitadel.InstancesConfig {
	return zitadel.InstancesConfig{
		ZitadelURL: env("ZITADEL_URL", "http://i-zitadel:8080"), ExternalDomain: env("ZITADEL_EXTERNAL_DOMAIN", "workforce.zitadel.internal"),
		ExternalOrigin: env("ZITADEL_EXTERNAL_ORIGIN", "http://workforce.zitadel.internal:8080"), KeysDir: env("ZITADEL_KEYS_DIR", "/keys"),
		IDDomain: env("ID_DOMAIN", "cs.internal"), IDPort: env("ID_PORT", "8096"),
		RedirectURI: env("DRIVER_REDIRECT_URI", "http://localhost:3999/callback"),
	}
}

func envInt(k string, def int) int {
	var n int
	if _, err := fmt.Sscanf(env(k, ""), "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}

func readJSON(path string, v any) error {
	var lastErr error
	for i := 0; i < 120; i++ {
		b, err := os.ReadFile(path)
		if err == nil {
			return json.Unmarshal(b, v)
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	return fmt.Errorf("read %s: %w", path, lastErr)
}

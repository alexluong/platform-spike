// Command server is the composition root: config → adapters → modules, by hand.
// Stack a: IDP=zitadel AUTHZ=spicedb. Stack b: IDP=ory AUTHZ=openfga.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	switch env("IDP", "zitadel") {
	case "zitadel":
		var cfg zitadel.Config
		if err := readJSON(env("STACK_CONFIG", "/bootstrap/stack.json"), &cfg); err != nil {
			return err
		}
		id = zitadel.New(ctx, cfg)
	case "ory":
		var cfg ory.Config
		if err := readJSON(env("STACK_CONFIG", "/bootstrap/stack.json"), &cfg); err != nil {
			return err
		}
		id = ory.New(ctx, cfg)
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

	relay := &outbox.Relay{DB: pool, Sync: eng, Log: log}
	if err := enqueueSystemRoles(ctx, pool, relay); err != nil {
		return err
	}

	exec := &core.Executor{
		DB:    pool,
		Authn: &core.Authenticator{Verifier: id, DB: pool},
		Authz: eng,
		Relay: relay,
		Log:   log,
		Now:   time.Now,
	}

	var reg core.Registry
	reg.Add(&platform.Module{IdP: id})
	reg.Add(&merchants.Module{})
	reg.Add(&roles.Module{})
	reg.Add(&stores.Module{})
	reg.Add(&catalog.Module{})
	reg.Add(&orders.Module{})
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

	go relay.Run(ctx, time.Second)

	srv := &http.Server{Addr: ":" + env("PORT", "8081"), Handler: mux, ReadHeaderTimeout: 10 * time.Second}
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

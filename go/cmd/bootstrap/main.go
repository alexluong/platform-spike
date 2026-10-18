// Command bootstrap is the one-shot, idempotent stack bootstrap: app DB
// migrations, authz engine schema, IdP project/app. It writes the IdP config
// the server reads (STACK_CONFIG). Adapters chosen by IDP / AUTHZ like the server.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/alexluong/platform-spike/go/internal/adapters/logto"
	"github.com/alexluong/platform-spike/go/internal/adapters/oidcop"
	"github.com/alexluong/platform-spike/go/internal/adapters/openfga"
	"github.com/alexluong/platform-spike/go/internal/adapters/ory"
	"github.com/alexluong/platform-spike/go/internal/adapters/spicedb"
	"github.com/alexluong/platform-spike/go/internal/adapters/zitadel"
	"github.com/alexluong/platform-spike/go/internal/db"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("bootstrap failed", "err", err)
		os.Exit(1)
	}
	log.Info("bootstrap done")
}

// rotateSigningKey (stack h): `bootstrap rotate-signing-key` in any app container. The new
// key is published at once and signs after PUBLISH_AHEAD (default 1m: every instance
// reloads keys every 30s); the old keys verify for RETIRE_AFTER more (default 30m: two
// access-token lifetimes).
func rotateSigningKey(ctx context.Context, log *slog.Logger) error {
	ahead, err := time.ParseDuration(env("PUBLISH_AHEAD", "1m"))
	if err != nil {
		return err
	}
	retire, err := time.ParseDuration(env("RETIRE_AFTER", "30m"))
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, env("DATABASE_URL", "postgres://app:app@localhost:5432/app"))
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := oidcop.Rotate(ctx, pool, os.Getenv("ISSUER_SECRET"), ahead, retire); err != nil {
		return err
	}
	log.Info("signing key rotated", "signsAfter", ahead, "oldRetireAfter", retire)
	return nil
}

func retry(log *slog.Logger, what string, f func() error) error {
	var err error
	for i := 0; i < 120; i++ {
		if err = f(); err == nil {
			return nil
		}
		log.Info("retrying", "step", what, "err", err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("%s: %w", what, err)
}

func run(log *slog.Logger) error {
	ctx := context.Background()
	if len(os.Args) > 1 && os.Args[1] == "rotate-signing-key" {
		return rotateSigningKey(ctx, log)
	}
	if len(os.Args) > 2 && os.Args[1] == "keygen" { // stack i: Zitadel system API user keys
		return zitadel.Keygen(os.Args[2], "provisioner", "login")
	}
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		return probe(ctx, log)
	}

	pool, err := db.Open(ctx, env("DATABASE_URL", "postgres://app:app@localhost:5432/app"))
	if err != nil {
		return err
	}
	if err := db.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	pool.Close()
	log.Info("migrations applied")

	switch env("AUTHZ", "spicedb") {
	case "spicedb":
		c, err := spicedb.New(env("SPICEDB_ENDPOINT", "spicedb:50051"), env("SPICEDB_KEY", ""))
		if err != nil {
			return err
		}
		if err := retry(log, "spicedb schema", func() error { return c.WriteSchema(ctx) }); err != nil {
			return err
		}
		log.Info("spicedb schema written")
	case "openfga":
		if err := retry(log, "openfga store and model", func() error {
			store, model, err := openfga.Bootstrap(ctx, env("OPENFGA_URL", "http://openfga:8080"))
			if err == nil {
				log.Info("openfga model ready", "store", store, "model", model)
			}
			return err
		}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown AUTHZ %q", os.Getenv("AUTHZ"))
	}

	var out any
	switch idp := env("IDP", "zitadel"); idp {
	case "zitadel", "zitadel-orgs":
		issuer := env("ZITADEL_ISSUER", "http://cs-ws.lab.alexluong.com:8085")
		cfg, err := zitadel.Bootstrap(ctx, log, zitadel.BootstrapInput{
			Issuer:       issuer,
			AdminPATFile: env("ZITADEL_ADMIN_PAT_FILE", "/zitadel/bootstrap/admin.pat"),
			LoginPATFile: env("ZITADEL_LOGIN_PAT_FILE", "/zitadel/bootstrap/login-client.pat"),
			ProjectName:  "platform-spike",
			AppName:      "conformance-driver",
			RedirectURI:  env("DRIVER_REDIRECT_URI", "http://localhost:3999/callback"),
			LoginBaseURI: issuer + "/ui/v2/login/",
			Orgs:         idp == "zitadel-orgs",
		})
		if err != nil {
			return err
		}
		out = cfg
	case "zitadel-instances": // stack i: directory table, workforce and platform pools
		pool, err := db.Open(ctx, env("DATABASE_URL", "postgres://app:app@localhost:5432/app"))
		if err != nil {
			return err
		}
		defer pool.Close()
		if err := zitadel.MigrateInstances(ctx, pool); err != nil {
			return err
		}
		x, err := zitadel.NewInstances(zitadel.InstancesConfig{
			ZitadelURL: env("ZITADEL_URL", "http://i-zitadel:8080"), ExternalDomain: env("ZITADEL_EXTERNAL_DOMAIN", "workforce.zitadel.internal"),
			ExternalOrigin: env("ZITADEL_EXTERNAL_ORIGIN", "http://workforce.zitadel.internal:8080"), KeysDir: env("ZITADEL_KEYS_DIR", "/keys"),
			IDDomain: env("ID_DOMAIN", "cs.internal"), IDPort: env("ID_PORT", "8096"),
			RedirectURI: env("DRIVER_REDIRECT_URI", "http://localhost:3999/callback"),
		}, pool, log)
		if err != nil {
			return err
		}
		if err := retry(log, "zitadel workforce and platform pools", func() error { return x.BootstrapInstances(ctx) }); err != nil {
			return err
		}
		out = map[string]any{"idp": "zitadel-instances"}
	case "ory":
		var cfg ory.Config
		if err := retry(log, "hydra driver client", func() (err error) {
			cfg, err = ory.Bootstrap(ctx, log, ory.BootstrapInput{
				Issuer:         env("HYDRA_ISSUER", "http://cs-ws.lab.alexluong.com:4444"),
				HydraPublicURL: env("HYDRA_PUBLIC_URL", "http://hydra:4444"),
				HydraAdminURL:  env("HYDRA_ADMIN_URL", "http://hydra:4445"),
				KratosAdminURL: env("KRATOS_ADMIN_URL", "http://kratos:4434"),
				Audience:       env("API_AUDIENCE", "platform-spike"),
				ClientName:     "conformance-driver",
				RedirectURI:    env("DRIVER_REDIRECT_URI", "http://localhost:3999/callback"),
			})
			return err
		}); err != nil {
			return err
		}
		out = cfg
	case "logto":
		var cfg logto.Config
		if err := retry(log, "logto resource, driver app, sign-in experience", func() (err error) {
			cfg, err = logto.Bootstrap(ctx, log, logto.BootstrapInput{
				Endpoint:          env("LOGTO_ENDPOINT", "http://cs-ws.lab.alexluong.com:8092"),
				InternalURL:       env("LOGTO_INTERNAL_URL", "http://logto:3001"),
				AdminClientID:     env("LOGTO_ADMIN_CLIENT_ID", ""),
				AdminClientSecret: env("LOGTO_ADMIN_CLIENT_SECRET", ""),
				Resource:          env("API_RESOURCE", "https://api.platform-spike.local"),
				ClientName:        "conformance-driver",
				RedirectURI:       env("DRIVER_REDIRECT_URI", "http://localhost:3999/callback"),
			})
			return err
		}); err != nil {
			return err
		}
		out = cfg
	case "oidcop":
		// The issuer lives in the app DB: its tables, nothing external. The server creates
		// the first signing key at start (under a lock).
		pool, err := db.Open(ctx, env("DATABASE_URL", "postgres://app:app@localhost:5432/app"))
		if err != nil {
			return err
		}
		defer pool.Close()
		if err := oidcop.Migrate(ctx, pool); err != nil {
			return fmt.Errorf("issuer migrations: %w", err)
		}
		log.Info("issuer migrations applied")
		out = map[string]any{"idp": "oidcop"}
	default:
		return fmt.Errorf("unknown IDP %q", os.Getenv("IDP"))
	}

	path := env("STACK_CONFIG", "/bootstrap/stack.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(path+".tmp", b, 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

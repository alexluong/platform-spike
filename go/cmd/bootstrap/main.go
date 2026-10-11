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
	switch env("IDP", "zitadel") {
	case "zitadel":
		issuer := env("ZITADEL_ISSUER", "http://cs-ws.lab.alexluong.com:8085")
		cfg, err := zitadel.Bootstrap(ctx, log, zitadel.BootstrapInput{
			Issuer:       issuer,
			AdminPATFile: env("ZITADEL_ADMIN_PAT_FILE", "/zitadel/bootstrap/admin.pat"),
			LoginPATFile: env("ZITADEL_LOGIN_PAT_FILE", "/zitadel/bootstrap/login-client.pat"),
			ProjectName:  "platform-spike",
			AppName:      "conformance-driver",
			RedirectURI:  env("DRIVER_REDIRECT_URI", "http://localhost:3999/callback"),
			LoginBaseURI: issuer + "/ui/v2/login/",
		})
		if err != nil {
			return err
		}
		out = cfg
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

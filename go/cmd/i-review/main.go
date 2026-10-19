// i-review: review tooling for stack i (results/review-i.md), not part of the app. Acts on
// Zitadel with the provisioner system key, the way a control plane (or an attacker who stole
// the key) would. Runs on the stack's network with the keys volume:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/i-review ./cmd/i-review
//	scp /tmp/i-review cs-ws:/tmp/ && ssh cs-ws docker run --rm --network ps-i_i-net \
//	  -v ps-i_i-keys:/keys:ro -v /tmp/i-review:/i-review alpine /i-review <cmd> <args>
//
// Commands (instance = instance domain, e.g. platform.zitadel.internal):
//
//	deactivate <instance> <userId>   POST /v2/users/{id}/deactivate
//	reactivate <instance> <userId>   POST /v2/users/{id}/reactivate
//	oidc <instance>                  GET /admin/v1/settings/oidc (token lifetimes)
//	lockout <instance>               GET /admin/v1/policies/lockout
//	call <instance> <method> <path> [json]   any call as the provisioner (blast radius demo)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/alexluong/platform-spike/go/internal/adapters/zitadel"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: i-review <cmd> <instance> [args]")
		os.Exit(2)
	}
	z, err := zitadel.NewZitadel(env("ZITADEL_URL", "http://i-zitadel:8080"), env("ZITADEL_EXTERNAL_DOMAIN", "workforce.zitadel.internal"),
		env("ZITADEL_EXTERNAL_ORIGIN", "http://workforce.zitadel.internal:8080"), env("ZITADEL_KEYS_DIR", "/keys"))
	if err != nil {
		fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	at := zitadel.At{InstanceHost: os.Args[2]}
	var out any
	switch cmd := os.Args[1]; cmd {
	case "deactivate", "reactivate":
		err = z.Call(ctx, z.Provisioner, at, "POST", "/v2/users/"+os.Args[3]+"/"+cmd, map[string]any{}, &out)
	case "oidc":
		err = z.Call(ctx, z.Provisioner, at, "GET", "/admin/v1/settings/oidc", nil, &out)
	case "lockout":
		err = z.Call(ctx, z.Provisioner, at, "GET", "/admin/v1/policies/lockout", nil, &out)
	case "call":
		var body any
		if len(os.Args) > 5 {
			if err := json.Unmarshal([]byte(os.Args[5]), &body); err != nil {
				fail(err)
			}
		}
		err = z.Call(ctx, z.Provisioner, at, os.Args[3], os.Args[4], body, &out)
	default:
		fail(fmt.Errorf("unknown command %q", cmd))
	}
	if err != nil {
		fail(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

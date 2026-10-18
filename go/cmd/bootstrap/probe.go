package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/alexluong/platform-spike/go/internal/adapters/zitadel"
)

// probe: throwaway checks of Zitadel's system API behaviour (stack i development).
func probe(ctx context.Context, log *slog.Logger) error {
	z, err := zitadel.NewZitadel(env("ZITADEL_URL", ""), env("ZITADEL_EXTERNAL_DOMAIN", ""), env("ZITADEL_EXTERNAL_ORIGIN", ""), env("ZITADEL_KEYS_DIR", "/keys"))
	if err != nil {
		return err
	}
	sys := zitadel.At{InstanceHost: z.SystemHost}
	var list map[string]any
	err = z.Call(ctx, z.Provisioner, sys, "POST", "/system/v1/instances/_search", map[string]any{}, &list)
	log.Info("list instances", "err", err, "out", list)
	t := time.Now()
	var created map[string]any
	dom := "probe-" + time.Now().Format("150405") + ".zitadel.internal"
	err = z.Call(ctx, z.Provisioner, sys, "POST", "/system/v1/instances/_create", map[string]any{
		"instanceName": dom, "firstOrgName": "staff", "customDomain": dom,
		"machine": map[string]any{"userName": "bootstrap", "name": "bootstrap"},
	}, &created)
	log.Info("create instance", "err", err, "out", created, "took", time.Since(t))
	at := zitadel.At{InstanceHost: dom}
	var me map[string]any
	err = z.Call(ctx, z.Provisioner, at, "GET", "/management/v1/orgs/me", nil, &me)
	log.Info("orgs/me as provisioner", "err", err, "out", me)
	var org map[string]any
	err = z.Call(ctx, z.Provisioner, at, "POST", "/zitadel.org.v2.OrganizationService/AddOrganization", map[string]any{"name": "customers", "organizationId": "customers"}, &org)
	log.Info("add org", "err", err, "out", org)
	var sess map[string]any
	err = z.Call(ctx, z.Login, at, "POST", "/v2/sessions", map[string]any{"checks": map[string]any{"user": map[string]any{"loginName": "nobody@example.com"}}}, &sess)
	log.Info("session as login", "err", err, "out", sess)
	return nil
}

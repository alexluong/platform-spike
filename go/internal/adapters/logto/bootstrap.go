package logto

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// BootstrapInput configures Bootstrap.
type BootstrapInput struct {
	Endpoint          string // Logto's external URL (issuer = Endpoint + "/oidc")
	InternalURL       string
	AdminClientID     string // seeded M2M app (stacks/f/postgres/logto-seed.sql)
	AdminClientSecret string
	Resource          string // API resource indicator
	ClientName        string // driver's SPA app, found by name + redirect URI (idempotent)
	RedirectURI       string
}

// Bootstrap ensures the API resource, the login driver's SPA app (auth code + PKCE) and a
// sign-in experience with email + password sign-in only (no self-registration, no breached-
// password lookup), then returns the app's config. Every step is idempotent.
func Bootstrap(ctx context.Context, log *slog.Logger, in BootstrapInput) (Config, error) {
	cfg := Config{
		Endpoint: in.Endpoint, InternalURL: in.InternalURL, Resource: in.Resource, RedirectURI: in.RedirectURI,
		AdminClientID: in.AdminClientID, AdminClientSecret: in.AdminClientSecret,
	}
	c := &Client{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
	c.mgmt = newTokenSource(c.http, cfg)

	// API resource.
	var resources []struct {
		Indicator string `json:"indicator"`
	}
	if err := c.api(ctx, "GET", "/api/resources?page_size=100&excludeManagementApis=true", nil, &resources); err != nil {
		return cfg, err
	}
	if !slices.ContainsFunc(resources, func(r struct {
		Indicator string `json:"indicator"`
	}) bool {
		return r.Indicator == in.Resource
	}) {
		if err := c.api(ctx, "POST", "/api/resources", map[string]any{
			"name": "platform-spike API", "indicator": in.Resource, "accessTokenTtl": 3600,
		}, nil); err != nil {
			return cfg, err
		}
		log.Info("logto api resource created", "indicator", in.Resource)
	}

	// Driver app.
	var apps []struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		OidcClientMetadata struct {
			RedirectURIs []string `json:"redirectUris"`
		} `json:"oidcClientMetadata"`
	}
	if err := c.api(ctx, "GET", "/api/applications?types=SPA&page_size=100&search="+url.QueryEscape(in.ClientName), nil, &apps); err != nil {
		return cfg, err
	}
	for _, a := range apps {
		if a.Name == in.ClientName && slices.Contains(a.OidcClientMetadata.RedirectURIs, in.RedirectURI) {
			cfg.ClientID = a.ID
		}
	}
	if cfg.ClientID == "" {
		var out struct {
			ID string `json:"id"`
		}
		if err := c.api(ctx, "POST", "/api/applications", map[string]any{
			"name": in.ClientName, "type": "SPA",
			"oidcClientMetadata": map[string]any{"redirectUris": []string{in.RedirectURI}, "postLogoutRedirectUris": []string{}},
		}, &out); err != nil {
			return cfg, err
		}
		cfg.ClientID = out.ID
		log.Info("logto driver app created", "clientId", out.ID)
	}

	// Sign-in experience: email + password, sign-in only. Users are created through the
	// Management API (/api/_test/users), never by self-registration.
	if err := c.api(ctx, "PATCH", "/api/sign-in-exp", map[string]any{
		"signInMode": "SignIn",
		"signUp":     map[string]any{"identifiers": []string{}, "password": false, "verify": false},
		"signIn": map[string]any{"methods": []map[string]any{
			{"identifier": "email", "password": true, "verificationCode": false, "isPasswordPrimary": true},
		}},
		// Default policy looks every new password up at api.pwnedpasswords.com.
		"passwordPolicy": map[string]any{"rejects": map[string]any{"pwned": false}},
	}, nil); err != nil {
		return cfg, err
	}
	return cfg, nil
}

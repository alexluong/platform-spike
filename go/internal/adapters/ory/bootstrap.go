package ory

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
	Issuer         string // Hydra's external issuer URL
	HydraPublicURL string
	HydraAdminURL  string
	KratosAdminURL string
	Audience       string
	ClientName     string // driver's public client, found by name (idempotent)
	RedirectURI    string
}

// Bootstrap registers the login driver's public OAuth2 client in Hydra
// (authorization code + PKCE, no secret) if missing, and returns the app's config.
func Bootstrap(ctx context.Context, log *slog.Logger, in BootstrapInput) (Config, error) {
	hc := &http.Client{Timeout: 15 * time.Second}
	cfg := Config{
		Issuer: in.Issuer, HydraPublicURL: in.HydraPublicURL, HydraAdminURL: in.HydraAdminURL,
		KratosAdminURL: in.KratosAdminURL, Audience: in.Audience, RedirectURI: in.RedirectURI,
	}
	var existing []struct {
		ClientID     string   `json:"client_id"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := Call(ctx, hc, "GET", in.HydraAdminURL+"/admin/clients?client_name="+url.QueryEscape(in.ClientName), nil, &existing); err != nil {
		return cfg, err
	}
	for _, c := range existing {
		if slices.Contains(c.RedirectURIs, in.RedirectURI) {
			cfg.ClientID = c.ClientID
			log.Info("hydra driver client exists", "clientId", c.ClientID)
			return cfg, nil
		}
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := Call(ctx, hc, "POST", in.HydraAdminURL+"/admin/clients", map[string]any{
		"client_name":                in.ClientName,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"redirect_uris":              []string{in.RedirectURI},
		"token_endpoint_auth_method": "none",
		"scope":                      "openid offline",
		"audience":                   []string{in.Audience},
		"access_token_strategy":      "jwt",
	}, &out); err != nil {
		return cfg, err
	}
	cfg.ClientID = out.ClientID
	log.Info("hydra driver client created", "clientId", out.ClientID)
	return cfg, nil
}

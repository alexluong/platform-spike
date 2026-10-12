// Package ory adapts the identity port to Ory: Kratos holds the users
// (identities with password credentials, created through the admin API) and
// Hydra is the OAuth2/OIDC server (JWT access tokens verified against its
// JWKS; OAuth2 clients for apps and agents through its admin API).
package ory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/alexluong/platform-spike/go/internal/identity"
)

// Config is produced by Bootstrap and read by the app at startup.
type Config struct {
	Issuer         string `json:"issuer"`         // Hydra's issuer: the external public URL clients use (token `iss`)
	HydraPublicURL string `json:"hydraPublicUrl"` // Hydra public API inside the network (JWKS)
	HydraAdminURL  string `json:"hydraAdminUrl"`  // Hydra admin API inside the network (clients)
	KratosAdminURL string `json:"kratosAdminUrl"` // Kratos admin API inside the network (identities)
	Audience       string `json:"audience"`       // access tokens must carry this audience
	ClientID       string `json:"clientId"`       // public OAuth2 client (auth code + PKCE) used by the login driver
	RedirectURI    string `json:"redirectUri"`    // registered redirect for the driver
}

// Client implements identity.Verifier and identity.Provisioner.
type Client struct {
	cfg      Config
	http     *http.Client
	verifier *oidc.IDTokenVerifier
}

func New(ctx context.Context, cfg Config) *Client {
	hc := &http.Client{Timeout: 15 * time.Second}
	// Keys come from the internal URL; the issuer check uses the external one (what Hydra puts in `iss`).
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), hc), cfg.HydraPublicURL+"/.well-known/jwks.json")
	// Checks signature, issuer, expiry and that aud contains the API audience (ID tokens carry the client id instead).
	v := oidc.NewVerifier(cfg.Issuer, keys, &oidc.Config{ClientID: cfg.Audience})
	return &Client{cfg: cfg, http: hc, verifier: v}
}

// DriverConfig is what the conformance driver needs (served only in TEST_MODE).
// The driver reaches Kratos public, Hydra public and Hydra admin on their published ports.
func (c *Client) DriverConfig() map[string]any {
	return map[string]any{
		"idp": "ory", "issuer": c.cfg.Issuer, "clientId": c.cfg.ClientID, "redirectUri": c.cfg.RedirectURI, "audience": c.cfg.Audience,
	}
}

func (c *Client) Verify(ctx context.Context, bearer string) (identity.Token, error) {
	tok, err := c.verifier.Verify(ctx, bearer)
	if err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	var claims struct {
		ClientID string `json:"client_id"`
	}
	if err := tok.Claims(&claims); err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	if err := checkAccessToken(claims.ClientID, tok.Subject, c.cfg.ClientID); err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	return identity.Token{Subject: tok.Subject}, nil
}

// checkAccessToken accepts only Hydra JWT access tokens from our own clients. The
// verifier above is go-oidc's ID-token verifier: it checks signature, iss, exp and
// that aud contains the API audience, which an ID token also passes when some
// client's id equals the audience (Hydra lets the admin API pick client ids). Hydra
// puts client_id in access tokens, never in ID tokens. Accepted: the login
// driver's client (user tokens), or client_credentials (client_id == sub: apps
// and agents; an unknown client id maps to no principal).
func checkAccessToken(clientID, subject, loginClientID string) error {
	switch {
	case clientID == "":
		return fmt.Errorf("not an access token (no client_id)")
	case clientID == loginClientID, clientID == subject:
		return nil
	}
	return fmt.Errorf("token from client %q not accepted", clientID)
}

// Ping checks Kratos and Hydra are ready.
func (c *Client) Ping(ctx context.Context) error {
	for _, u := range []string{c.cfg.KratosAdminURL + "/health/ready", c.cfg.HydraAdminURL + "/health/ready"} {
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("%s: %d", u, resp.StatusCode)
		}
	}
	return nil
}

// CreateUser creates a Kratos identity with a password credential; the subject is the identity id
// (the login driver accepts Hydra's login request with that id).
func (c *Client) CreateUser(ctx context.Context, email, password, _ string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := Call(ctx, c.http, "POST", c.cfg.KratosAdminURL+"/admin/identities", map[string]any{
		"schema_id":   "default",
		"traits":      map[string]any{"email": email},
		"credentials": map[string]any{"password": map[string]any{"config": map[string]any{"password": password}}},
	}, &out)
	return out.ID, err
}

// CreateClient registers a Hydra OAuth2 client (client_credentials). Hydra's
// client-credentials tokens carry the client id as `sub`.
func (c *Client) CreateClient(ctx context.Context, name, _ string) (identity.Client, error) {
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := Call(ctx, c.http, "POST", c.cfg.HydraAdminURL+"/admin/clients", map[string]any{
		"client_name":                name,
		"grant_types":                []string{"client_credentials"},
		"response_types":             []string{"token"},
		"token_endpoint_auth_method": "client_secret_basic",
		"audience":                   []string{c.cfg.Audience},
		"access_token_strategy":      "jwt",
	}, &out); err != nil {
		return identity.Client{}, err
	}
	return identity.Client{Subject: out.ClientID, ClientID: out.ClientID, ClientSecret: out.ClientSecret}, nil
}

// Call does a JSON request against an Ory API (admin APIs need no token inside the network).
func Call(ctx context.Context, hc *http.Client, method, url string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Method: method, URL: url, Body: string(raw)}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// APIError is a non-2xx Ory response.
type APIError struct {
	Status      int
	Method, URL string
	Body        string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("ory %s %s: %d %s", e.Method, e.URL, e.Status, e.Body)
}

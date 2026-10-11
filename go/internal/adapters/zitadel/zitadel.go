// Package zitadel adapts the identity port to Zitadel (v4): JWT access tokens
// verified against Zitadel's JWKS, users and machine clients created through
// the v2 User API with the bootstrap service account's PAT.
package zitadel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	Issuer         string `json:"issuer"`         // external URL, e.g. http://cs-ws:8085 (also reachable inside compose)
	OrgID          string `json:"orgId"`          // org that holds all users and machine clients
	ProjectID      string `json:"projectId"`      // tokens must carry this audience
	ClientID       string `json:"clientId"`       // OIDC app (auth code + PKCE) used by the login driver
	RedirectURI    string `json:"redirectUri"`    // registered redirect for the driver
	AdminPAT       string `json:"adminPat"`       // service account (IAM owner) used by the app
	LoginClientPAT string `json:"loginClientPat"` // IAM_LOGIN_CLIENT: the driver's stand-in for the login UI
}

// Client implements identity.Verifier and identity.Provisioner.
type Client struct {
	cfg      Config
	http     *http.Client
	verifier *oidc.IDTokenVerifier
}

func New(ctx context.Context, cfg Config) *Client {
	hc := &http.Client{Timeout: 15 * time.Second}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), hc), cfg.Issuer+"/oauth/v2/keys")
	// go-oidc's verifier checks signature, issuer, expiry and that aud contains the project id.
	v := oidc.NewVerifier(cfg.Issuer, keys, &oidc.Config{ClientID: cfg.ProjectID})
	return &Client{cfg: cfg, http: hc, verifier: v}
}

// DriverConfig is what the conformance driver needs (served only in TEST_MODE).
func (c *Client) DriverConfig() map[string]any {
	return map[string]any{
		"idp": "zitadel", "issuer": c.cfg.Issuer, "clientId": c.cfg.ClientID, "projectId": c.cfg.ProjectID,
		"redirectUri": c.cfg.RedirectURI, "loginClientToken": c.cfg.LoginClientPAT,
	}
}

func (c *Client) Verify(ctx context.Context, bearer string) (identity.Token, error) {
	tok, err := c.verifier.Verify(ctx, bearer)
	if err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	return identity.Token{Subject: tok.Subject}, nil
}

// Ping checks Zitadel is reachable.
func (c *Client) Ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.cfg.Issuer+"/debug/ready", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("zitadel ready: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) CreateUser(ctx context.Context, email, password string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := call(ctx, c.http, c.cfg.Issuer, c.cfg.AdminPAT, "POST", "/v2/users/new", map[string]any{
		"organizationId": c.cfg.OrgID,
		"username":       email,
		"human": map[string]any{
			"profile":  map[string]any{"givenName": "Test", "familyName": "User"},
			"email":    map[string]any{"email": email, "isVerified": true},
			"password": map[string]any{"password": password, "changeRequired": false},
		},
	}, &out)
	return out.ID, err
}

func (c *Client) CreateClient(ctx context.Context, name string) (identity.Client, error) {
	username := name + "-" + randHex(4)
	var user struct {
		ID string `json:"id"`
	}
	if err := call(ctx, c.http, c.cfg.Issuer, c.cfg.AdminPAT, "POST", "/v2/users/new", map[string]any{
		"organizationId": c.cfg.OrgID,
		"username":       username,
		"machine":        map[string]any{"name": name, "accessTokenType": "ACCESS_TOKEN_TYPE_JWT"},
	}, &user); err != nil {
		return identity.Client{}, err
	}
	var sec struct {
		ClientSecret string `json:"clientSecret"`
	}
	if err := call(ctx, c.http, c.cfg.Issuer, c.cfg.AdminPAT, "POST", "/v2/users/"+user.ID+"/secret", map[string]any{}, &sec); err != nil {
		return identity.Client{}, err
	}
	// Zitadel machine users authenticate with their username as client_id.
	return identity.Client{Subject: user.ID, ClientID: username, ClientSecret: sec.ClientSecret}, nil
}

// call does a JSON request against the Zitadel API.
func call(ctx context.Context, hc *http.Client, base, token, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Method: method, Path: path, Body: string(raw)}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// APIError is a non-2xx Zitadel response.
type APIError struct {
	Status       int
	Method, Path string
	Body         string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zitadel %s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

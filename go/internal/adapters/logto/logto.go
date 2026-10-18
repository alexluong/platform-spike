// Package logto adapts the identity port to Logto (OSS, v1.45): JWT access tokens
// for one API resource (RFC 8707 resource indicator) verified against Logto's JWKS;
// users and machine-to-machine apps created through the Management API with the
// seeded admin M2M app's client_credentials token.
package logto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/alexluong/platform-spike/go/internal/identity"
)

// managementAPI is the Management API resource of Logto OSS's only tenant ("default").
const managementAPI = "https://default.logto.app/api"

// Config is produced by Bootstrap and read by the app at startup.
type Config struct {
	Endpoint          string `json:"endpoint"`          // external URL clients use; the issuer is Endpoint + "/oidc"
	InternalURL       string `json:"internalUrl"`       // Logto inside the network (JWKS, token, Management API)
	Resource          string `json:"resource"`          // API resource indicator: access tokens must carry it as aud
	ClientID          string `json:"clientId"`          // SPA app (auth code + PKCE) used by the login driver
	RedirectURI       string `json:"redirectUri"`       // registered redirect for the driver
	AdminClientID     string `json:"adminClientId"`     // seeded M2M app with the Management API role
	AdminClientSecret string `json:"adminClientSecret"` //
}

func (c Config) issuer() string { return strings.TrimSuffix(c.Endpoint, "/") + "/oidc" }

// Client implements identity.Verifier and identity.Provisioner.
type Client struct {
	cfg      Config
	http     *http.Client
	verifier *oidc.IDTokenVerifier
	mgmt     *tokenSource
}

func New(ctx context.Context, cfg Config) *Client {
	hc := &http.Client{Timeout: 15 * time.Second}
	// Keys from the internal URL; the issuer check uses the external one (what Logto puts in `iss`).
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), hc), cfg.InternalURL+"/oidc/jwks")
	// go-oidc checks the signature (alg allowlist: Logto signs with ES384 by default, RS256 after
	// a rotation to RSA), iss, exp and that aud contains the API resource. Verify adds the rest.
	v := oidc.NewVerifier(cfg.issuer(), keys, &oidc.Config{ClientID: cfg.Resource, SupportedSigningAlgs: []string{oidc.ES384, oidc.RS256}})
	return &Client{cfg: cfg, http: hc, verifier: v, mgmt: newTokenSource(hc, cfg)}
}

// DriverConfig is what the conformance driver needs (served only in TEST_MODE): the public
// endpoint (OIDC and the sign-in experience API, through the edge), the SPA client id and
// the API resource. Nothing secret: a real browser would know all of it.
func (c *Client) DriverConfig() map[string]any {
	return map[string]any{
		"idp": "logto", "endpoint": c.cfg.Endpoint, "issuer": c.cfg.issuer(),
		"clientId": c.cfg.ClientID, "redirectUri": c.cfg.RedirectURI, "resource": c.cfg.Resource,
	}
}

// Verify checks a bearer token (SPEC §14 P7): signature (alg allowlist), iss, aud (the API
// resource), exp (go-oidc); typ "at+jwt" (Logto's JWT access tokens, RFC 9068; ID tokens are
// "JWT" and carry the client id as aud, so they also fail the aud check); and the client that
// obtained it: the login app (users), or a machine-to-machine app itself (apps, agents:
// client_credentials tokens have sub == client_id; the app maps the subject to its own row).
// Organization tokens (aud urn:logto:organization:…) fail the aud check.
func (c *Client) Verify(ctx context.Context, bearer string) (identity.Token, error) {
	if typ := tokenType(bearer); !strings.EqualFold(typ, "at+jwt") && !strings.EqualFold(typ, "application/at+jwt") {
		return identity.Token{}, fmt.Errorf("%w: not an access token (typ %q)", identity.ErrInvalidToken, typ)
	}
	tok, err := c.verifier.Verify(ctx, bearer)
	if err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	var cl struct {
		ClientID string `json:"client_id"`
	}
	if err := tok.Claims(&cl); err != nil {
		return identity.Token{}, fmt.Errorf("%w: claims: %v", identity.ErrInvalidToken, err)
	}
	if err := checkClient(cl.ClientID, tok.Subject, c.cfg.ClientID); err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	return identity.Token{Subject: tok.Subject}, nil
}

// checkClient: user tokens come from the login app; client_credentials tokens name the
// M2M app as both client_id and sub. Any other app in the tenant may request a token for
// the resource (Logto doesn't restrict which apps ask for which API), so it is refused here.
func checkClient(clientID, subject, loginClientID string) error {
	switch {
	case clientID == "":
		return fmt.Errorf("no client_id")
	case clientID == loginClientID, clientID == subject:
		return nil
	}
	return fmt.Errorf("token from client %q not accepted", clientID)
}

// tokenType reads the JOSE header's typ without verifying anything (go-oidc doesn't expose it).
func tokenType(jwt string) string {
	h, _, ok := strings.Cut(jwt, ".")
	if !ok {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		return ""
	}
	var hdr struct {
		Typ string `json:"typ"`
	}
	_ = json.Unmarshal(raw, &hdr)
	return hdr.Typ
}

// Ping checks Logto answers.
func (c *Client) Ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.cfg.InternalURL+"/api/status", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("logto status: %d", resp.StatusCode)
	}
	return nil
}

// CreateUser creates a user with a verified primary email and a password (Logto hashes it,
// Argon2i). One Management API call. The email is the sign-in identifier.
func (c *Client) CreateUser(ctx context.Context, email, password, _ string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.api(ctx, "POST", "/api/users", map[string]any{"primaryEmail": email, "password": password}, &out)
	return out.ID, err
}

// CreateClient creates a machine-to-machine app and reads its generated secret: two
// Management API calls (the create response omits the secret). No role: the API resource
// defines no scopes, and Logto issues client_credentials tokens for it without one.
func (c *Client) CreateClient(ctx context.Context, name, _ string) (identity.Client, error) {
	var app struct {
		ID string `json:"id"`
	}
	if err := c.api(ctx, "POST", "/api/applications", map[string]any{"name": name, "type": "MachineToMachine"}, &app); err != nil {
		return identity.Client{}, err
	}
	var secrets []struct {
		Value string `json:"value"`
	}
	if err := c.api(ctx, "GET", "/api/applications/"+app.ID+"/secrets", nil, &secrets); err != nil {
		return identity.Client{}, err
	}
	if len(secrets) == 0 {
		return identity.Client{}, fmt.Errorf("logto: application %s has no secret", app.ID)
	}
	// client_credentials tokens carry the app id as sub and client_id.
	return identity.Client{Subject: app.ID, ClientID: app.ID, ClientSecret: secrets[0].Value}, nil
}

func (c *Client) api(ctx context.Context, method, path string, body, out any) error {
	tok, err := c.mgmt.token(ctx)
	if err != nil {
		return err
	}
	return call(ctx, c.http, method, c.cfg.InternalURL+path, tok, body, out)
}

// tokenSource caches the admin M2M app's Management API token until shortly before expiry.
type tokenSource struct {
	hc  *http.Client
	cfg Config
	mu  sync.Mutex
	tok string
	exp time.Time
}

func newTokenSource(hc *http.Client, cfg Config) *tokenSource { return &tokenSource{hc: hc, cfg: cfg} }

func (s *tokenSource) token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok != "" && time.Now().Before(s.exp) {
		return s.tok, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {managementAPI}, "scope": {"all"}}
	req, err := http.NewRequestWithContext(ctx, "POST", s.cfg.InternalURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(url.QueryEscape(s.cfg.AdminClientID), url.QueryEscape(s.cfg.AdminClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", &APIError{Status: resp.StatusCode, Method: "POST", URL: "/oidc/token", Body: string(raw)}
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	s.tok, s.exp = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second-time.Minute)
	return s.tok, nil
}

// call does a JSON request against Logto.
func call(ctx context.Context, hc *http.Client, method, u, token string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
		return &APIError{Status: resp.StatusCode, Method: method, URL: u, Body: string(raw)}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// APIError is a non-2xx Logto response.
type APIError struct {
	Status      int
	Method, URL string
	Body        string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("logto %s %s: %d %s", e.Method, e.URL, e.Status, e.Body)
}

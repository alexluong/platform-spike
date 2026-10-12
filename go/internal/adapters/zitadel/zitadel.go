// Package zitadel adapts the identity port to Zitadel (v4): JWT access tokens
// verified against Zitadel's JWKS, users and machine clients created through
// the v2 User API with the bootstrap service account's PAT. With Config.Orgs
// (IDP=zitadel-orgs, stack a2) merchants are organizations and the adapter is
// also an outbox consumer (orgs.go).
package zitadel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/alexluong/platform-spike/go/internal/identity"
)

// Config is produced by Bootstrap and read by the app at startup.
type Config struct {
	Issuer         string `json:"issuer"`         // external URL, e.g. http://cs-ws:8085 (also reachable inside compose)
	OrgID          string `json:"orgId"`          // stack a: org of all users and clients; orgs mode: the platform org
	ProjectID      string `json:"projectId"`      // tokens must carry this audience
	ClientID       string `json:"clientId"`       // OIDC app (auth code + PKCE) used by the login driver
	RedirectURI    string `json:"redirectUri"`    // registered redirect for the driver
	AdminPAT       string `json:"adminPat"`       // service account (IAM owner) used by the app
	LoginClientPAT string `json:"loginClientPat"` // IAM_LOGIN_CLIENT: the driver's stand-in for the login UI

	// Organizations mode (stack a2).
	Orgs           bool   `json:"orgs,omitempty"`
	PeopleOrgID    string `json:"peopleOrgId,omitempty"`    // home org of merchant users
	CustomersOrgID string `json:"customersOrgId,omitempty"` // home org of customers
}

// Client implements identity.Verifier and identity.Provisioner (and, in orgs mode,
// authz.RelationSync as the identity outbox consumer).
type Client struct {
	cfg      Config
	http     *http.Client
	verifier *oidc.IDTokenVerifier
}

func New(ctx context.Context, cfg Config) *Client {
	hc := &http.Client{Timeout: 15 * time.Second}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), hc), cfg.Issuer+"/oauth/v2/keys")
	// go-oidc checks the signature (RS256 only: the alg allowlist), issuer, expiry and that
	// aud contains the project id. Verify adds the access-token checks it doesn't do.
	v := oidc.NewVerifier(cfg.Issuer, keys, &oidc.Config{ClientID: cfg.ProjectID, SupportedSigningAlgs: []string{oidc.RS256}})
	return &Client{cfg: cfg, http: hc, verifier: v}
}

// DriverConfig is what the conformance driver needs (served only in TEST_MODE).
func (c *Client) DriverConfig() map[string]any {
	return map[string]any{
		"idp": "zitadel", "issuer": c.cfg.Issuer, "clientId": c.cfg.ClientID, "projectId": c.cfg.ProjectID,
		"redirectUri": c.cfg.RedirectURI, "loginClientToken": c.cfg.LoginClientPAT,
	}
}

// accessClaims are the claims Verify reads beyond go-oidc's checks.
type accessClaims struct {
	ClientID string `json:"client_id"` // Zitadel access tokens name the client that got them
	Azp      string `json:"azp"`
	Nonce    string `json:"nonce"`
	AtHash   string `json:"at_hash"`
	// Organizations mode: the merchant org that granted the member role, and the user's org.
	Roles         map[string]map[string]string `json:"urn:zitadel:iam:org:project:roles"`
	ResourceOwner string                       `json:"urn:zitadel:iam:user:resourceowner:id"`
}

// Verify checks a bearer token (SPEC §14 P7): signature with an RS256-only allowlist,
// iss, aud (the project), exp (go-oidc); an access token, not an ID token (Zitadel's
// access tokens carry client_id and never at_hash/nonce); and the client that obtained it
// is one the API allows: the login app (users), or a machine user itself (apps, agents:
// client_credentials tokens name the machine's username as client_id; the app checks the
// subject maps to one of its apps or agents).
func (c *Client) Verify(ctx context.Context, bearer string) (identity.Token, error) {
	tok, err := c.verifier.Verify(ctx, bearer)
	if err != nil {
		return identity.Token{}, fmt.Errorf("%w: %v", identity.ErrInvalidToken, err)
	}
	var cl accessClaims
	if err := tok.Claims(&cl); err != nil {
		return identity.Token{}, fmt.Errorf("%w: claims: %v", identity.ErrInvalidToken, err)
	}
	if cl.ClientID == "" || cl.AtHash != "" || cl.Nonce != "" {
		return identity.Token{}, fmt.Errorf("%w: not an access token", identity.ErrInvalidToken)
	}
	if cl.ClientID != c.cfg.ClientID && !c.machineClient(cl.ClientID, tok.Subject) {
		return identity.Token{}, fmt.Errorf("%w: client %q not allowed", identity.ErrInvalidToken, cl.ClientID)
	}
	out := identity.Token{Subject: tok.Subject}
	if c.cfg.Orgs {
		out.MerchantID = c.tenantClaim(cl)
	}
	return out, nil
}

// machineClient: a client_credentials token, where the client is the machine user itself.
// Zitadel puts the machine's username in client_id; usernames this app creates are
// "<app or agent id>-<hex>" (CreateClient), never the login app's client id. The subject
// check (an app or agent row with this subject) happens in the app.
func (c *Client) machineClient(clientID, subject string) bool {
	return subject != "" && (strings.HasPrefix(clientID, "app_") || strings.HasPrefix(clientID, "ag_"))
}

// tenantClaim: the merchant a token speaks for, if it says so. Users: the org that granted
// the member role (absent in tokens from before they joined). Agents: their home org (a
// machine user lives in its merchant's org). Platform/people/customers orgs are no tenant.
func (c *Client) tenantClaim(cl accessClaims) string {
	for org := range cl.Roles[RoleMember] {
		return org
	}
	switch cl.ResourceOwner {
	case "", c.cfg.OrgID, c.cfg.PeopleOrgID, c.cfg.CustomersOrgID:
		return ""
	}
	return cl.ResourceOwner
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

func (c *Client) CreateUser(ctx context.Context, email, password, kind string) (string, error) {
	org := c.cfg.OrgID
	if c.cfg.Orgs {
		org = c.homeOrg(kind)
	}
	var out struct {
		ID string `json:"id"`
	}
	err := call(ctx, c.http, c.cfg.Issuer, c.cfg.AdminPAT, "POST", "/v2/users/new", map[string]any{
		"organizationId": org,
		"username":       email,
		"human": map[string]any{
			"profile":  map[string]any{"givenName": "Test", "familyName": "User"},
			"email":    map[string]any{"email": email, "isVerified": true},
			"password": map[string]any{"password": password, "changeRequired": false},
		},
	}, &out)
	if err != nil {
		return "", err
	}
	if c.cfg.Orgs {
		if err := c.grantAccount(ctx, out.ID); err != nil {
			return "", err
		}
	}
	return out.ID, nil
}

func (c *Client) CreateClient(ctx context.Context, name, merchantID string) (identity.Client, error) {
	username := name + "-" + randHex(4)
	org := c.cfg.OrgID
	agent := c.cfg.Orgs && merchantID != ""
	if agent {
		org = merchantID // an agent lives in its merchant's organization
	}
	var user struct {
		ID string `json:"id"`
	}
	if err := call(ctx, c.http, c.cfg.Issuer, c.cfg.AdminPAT, "POST", "/v2/users/new", map[string]any{
		"organizationId": org,
		"username":       username,
		"machine":        map[string]any{"name": name, "accessTokenType": "ACCESS_TOKEN_TYPE_JWT"},
	}, &user); err != nil {
		return identity.Client{}, err
	}
	if agent {
		// Disabled until the registration commits: the agent.registered outbox row enables it
		// (Apply). A rolled-back registration leaves an inert machine user, not a credential.
		if err := c.rpc(ctx, "zitadel.user.v2.UserService/DeactivateUser", map[string]any{"userId": user.ID}, nil); err != nil {
			return identity.Client{}, err
		}
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

// rpc calls a Zitadel v2 service over the Connect protocol (JSON), e.g.
// "zitadel.org.v2.OrganizationService/AddOrganization". Some v2 services have no REST path.
func (c *Client) rpc(ctx context.Context, method string, body, out any) error {
	return call(ctx, c.http, c.cfg.Issuer, c.cfg.AdminPAT, "POST", "/"+method, body, out)
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
		e := &APIError{Status: resp.StatusCode, Method: method, Path: path, Body: string(raw)}
		var cb struct {
			Code any `json:"code"`
		}
		if json.Unmarshal(raw, &cb) == nil {
			if s, ok := cb.Code.(string); ok {
				e.Code = s // Connect error code, e.g. already_exists
			}
		}
		return e
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
	Code         string // Connect code (rpc calls)
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zitadel %s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

// permanent: Zitadel will reject the same request on every retry. Narrow on purpose (the
// relay retries everything else forever, SPEC §1 operational rules): only malformed
// requests. not_found and failed_precondition can be projection lag; auth errors are config.
func (e *APIError) permanent() bool {
	return slices.Contains([]string{"invalid_argument", "unimplemented"}, e.Code)
}

func isCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

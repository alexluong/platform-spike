package zitadel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// BootstrapInput configures the idempotent Zitadel bootstrap.
type BootstrapInput struct {
	Issuer       string // external URL of Zitadel (reachable from the bootstrap container too)
	AdminPATFile string // written by Zitadel's first-instance setup (machine user, IAM owner)
	LoginPATFile string // written by Zitadel's first-instance setup (IAM_LOGIN_CLIENT)
	ProjectName  string
	AppName      string
	RedirectURI  string
	LoginBaseURI string // login v2 base URI configured on the app (never served; the driver stands in)
	// Orgs: organizations mode (stack a2): roles and login check on the project, role
	// claims in access tokens, home orgs for merchant users and customers.
	Orgs bool
}

// Bootstrap ensures the project and the PKCE OIDC app exist and returns the app config.
func Bootstrap(ctx context.Context, log *slog.Logger, in BootstrapInput) (Config, error) {
	hc := &http.Client{Timeout: 15 * time.Second}
	adminPAT, err := waitFile(ctx, in.AdminPATFile)
	if err != nil {
		return Config{}, err
	}
	loginPAT, err := waitFile(ctx, in.LoginPATFile)
	if err != nil {
		return Config{}, err
	}
	z := func(method, path string, body, out any) error {
		return call(ctx, hc, in.Issuer, adminPAT, method, path, body, out)
	}
	projectSettings := map[string]any{"name": in.ProjectName}
	if in.Orgs {
		// Check authorization on authentication: a human needs an active authorization on
		// the project to log in (how a suspended merchant's people are locked out), and
		// role claims (the member role names the merchant org) go into tokens.
		projectSettings["projectRoleAssertion"] = true
		projectSettings["projectRoleCheck"] = true
	}

	// Wait until the API answers with our PAT (projections may lag right after setup).
	var org struct {
		Org struct {
			ID string `json:"id"`
		} `json:"org"`
	}
	for i := 0; ; i++ {
		err = z("GET", "/management/v1/orgs/me", nil, &org)
		if err == nil && org.Org.ID != "" {
			break
		}
		if i > 120 {
			return Config{}, fmt.Errorf("zitadel not ready: %w", err)
		}
		log.Info("waiting for zitadel", "err", err)
		time.Sleep(2 * time.Second)
	}

	nameQuery := func(name string) map[string]any {
		return map[string]any{"queries": []any{map[string]any{"nameQuery": map[string]any{"name": name, "method": "TEXT_QUERY_METHOD_EQUALS"}}}}
	}

	var projects struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := z("POST", "/management/v1/projects/_search", nameQuery(in.ProjectName), &projects); err != nil {
		return Config{}, err
	}
	var projectID string
	if len(projects.Result) > 0 {
		projectID = projects.Result[0].ID
		if in.Orgs {
			// Re-runs: make sure the settings hold ("not changed" is fine).
			if err := z("PUT", "/management/v1/projects/"+projectID, projectSettings, nil); err != nil && !strings.Contains(err.Error(), "NotChanged") {
				return Config{}, err
			}
		}
	} else {
		var p struct {
			ID string `json:"id"`
		}
		if err := z("POST", "/management/v1/projects", projectSettings, &p); err != nil {
			return Config{}, err
		}
		projectID = p.ID
		log.Info("created project", "id", projectID)
	}
	if in.Orgs {
		for _, role := range []string{RoleAccount, RoleMember} {
			err := z("POST", "/management/v1/projects/"+projectID+"/roles", map[string]any{"roleKey": role, "displayName": role}, nil)
			if err != nil && !strings.Contains(err.Error(), "AlreadyExists") && !isStatus(err, http.StatusConflict) {
				return Config{}, err
			}
		}
	}

	var apps struct {
		Result []struct {
			OIDCConfig struct {
				ClientID string `json:"clientId"`
			} `json:"oidcConfig"`
		} `json:"result"`
	}
	if err := z("POST", "/management/v1/projects/"+projectID+"/apps/_search", nameQuery(in.AppName), &apps); err != nil {
		return Config{}, err
	}
	var clientID string
	if len(apps.Result) > 0 {
		clientID = apps.Result[0].OIDCConfig.ClientID
	} else {
		var a struct {
			ClientID string `json:"clientId"`
		}
		if err := z("POST", "/management/v1/projects/"+projectID+"/apps/oidc", map[string]any{
			"name":                     in.AppName,
			"redirectUris":             []string{in.RedirectURI},
			"responseTypes":            []string{"OIDC_RESPONSE_TYPE_CODE"},
			"grantTypes":               []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE"},
			"appType":                  "OIDC_APP_TYPE_USER_AGENT",
			"authMethodType":           "OIDC_AUTH_METHOD_TYPE_NONE", // public client + PKCE
			"accessTokenType":          "OIDC_TOKEN_TYPE_JWT",
			"devMode":                  true, // http redirect URI
			"version":                  "OIDC_VERSION_1_0",
			"accessTokenRoleAssertion": in.Orgs,
			"loginVersion":             map[string]any{"loginV2": map[string]any{"baseUri": in.LoginBaseURI}},
		}, &a); err != nil {
			return Config{}, err
		}
		clientID = a.ClientID
		log.Info("created oidc app", "clientId", clientID)
	}
	if clientID == "" {
		return Config{}, errors.New("no client id for oidc app")
	}
	cfg := Config{
		Issuer: in.Issuer, OrgID: org.Org.ID, ProjectID: projectID, ClientID: clientID,
		RedirectURI: in.RedirectURI, AdminPAT: adminPAT, LoginClientPAT: loginPAT,
	}
	if in.Orgs {
		// Home orgs for humans outside merchants (ids chosen here, so re-runs find them).
		c := &Client{cfg: Config{Issuer: in.Issuer, AdminPAT: adminPAT}, http: hc}
		for _, o := range []string{"people", "customers"} {
			err := c.rpc(ctx, "zitadel.org.v2.OrganizationService/AddOrganization", map[string]any{"name": o, "organizationId": o}, nil)
			if err != nil && !isCode(err, "already_exists") {
				return Config{}, err
			}
		}
		cfg.Orgs, cfg.PeopleOrgID, cfg.CustomersOrgID = true, "people", "customers"
	}
	return cfg, nil
}

func isStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

func waitFile(ctx context.Context, path string) (string, error) {
	for i := 0; i < 300; i++ {
		b, err := os.ReadFile(path)
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			return strings.TrimSpace(string(b)), nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return "", fmt.Errorf("timed out waiting for %s", path)
}

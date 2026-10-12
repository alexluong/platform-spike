package zitadel

// Organizations mode (IDP=zitadel-orgs, stack a2, SPEC §15): the IdP owns the merchant's
// identity side.
//
//   - Each merchant is a Zitadel organization whose id is the merchant id (created by the
//     merchant.created outbox event, so retries are idempotent). The platform project is
//     granted to it (project grant, role "member").
//   - A Zitadel user lives in exactly one organization and can't be moved. The spec's users
//     exist before they join a merchant (and the suite logs them in first), so human users
//     live in a home org by kind (platform staff: the platform org; customers: "customers";
//     merchant users: "people"), and membership is an authorization (user grant) on the
//     platform project in the merchant's organization: Zitadel's own model for users of one
//     org acting in another (B2B project grants).
//   - Login policy: the project has "check authorization on authentication"
//     (projectRoleCheck). Every human gets an "account" authorization from the platform org
//     at creation. Suspending a merchant deactivates its organization (blocks its agents,
//     which are machine users inside it) and every authorization of its members (blocks
//     their login: Zitadel does not cascade an org's deactivation to grants it handed out).
//   - The identity sync below applies outbox events (second consumer, partitioned per
//     merchant). Same retry rules as the engine: transient errors are retried forever,
//     only requests Zitadel will never accept are permanent.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alexluong/platform-spike/go/internal/authz"
)

// Role keys on the platform project. They are login entitlements and the tenant claim,
// not §3 roles: permissions stay in the app DB and the engine.
const (
	RoleAccount = "account" // granted by the platform org to every human: may sign in
	RoleMember  = "member"  // granted by a merchant's org to its members
)

// SyncsEvent: the outbox events the identity sync consumes.
func SyncsEvent(t string) bool {
	switch t {
	case authz.EvMerchantCreated, authz.EvMerchantSuspended, authz.EvMerchantReinstated,
		authz.EvMemberAdded, authz.EvMemberRemoved, authz.EvAgentRegistered:
		return true
	}
	return false
}

// homeOrg: where a human of this kind lives.
func (c *Client) homeOrg(kind string) string {
	switch kind {
	case "customer":
		return c.cfg.CustomersOrgID
	case "user":
		return c.cfg.PeopleOrgID
	}
	return c.cfg.OrgID // platform staff
}

// Apply is the identity sync (outbox consumer "identity"). Re-applying an event is a no-op.
func (c *Client) Apply(ctx context.Context, ev authz.Event) error {
	if !c.cfg.Orgs {
		return nil
	}
	err := c.apply(ctx, ev)
	var ae *APIError
	if errors.As(err, &ae) && ae.permanent() {
		return fmt.Errorf("%w: %w", authz.ErrPermanent, err)
	}
	return err
}

func (c *Client) apply(ctx context.Context, ev authz.Event) error {
	mid := ev.MerchantID
	switch ev.Type {
	case authz.EvMerchantCreated:
		err := c.rpc(ctx, "zitadel.org.v2.OrganizationService/AddOrganization",
			map[string]any{"name": "merchant " + mid, "organizationId": mid}, nil)
		if err != nil && !isCode(err, "already_exists") {
			return err
		}
		err = c.rpc(ctx, "zitadel.project.v2.ProjectService/CreateProjectGrant",
			map[string]any{"projectId": c.cfg.ProjectID, "grantedOrganizationId": mid, "roleKeys": []string{RoleMember}}, nil)
		if err != nil && !isCode(err, "already_exists") {
			return err
		}
		return nil

	case authz.EvMemberAdded:
		// Right after merchant.created the project grant may not be in Zitadel's projection
		// yet (Errors.Project.Grant.NotFound): retry briefly here before failing the row.
		return retryLag(ctx, func() error {
			err := c.rpc(ctx, "zitadel.authorization.v2.AuthorizationService/CreateAuthorization",
				map[string]any{"userId": ev.Subject, "projectId": c.cfg.ProjectID, "organizationId": mid, "roleKeys": []string{RoleMember}}, nil)
			if err != nil && !isCode(err, "already_exists") {
				return err
			}
			return nil
		})

	case authz.EvMemberRemoved:
		mine, err := c.authorizations(ctx, []string{ev.Subject}, mid)
		if err != nil {
			return err
		}
		for _, a := range mine {
			if err := c.rpc(ctx, "zitadel.authorization.v2.AuthorizationService/DeleteAuthorization", map[string]any{"id": a.ID}, nil); err != nil && !isCode(err, "not_found") {
				return err
			}
		}
		// Removed while suspended can't happen through the API (the merchant's people are
		// locked out), but if it did, the account authorization must come back.
		return c.setUsersActive(ctx, []string{ev.Subject}, c.cfg.OrgID, true)

	case authz.EvMerchantSuspended, authz.EvMerchantReinstated:
		active := ev.Type == authz.EvMerchantReinstated
		method := "DeactivateOrganization"
		if active {
			method = "ActivateOrganization"
		}
		if err := c.rpc(ctx, "zitadel.org.v2.OrganizationService/"+method, map[string]any{"organizationId": mid}, nil); err != nil && !isCode(err, "failed_precondition") {
			return err // failed_precondition: already in that state
		}
		// Token issuance reads the org's state twice: the event store (immediate) and the
		// userinfo projection (lags). Wait for the projection so the next login sees it.
		if err := c.waitOrgState(ctx, mid, active); err != nil {
			return err
		}
		members, err := c.authorizations(ctx, nil, mid)
		if err != nil {
			return err
		}
		var users []string
		for _, a := range members {
			users = append(users, a.User.ID)
		}
		// Every authorization of the members on the project (theirs from the merchant org
		// and their account authorization from the platform org).
		return c.setUsersActive(ctx, users, "", active)

	case authz.EvAgentRegistered:
		// The machine user was created deactivated; the committed registration enables it.
		err := c.rpc(ctx, "zitadel.user.v2.UserService/ReactivateUser", map[string]any{"userId": ev.Subject}, nil)
		if err != nil && !isCode(err, "failed_precondition") { // already active
			return err
		}
		// Token issuance needs the user active in the projection too (else "User.NotFound").
		return c.waitUserActive(ctx, ev.Subject)
	}
	return nil
}

type authorization struct {
	ID    string `json:"id"`
	State string `json:"state"`
	User  struct {
		ID string `json:"id"`
	} `json:"user"`
	Organization struct {
		ID string `json:"id"`
	} `json:"organization"`
}

// authorizations on the platform project, filtered by users (nil = any) and org ("" = any).
func (c *Client) authorizations(ctx context.Context, users []string, org string) ([]authorization, error) {
	filters := []any{map[string]any{"projectId": map[string]any{"id": c.cfg.ProjectID}}}
	if org != "" {
		filters = append(filters, map[string]any{"organizationId": map[string]any{"id": org}})
	}
	if users != nil {
		if len(users) == 0 {
			return nil, nil
		}
		filters = append(filters, map[string]any{"inUserIds": map[string]any{"ids": users}})
	}
	var out struct {
		Authorizations []authorization `json:"authorizations"`
	}
	err := c.rpc(ctx, "zitadel.authorization.v2.AuthorizationService/ListAuthorizations",
		map[string]any{"pagination": map[string]any{"limit": 1000}, "filters": filters}, &out)
	return out.Authorizations, err
}

// setUsersActive (de)activates the users' authorizations on the project (in org, "" = any),
// then waits until Zitadel's projection shows it: the login check ("check authorization on
// authentication") reads that projection, so the change must be visible before the
// request that caused it answers (read-your-writes for login).
func (c *Client) setUsersActive(ctx context.Context, users []string, org string, active bool) error {
	if len(users) == 0 {
		return nil
	}
	want, method := "STATE_INACTIVE", "DeactivateAuthorization"
	if active {
		want, method = "STATE_ACTIVE", "ActivateAuthorization"
	}
	as, err := c.authorizations(ctx, users, org)
	if err != nil {
		return err
	}
	for _, a := range as {
		if a.State == want {
			continue
		}
		err := c.rpc(ctx, "zitadel.authorization.v2.AuthorizationService/"+method, map[string]any{"id": a.ID}, nil)
		if err != nil && !isCode(err, "failed_precondition") && !isCode(err, "not_found") {
			return err
		}
	}
	return c.waitAuthorizations(ctx, users, org, func(as []authorization) bool {
		for _, a := range as {
			if a.State != want {
				return false
			}
		}
		return true
	})
}

// waitAuthorizations polls the projection until ok holds (transient error after 10 s).
func (c *Client) waitAuthorizations(ctx context.Context, users []string, org string, ok func([]authorization) bool) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		as, err := c.authorizations(ctx, users, org)
		if err == nil && ok(as) {
			return nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = errors.New("zitadel: authorization projection did not catch up in 10s")
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// grantAccount gives a new human the platform org's account authorization and waits until
// the login check can see it (the driver logs in right after creating the user).
func (c *Client) grantAccount(ctx context.Context, userID string) error {
	err := c.rpc(ctx, "zitadel.authorization.v2.AuthorizationService/CreateAuthorization",
		map[string]any{"userId": userID, "projectId": c.cfg.ProjectID, "organizationId": c.cfg.OrgID, "roleKeys": []string{RoleAccount}}, nil)
	if err != nil && !isCode(err, "already_exists") {
		return err
	}
	return c.waitAuthorizations(ctx, []string{userID}, c.cfg.OrgID, func(as []authorization) bool {
		for _, a := range as {
			if a.State == "STATE_ACTIVE" {
				return true
			}
		}
		return false
	})
}

// retryLag retries f for up to 5 s while Zitadel answers not_found/failed_precondition
// (its projections lag its writes).
func retryLag(ctx context.Context, f func() error) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := f()
		if err == nil || !(isCode(err, "not_found") || isCode(err, "failed_precondition")) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// waitOrgState polls the org projection until the org is (in)active (10 s, then transient).
func (c *Client) waitOrgState(ctx context.Context, org string, active bool) error {
	want := "ORGANIZATION_STATE_INACTIVE"
	if active {
		want = "ORGANIZATION_STATE_ACTIVE"
	}
	return poll(ctx, "org "+org+" "+want, func() (bool, error) {
		var out struct {
			Result []struct {
				State string `json:"state"`
			} `json:"result"`
		}
		err := c.rpc(ctx, "zitadel.org.v2.OrganizationService/ListOrganizations",
			map[string]any{"queries": []any{map[string]any{"idQuery": map[string]any{"id": org}}}}, &out)
		return err == nil && len(out.Result) == 1 && out.Result[0].State == want, err
	})
}

// waitUserActive polls the user projection until the user is active.
func (c *Client) waitUserActive(ctx context.Context, userID string) error {
	return poll(ctx, "user "+userID+" active", func() (bool, error) {
		var out struct {
			User struct {
				State string `json:"state"`
			} `json:"user"`
		}
		err := c.rpc(ctx, "zitadel.user.v2.UserService/GetUserByID", map[string]any{"userId": userID}, &out)
		return err == nil && out.User.State == "USER_STATE_ACTIVE", err
	})
}

func poll(ctx context.Context, what string, f func() (bool, error)) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		ok, err := f()
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = fmt.Errorf("zitadel: projection did not catch up in 10s (%s)", what)
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

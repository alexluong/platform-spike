// Package identity is the identity port: validate a bearer token into an
// IdP subject, and provision identities (test-mode users, machine clients for
// apps and agents). IdPs (Zitadel, Ory, ...) are adapters behind it.
package identity

import (
	"context"
	"errors"
)

// ErrInvalidToken means the token is missing, malformed, expired or not ours.
var ErrInvalidToken = errors.New("invalid token")

// ErrNotSupported: the adapter doesn't implement this operation (yet).
var ErrNotSupported = errors.New("not supported by this identity adapter")

// Token is what a valid bearer token tells us. The app maps Subject to its own principal.
type Token struct {
	Subject string
	// MerchantID is the tenant the IdP put in the token (an organization claim), when it
	// carries one. An extra tenant check only: membership still comes from the app's records
	// (SPEC §2, §15.1). Empty for IdPs without tenancy and for tokens without the claim.
	// Adapters with a pool per merchant (SPEC §16: h2, i) set it to the merchant of the pool that
	// issued the token (from their directory, never a claim); the Authenticator then requires it
	// for principals of a merchant's own pool (HomeMerchantID), so it is load-bearing there.
	MerchantID string
}

// Verifier validates bearer tokens.
type Verifier interface {
	Verify(ctx context.Context, bearer string) (Token, error)
}

// Client is a machine client (client credentials) created in the IdP.
type Client struct {
	Subject      string // the `sub` its tokens will carry
	ClientID     string
	ClientSecret string
}

// Provisioner creates identities in the IdP.
type Provisioner interface {
	// CreateUser creates a password user (test mode only) and returns its subject.
	// kind is the principal kind (platform | user | customer): IdPs with tenancy place
	// the identity by it (platform staff, customers and merchant users live apart).
	CreateUser(ctx context.Context, email, password, kind string) (subject string, err error)
	// CreateClient creates a machine client for an app (merchantID "") or an agent of
	// merchantID. IdPs with tenancy create an agent's client inside the merchant's tenant
	// and may keep it disabled until the agent.registered outbox event is applied (so a
	// rolled-back registration leaves no usable credential).
	CreateClient(ctx context.Context, name, merchantID string) (Client, error)
	// DeleteClient removes a machine client (by ClientID): its secret stops minting tokens.
	// An adapter that shares the app's DB does it in the caller's transaction (ctx).
	DeleteClient(ctx context.Context, clientID string) error
}

// ErrNotFound: the adapter has no such merchant, user or pool.
var ErrNotFound = errors.New("identity: not found")

// TenantPools is implemented by identity adapters with one user pool per merchant (SPEC §16:
// stacks h2 and i). Writes join the caller's transaction when the adapter shares the app's DB
// (ctx carries it); adapters with an external IdP do the slow work from the outbox instead.
type TenantPools interface {
	// ProvisionMerchant is called in the merchant-create transaction. ready: the pool is usable
	// at commit (h2: rows in the same transaction). Not ready: the adapter provisions it later
	// (i: from the merchant.created outbox row) and reports readiness through the app's hook
	// (platform.MarkPoolReady); the merchant shows "provisioning" meanwhile.
	ProvisionMerchant(ctx context.Context, merchantID string) (ready bool, err error)
	// SetMerchantSuspended makes the merchant's pool refuse (or accept again) logins, in the
	// suspend/reinstate transaction. Adapters that do it from the outbox (i) return nil.
	SetMerchantSuspended(ctx context.Context, merchantID string, suspended bool) error
	// PoolIdentity: what a storefront or admin UI needs to start a login at the merchant's pool
	// (GET /api/merchants/:mid/identity); at least {"issuer"}. ErrNotFound when it has none yet.
	PoolIdentity(ctx context.Context, merchantID string) (map[string]any, error)
	// CreateTenantUser creates a password identity in the merchant's pool: kind user = its staff,
	// customer = its customers. Returns the subject its tokens map to (test mode only).
	CreateTenantUser(ctx context.Context, merchantID, email, password, kind string) (subject string, err error)
}

// ShopLinker is the app's hook for "Sign in with Shop" (SPEC §16.5): after a Shop account
// (shopSubject) signs in at a merchant, link the merchant's customer record to the tenant
// identity (tenantSubject). Called by the adapter inside its transaction (ctx carries it).
type ShopLinker func(ctx context.Context, merchantID, shopSubject, tenantSubject string) error

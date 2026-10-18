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

// Pools is implemented by IdPs that keep one user pool per merchant (SPEC §16: its own staff
// and customers). Optional: stacks with one pool for everyone don't have it.
type Pools interface {
	// CreatePoolUser creates a password identity in merchantID's pool (test mode only).
	// kind is "user" (the merchant's staff) or "customer" (its customers).
	CreatePoolUser(ctx context.Context, merchantID, email, password, kind string) (subject string, err error)
	// PoolIdentity: what a login UI needs to start a login at the merchant's pool; at least
	// {"issuer"}. Errors when the merchant has no pool.
	PoolIdentity(ctx context.Context, merchantID string) (map[string]any, error)
}

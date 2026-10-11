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

// Token is what a valid bearer token tells us. The app maps Subject to its own principal.
type Token struct {
	Subject string
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
	CreateUser(ctx context.Context, email, password string) (subject string, err error)
	// CreateClient creates a machine client for an app or agent.
	CreateClient(ctx context.Context, name string) (Client, error)
}

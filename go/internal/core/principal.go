package core

import (
	"context"
	"errors"
	"strings"

	"github.com/alexluong/platform-spike/go/internal/identity"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Principal is the authenticated caller, resolved from the IdP subject to the app's own records.
type Principal struct {
	ID           string
	Kind         perm.Kind
	MerchantID   string // users (when a member) and agents
	PlatformRole string // platform_admin | support
	OwnerUserID  string // agents: the user who registered it
}

// Authenticator turns a bearer token into a Principal: identity port + app DB.
type Authenticator struct {
	Verifier identity.Verifier
	DB       *pgxpool.Pool
}

func (a *Authenticator) Authenticate(ctx context.Context, header string) (*Principal, error) {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || tok == "" {
		return nil, ErrUnauthenticated
	}
	t, err := a.Verifier.Verify(ctx, tok)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return LookupPrincipal(ctx, a.DB, t.Subject)
}

// LookupPrincipal finds the user, app or agent whose IdP subject is sub.
func LookupPrincipal(ctx context.Context, db *pgxpool.Pool, sub string) (*Principal, error) {
	var p Principal
	var kind string
	var merchant, role *string
	err := db.QueryRow(ctx, `SELECT id, kind, merchant_id, platform_role FROM users WHERE idp_subject=$1`, sub).
		Scan(&p.ID, &kind, &merchant, &role)
	if err == nil {
		p.Kind = perm.Kind(kind)
		p.MerchantID = deref(merchant)
		p.PlatformRole = deref(role)
		return &p, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	err = db.QueryRow(ctx, `SELECT id FROM apps WHERE idp_subject=$1`, sub).Scan(&p.ID)
	if err == nil {
		p.Kind = perm.KindApp
		return &p, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	err = db.QueryRow(ctx, `SELECT id, merchant_id, owner_user_id FROM agents WHERE idp_subject=$1`, sub).
		Scan(&p.ID, &p.MerchantID, &p.OwnerUserID)
	if err == nil {
		p.Kind = perm.KindAgent
		return &p, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return nil, ErrUnauthenticated // valid token, unknown to the app
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

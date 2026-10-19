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
	MerchantID   string // agents; users with exactly one membership
	PlatformRole string // platform_admin | support
	OwnerUserID  string // agents: the user who registered it
	// MerchantIDs: a user's memberships (SPEC §16.2: a platform account may be a member of
	// several merchants).
	MerchantIDs []string
	// HomeMerchantID: the merchant whose own pool holds this principal (its tenant customers,
	// SPEC §16.1; staff are platform accounts). "" for platform-level principals.
	HomeMerchantID string
	// ShopAccountID: a merchant's customer record linked to this Shop account (SPEC §16.5).
	ShopAccountID string
}

// MemberOf: users are checked against their memberships, agents against their merchant.
func (p *Principal) MemberOf(merchantID string) bool {
	if p.MerchantID == merchantID {
		return merchantID != ""
	}
	if p.Kind == perm.KindAgent {
		return false
	}
	for _, m := range p.MerchantIDs {
		if m == merchantID {
			return true
		}
	}
	return false
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
	p, err := LookupPrincipal(ctx, a.DB, t.Subject)
	if err != nil {
		return nil, err
	}
	if !tokenFits(t, p) {
		return nil, ErrUnauthenticated
	}
	return p, nil
}

// tokenFits: the token's tenant (if any) agrees with the principal.
//   - A principal of a merchant's own pool (HomeMerchantID, SPEC §16.1) is accepted only with
//     a token of that merchant's pool: pool-per-merchant adapters (h2, i) put the pool's
//     merchant in t.MerchantID (from their directory, never a claim).
//   - A tenant claim in the token (IdPs with organizations) is an extra check, never the
//     source: membership comes from the app's records. A token minted for a merchant the
//     caller doesn't belong to now is stale: log in again. No claim, no check (tokens from
//     before the user joined, IdPs without tenancy).
func tokenFits(t identity.Token, p *Principal) bool {
	if p.HomeMerchantID != "" && t.MerchantID != p.HomeMerchantID {
		return false
	}
	if t.MerchantID != "" && p.HomeMerchantID == "" && (p.MerchantID != "" || len(p.MerchantIDs) > 0) && !p.MemberOf(t.MerchantID) {
		return false
	}
	return true
}

// LookupPrincipal finds the user, app or agent whose IdP subject is sub.
func LookupPrincipal(ctx context.Context, db *pgxpool.Pool, sub string) (*Principal, error) {
	var p Principal
	var kind string
	var home, role, shop *string
	err := db.QueryRow(ctx, `SELECT u.id, u.kind, u.home_merchant_id, u.platform_role, u.shop_account_id,
			coalesce((SELECT array_agg(m.merchant_id ORDER BY m.merchant_id) FROM memberships m WHERE m.user_id = u.id), '{}')
		FROM users u WHERE u.idp_subject=$1`, sub).
		Scan(&p.ID, &kind, &home, &role, &shop, &p.MerchantIDs)
	if err == nil {
		p.Kind = perm.Kind(kind)
		p.HomeMerchantID = deref(home)
		p.PlatformRole = deref(role)
		p.ShopAccountID = deref(shop)
		if len(p.MerchantIDs) == 1 {
			p.MerchantID = p.MerchantIDs[0]
		}
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

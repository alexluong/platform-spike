// Package customers: a merchant's customer records linked to Shop accounts (SPEC §16.5).
// A Shop buyer is a platform-level customer; at each merchant it becomes a customer record
// of that merchant (pool m:<merchant>, home_merchant_id), linked by shop_account_id. The record
// is created by the buyer's first Shop order there or by the first "Sign in with Shop" there,
// whichever comes first; the sign-in attaches the merchant pool's identity (idp_subject) to it.
// No IdP knowledge here: the identity side calls LinkShop with opaque subjects.
package customers

import (
	"context"
	"errors"
	"fmt"

	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is what these helpers need from a pool or a transaction.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ErrUnknownShopAccount: the upstream identity is not a Shop account the app knows.
var ErrUnknownShopAccount = errors.New("unknown shop account")

// Linked returns the id of merchantID's customer record linked to shopAccountID, creating it
// on first use.
func Linked(ctx context.Context, q Querier, merchantID, shopAccountID string) (string, error) {
	if _, err := q.Exec(ctx, `INSERT INTO users(id, kind, pool, home_merchant_id, shop_account_id)
		VALUES ($1,'customer',$2,$3,$4) ON CONFLICT (home_merchant_id, shop_account_id) WHERE shop_account_id IS NOT NULL DO NOTHING`,
		db.NewID("u"), "m:"+merchantID, merchantID, shopAccountID); err != nil {
		return "", err
	}
	var id string
	err := q.QueryRow(ctx, `SELECT id FROM users WHERE home_merchant_id=$1 AND shop_account_id=$2`, merchantID, shopAccountID).Scan(&id)
	return id, err
}

// LinkShop: an identity of merchantID's pool (tenantSubject) signed in with the Shop account
// whose platform-level identity is shopSubject. Attaches tenantSubject to the linked customer
// record (created if no Shop order came first). Idempotent; returns the record id.
func LinkShop(ctx context.Context, q Querier, merchantID, shopSubject, tenantSubject string) (string, error) {
	var shopID string
	err := q.QueryRow(ctx, `SELECT id FROM users WHERE idp_subject=$1 AND kind='customer' AND home_merchant_id IS NULL`, shopSubject).Scan(&shopID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUnknownShopAccount
	} else if err != nil {
		return "", err
	}
	id, err := Linked(ctx, q, merchantID, shopID)
	if err != nil {
		return "", err
	}
	var cur *string
	if err := q.QueryRow(ctx, `UPDATE users SET idp_subject=coalesce(idp_subject, $2) WHERE id=$1 RETURNING idp_subject`, id, tenantSubject).Scan(&cur); err != nil {
		return "", err
	}
	if cur == nil || *cur != tenantSubject {
		return "", fmt.Errorf("customer %s is linked to another identity of merchant %s", id, merchantID)
	}
	return id, nil
}

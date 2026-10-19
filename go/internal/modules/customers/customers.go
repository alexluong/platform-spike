// Package customers: a merchant's customer records and their links to Shop accounts (SPEC
// §16.5). A Shop account (a platform-level customer) becomes a customer of each merchant it
// buys from or signs in at: one record per (merchant, Shop account), created on first use.
// The merchant sees its own record; only the Shop account sees across merchants.
package customers

import (
	"context"
	"errors"

	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureShopCustomer returns merchant mid's customer record linked to Shop account shopUserID,
// creating it (no identity yet: idp_subject stays NULL until the buyer signs in with Shop there).
func EnsureShopCustomer(ctx context.Context, q db.Querier, mid, shopUserID string) (string, error) {
	if _, err := q.Exec(ctx, `INSERT INTO users(id, kind, home_merchant_id, shop_account_id) VALUES ($1,$2,$3,$4)
		ON CONFLICT (home_merchant_id, shop_account_id) WHERE shop_account_id IS NOT NULL DO NOTHING`,
		db.NewID("u"), string(perm.KindCustomer), mid, shopUserID); err != nil {
		return "", err
	}
	var id string
	err := q.QueryRow(ctx, `SELECT id FROM users WHERE home_merchant_id=$1 AND shop_account_id=$2`, mid, shopUserID).Scan(&id)
	return id, err
}

var ErrNoShopAccount = errors.New("customers: no Shop account for that identity")

// ShopLinker is the identity adapter's hook after "Sign in with Shop" at merchant mid: the
// merchant's record linked to the Shop account gets the tenant identity (in the adapter's
// transaction, which ctx carries). Same record as the one Shop-token orders created.
func ShopLinker(pool *pgxpool.Pool) identity.ShopLinker {
	return func(ctx context.Context, mid, shopSubject, tenantSubject string) error {
		q := db.TxOr(ctx, pool)
		var shopUser string
		err := q.QueryRow(ctx, `SELECT id FROM users WHERE idp_subject=$1 AND kind='customer' AND home_merchant_id IS NULL`, shopSubject).Scan(&shopUser)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoShopAccount
		} else if err != nil {
			return err
		}
		rec, err := EnsureShopCustomer(ctx, q, mid, shopUser)
		if err != nil {
			return err
		}
		tag, err := q.Exec(ctx, `UPDATE users SET idp_subject=$2 WHERE id=$1 AND (idp_subject IS NULL OR idp_subject=$2)`, rec, tenantSubject)
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("customers: record already linked to another identity")
		}
		return err
	}
}

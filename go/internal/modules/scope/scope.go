// Package scope resolves path ids to check targets (the scope resource and its
// merchant), shared by the store-level modules. Lookups are plain SQL.
package scope

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/jackc/pgx/v5"
)

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ErrNotFound
	}
	return err
}

// Merchant resolves a merchant id.
func Merchant(ctx context.Context, q core.Querier, mid string) (core.Target, error) {
	var x string
	if err := q.QueryRow(ctx, `SELECT id FROM merchants WHERE id=$1`, mid).Scan(&x); err != nil {
		return core.Target{}, notFound(err)
	}
	return core.MerchantTarget(mid), nil
}

// Store resolves a store id.
func Store(ctx context.Context, q core.Querier, sid string) (core.Target, error) {
	var mid string
	if err := q.QueryRow(ctx, `SELECT merchant_id FROM stores WHERE id=$1`, sid).Scan(&mid); err != nil {
		return core.Target{}, notFound(err)
	}
	return core.StoreTarget(sid, mid, nil), nil
}

// Item is an order line.
type Item struct {
	ProductID      string `json:"productId"`
	Qty            int64  `json:"qty"`
	UnitPriceCents int64  `json:"unitPriceCents"`
}

// Order is the order row (SPEC §8).
type Order struct {
	ID            string `json:"id"`
	StoreID       string `json:"storeId"`
	CustomerID    string `json:"customerId"`
	Items         []Item `json:"items"`
	TotalCents    int64  `json:"totalCents"`
	Status        string `json:"status"`
	RefundedCents int64  `json:"refundedCents"`
	MerchantID    string `json:"-"`
	// MerchantCustomerID: the merchant's customer record the order belongs to (SPEC §16.5): the
	// placing customer, or for a Shop-token order the merchant's record linked to that account.
	MerchantCustomerID string `json:"-"`
}

const OrderCols = `id, store_id, customer_id, items, total_cents, status, refunded_cents, merchant_id, coalesce(merchant_customer_id, '')`

// ScanOrder scans OrderCols.
func ScanOrder(row pgx.Row) (*Order, error) {
	var o Order
	var items []byte
	if err := row.Scan(&o.ID, &o.StoreID, &o.CustomerID, &items, &o.TotalCents, &o.Status, &o.RefundedCents, &o.MerchantID, &o.MerchantCustomerID); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(items, &o.Items); err != nil {
		return nil, err
	}
	return &o, nil
}

// OrderTarget resolves an order id to its store (locks the row for the request's tx).
func OrderTarget(ctx context.Context, q core.Querier, oid string) (core.Target, error) {
	o, err := ScanOrder(q.QueryRow(ctx, `SELECT `+OrderCols+` FROM orders WHERE id=$1 FOR UPDATE`, oid))
	if err != nil {
		return core.Target{}, notFound(err)
	}
	return core.StoreTarget(o.StoreID, o.MerchantID, o), nil
}

// OrderOf returns the order loaded by OrderTarget.
func OrderOf(r *core.Req) *Order { return r.Target.Data.(*Order) }

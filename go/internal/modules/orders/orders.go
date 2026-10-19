// Package orders: customer orders, cancel, refund. Customers are never in the
// authz engine: their checks are SQL (customer_id = me).
package orders

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/modules/customers"
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
)

type Module struct {
	// ShopLinks (SPEC §16.5, multi-pool stacks): a platform-level customer (Shop account) orders
	// at a merchant as that merchant's customer record linked to it; its history spans them.
	// Off: every customer is its own merchant customer record.
	ShopLinks bool
}

var errInvalidTransition = core.Conflict("invalid_transition")

const maxQty = 1_000_000

// mulAdd returns total + price*qty, or false if it overflows int64 (all inputs >= 0).
func mulAdd(total, price, qty int64) (int64, bool) {
	if price != 0 && qty > (math.MaxInt64-total)/price {
		return 0, false
	}
	return total + price*qty, true
}

func storeTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	return scope.Store(ctx, r.Tx, r.Path("sid"))
}

func orderTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	return scope.OrderTarget(ctx, r.Tx, r.Path("oid"))
}

type refundIn struct {
	AmountCents int64 `json:"amountCents"`
}

func refundContext(r *core.Req) (map[string]any, error) {
	var in refundIn
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if in.AmountCents <= 0 {
		return nil, core.BadInput("amountCents must be > 0")
	}
	return map[string]any{authz.CtxAmountCents: in.AmountCents}, nil
}

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Auth: core.AuthAny, Method: "POST", Path: "/api/stores/{sid}/orders", Status: 201, Target: storeTarget, Run: m.place},
		{Action: "order.view", Method: "GET", Path: "/api/stores/{sid}/orders", Target: storeTarget, Run: m.listStore},
		{Action: "order.view", Method: "GET", Path: "/api/orders/{oid}", CustomerAlt: true, Target: orderTarget, Run: m.get},
		{Auth: core.AuthAny, Method: "GET", Path: "/api/me/orders", Run: m.mine},
		{Action: "order.cancel", Method: "POST", Path: "/api/orders/{oid}/cancel", Target: orderTarget, Run: m.cancel},
		{Action: "order.refund", Method: "POST", Path: "/api/orders/{oid}/refund", Target: orderTarget, Context: refundContext, Run: m.refund},
	}
}

// place: order.place, a customer action checked in SQL (SPEC §4).
func (m *Module) place(ctx context.Context, r *core.Req) (any, error) {
	if r.P.Kind != perm.KindCustomer {
		return nil, core.ErrForbidden
	}
	// A merchant's own customer (tenant pool, SPEC §16.1) orders at that merchant's stores only.
	if r.P.HomeMerchantID != "" && r.P.HomeMerchantID != r.Target.MerchantID {
		return nil, core.ErrForbidden
	}
	var status string
	if err := r.Tx.QueryRow(ctx, `SELECT status FROM merchants WHERE id=$1`, r.Target.MerchantID).Scan(&status); err != nil {
		return nil, err
	}
	if status == "suspended" {
		return nil, core.ErrMerchantSuspended
	}
	// The order belongs to the merchant's customer record: the caller itself, or for a Shop
	// account the merchant's record linked to it, created on its first order (SPEC §16.5).
	merchantCustomer := r.P.ID
	if m.ShopLinks && r.P.HomeMerchantID == "" {
		var err error
		if merchantCustomer, err = customers.EnsureShopCustomer(ctx, r.Tx, r.Target.MerchantID, r.P.ID); err != nil {
			return nil, err
		}
	}
	var in struct {
		Items []struct {
			ProductID string `json:"productId"`
			Qty       int64  `json:"qty"`
		} `json:"items"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if len(in.Items) == 0 {
		return nil, core.BadInput("items are required")
	}
	o := scope.Order{ID: db.NewID("o"), StoreID: r.Target.Resource.ID, CustomerID: r.P.ID, Status: "pending", Items: []scope.Item{}}
	for _, it := range in.Items {
		if it.Qty <= 0 || it.Qty > maxQty {
			return nil, core.BadInput("qty must be 1..1000000")
		}
		var price int64
		err := r.Tx.QueryRow(ctx, `SELECT price_cents FROM products WHERE id=$1 AND store_id=$2`, it.ProductID, o.StoreID).Scan(&price)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.E(http.StatusBadRequest, "invalid_input", "unknown product "+it.ProductID)
		} else if err != nil {
			return nil, err
		}
		line, ok := mulAdd(o.TotalCents, price, it.Qty)
		if !ok || line > core.MaxCents {
			return nil, core.BadInput("order total too large")
		}
		o.Items = append(o.Items, scope.Item{ProductID: it.ProductID, Qty: it.Qty, UnitPriceCents: price})
		o.TotalCents = line
	}
	items, _ := json.Marshal(o.Items)
	_, err := r.Tx.Exec(ctx, `INSERT INTO orders(id, merchant_id, store_id, customer_id, items, total_cents, status, merchant_customer_id) VALUES ($1,$2,$3,$4,$5,$6,'pending',$7)`,
		o.ID, r.Target.MerchantID, o.StoreID, o.CustomerID, items, o.TotalCents, merchantCustomer)
	return o, err
}

func collect(rows pgx.Rows, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []*scope.Order{}
	for rows.Next() {
		o, err := scope.ScanOrder(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, o)
	}
	return map[string]any{"items": items}, rows.Err()
}

func (m *Module) listStore(ctx context.Context, r *core.Req) (any, error) {
	return collect(r.Tx.Query(ctx, `SELECT `+scope.OrderCols+` FROM orders WHERE store_id=$1 AND merchant_id=$2 ORDER BY created_at`,
		r.Target.Resource.ID, r.Target.MerchantID))
}

func (m *Module) get(ctx context.Context, r *core.Req) (any, error) {
	o := scope.OrderOf(r)
	if r.P.Kind == perm.KindCustomer {
		mine := o.CustomerID == r.P.ID || o.MerchantCustomerID == r.P.ID
		if !mine && m.ShopLinks && r.P.HomeMerchantID == "" && o.MerchantCustomerID != "" {
			// a Shop account sees its orders at every merchant, through the linked records
			if err := r.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND shop_account_id=$2)`, o.MerchantCustomerID, r.P.ID).Scan(&mine); err != nil {
				return nil, err
			}
		}
		if !mine {
			return nil, core.ErrNotFound // order.view_own
		}
	}
	return o, nil
}

func (m *Module) mine(ctx context.Context, r *core.Req) (any, error) {
	if r.P.Kind != perm.KindCustomer {
		return nil, core.ErrForbidden
	}
	if !m.ShopLinks {
		return collect(r.Tx.Query(ctx, `SELECT `+scope.OrderCols+` FROM orders WHERE customer_id=$1 ORDER BY created_at`, r.P.ID))
	}
	if r.P.HomeMerchantID != "" {
		// a merchant's own customer: that merchant's orders of its record (incl. Shop-token orders
		// there when the record is linked to a Shop account)
		return collect(r.Tx.Query(ctx, `SELECT `+scope.OrderCols+` FROM orders WHERE merchant_customer_id=$1 ORDER BY created_at`, r.P.ID))
	}
	// a Shop account: its own orders and every linked record's, at every merchant
	return collect(r.Tx.Query(ctx, `SELECT `+scope.OrderCols+` FROM orders WHERE customer_id=$1
		OR merchant_customer_id IN (SELECT id FROM users WHERE shop_account_id=$1) ORDER BY created_at`, r.P.ID))
}

func (m *Module) cancel(ctx context.Context, r *core.Req) (any, error) {
	o := scope.OrderOf(r)
	if o.Status != "pending" && o.Status != "paid" {
		return nil, errInvalidTransition
	}
	var shipped bool
	if err := r.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM shipments WHERE order_id=$1)`, o.ID).Scan(&shipped); err != nil {
		return nil, err
	}
	if shipped {
		return nil, errInvalidTransition
	}
	o.Status = "cancelled"
	_, err := r.Tx.Exec(ctx, `UPDATE orders SET status='cancelled' WHERE id=$1`, o.ID)
	return o, err
}

// refund: the limit condition was checked by can() (caveat/condition with amountCents); state rules here.
func (m *Module) refund(ctx context.Context, r *core.Req) (any, error) {
	var in refundIn
	_ = r.Decode(&in)
	o := scope.OrderOf(r)
	if o.Status != "paid" {
		return nil, errInvalidTransition
	}
	var captured int64
	if err := r.Tx.QueryRow(ctx, `SELECT coalesce(sum(amount_cents),0) FROM payments WHERE order_id=$1 AND status='captured'`, o.ID).Scan(&captured); err != nil {
		return nil, err
	}
	if captured == 0 {
		return nil, errInvalidTransition
	}
	if o.RefundedCents+in.AmountCents > captured {
		return nil, core.Conflict("over_refund")
	}
	o.RefundedCents += in.AmountCents
	_, err := r.Tx.Exec(ctx, `UPDATE orders SET refunded_cents=$2 WHERE id=$1`, o.ID, o.RefundedCents)
	return o, err
}

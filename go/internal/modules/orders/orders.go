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
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
)

type Module struct{}

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
	var status string
	if err := r.Tx.QueryRow(ctx, `SELECT status FROM merchants WHERE id=$1`, r.Target.MerchantID).Scan(&status); err != nil {
		return nil, err
	}
	if status == "suspended" {
		return nil, core.ErrMerchantSuspended
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
		if !ok {
			return nil, core.BadInput("order total too large")
		}
		o.Items = append(o.Items, scope.Item{ProductID: it.ProductID, Qty: it.Qty, UnitPriceCents: price})
		o.TotalCents = line
	}
	items, _ := json.Marshal(o.Items)
	_, err := r.Tx.Exec(ctx, `INSERT INTO orders(id, merchant_id, store_id, customer_id, items, total_cents, status) VALUES ($1,$2,$3,$4,$5,$6,'pending')`,
		o.ID, r.Target.MerchantID, o.StoreID, o.CustomerID, items, o.TotalCents)
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
	if r.P.Kind == perm.KindCustomer && o.CustomerID != r.P.ID {
		return nil, core.ErrNotFound // order.view_own
	}
	return o, nil
}

func (m *Module) mine(ctx context.Context, r *core.Req) (any, error) {
	if r.P.Kind != perm.KindCustomer {
		return nil, core.ErrForbidden
	}
	return collect(r.Tx.Query(ctx, `SELECT `+scope.OrderCols+` FROM orders WHERE customer_id=$1 ORDER BY created_at`, r.P.ID))
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

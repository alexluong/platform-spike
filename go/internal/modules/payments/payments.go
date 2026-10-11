// Package payments: fake payment provider (capture, list).
package payments

import (
	"context"

	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/jackc/pgx/v5"
)

type Module struct{}

type Payment struct {
	ID          string `json:"id"`
	OrderID     string `json:"orderId"`
	Status      string `json:"status"`
	AmountCents int64  `json:"amountCents"`
}

func orderTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	return scope.OrderTarget(ctx, r.Tx, r.Path("oid"))
}

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Action: "payment.capture", Method: "POST", Path: "/api/orders/{oid}/payments/capture", Status: 201, Target: orderTarget, Run: m.capture},
		{Action: "payment.view", Method: "GET", Path: "/api/orders/{oid}/payments", Target: orderTarget, Run: m.list},
	}
}

func (m *Module) capture(ctx context.Context, r *core.Req) (any, error) {
	o := scope.OrderOf(r)
	if o.Status != "pending" {
		return nil, core.Conflict("invalid_transition")
	}
	p := Payment{ID: db.NewID("pay"), OrderID: o.ID, Status: "captured", AmountCents: o.TotalCents}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO payments(id, merchant_id, order_id, status, amount_cents) VALUES ($1,$2,$3,$4,$5)`,
		p.ID, o.MerchantID, p.OrderID, p.Status, p.AmountCents); err != nil {
		return nil, err
	}
	_, err := r.Tx.Exec(ctx, `UPDATE orders SET status='paid' WHERE id=$1`, o.ID)
	return p, err
}

func (m *Module) list(ctx context.Context, r *core.Req) (any, error) {
	rows, err := r.Tx.Query(ctx, `SELECT id, order_id, status, amount_cents FROM payments WHERE order_id=$1 AND merchant_id=$2 ORDER BY created_at`,
		scope.OrderOf(r).ID, r.Target.MerchantID)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Payment, error) {
		var p Payment
		return p, row.Scan(&p.ID, &p.OrderID, &p.Status, &p.AmountCents)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": core.NonNil(items)}, nil
}

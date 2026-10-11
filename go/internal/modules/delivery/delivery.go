// Package delivery: shipments.
package delivery

import (
	"context"
	"errors"
	"strings"

	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/modules/scope"
	"github.com/jackc/pgx/v5"
)

type Module struct{}

type Shipment struct {
	ID      string `json:"id"`
	OrderID string `json:"orderId"`
	Carrier string `json:"carrier"`
	Status  string `json:"status"`
}

var rank = map[string]int{"label_created": 0, "in_transit": 1, "delivered": 2}

func orderTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	return scope.OrderTarget(ctx, r.Tx, r.Path("oid"))
}

func shipmentTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	var s Shipment
	var mid, sid string
	err := r.Tx.QueryRow(ctx, `SELECT s.id, s.order_id, s.carrier, s.status, o.merchant_id, o.store_id
		FROM shipments s JOIN orders o ON o.id = s.order_id WHERE s.id=$1 FOR UPDATE OF s`, r.Path("shid")).
		Scan(&s.ID, &s.OrderID, &s.Carrier, &s.Status, &mid, &sid)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Target{}, core.ErrNotFound
	} else if err != nil {
		return core.Target{}, err
	}
	return core.StoreTarget(sid, mid, &s), nil
}

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Action: "shipment.create", Method: "POST", Path: "/api/orders/{oid}/shipments", Status: 201, Target: orderTarget, Run: m.create},
		{Action: "shipment.update", Method: "POST", Path: "/api/shipments/{shid}/status", Target: shipmentTarget, Run: m.setStatus},
		{Action: "shipment.view", Method: "GET", Path: "/api/orders/{oid}/shipments", Target: orderTarget, Run: m.list},
	}
}

func (m *Module) create(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		Carrier string `json:"carrier"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Carrier) == "" {
		return nil, core.BadInput("carrier is required")
	}
	o := scope.OrderOf(r)
	if o.Status != "paid" {
		return nil, core.Conflict("invalid_transition")
	}
	s := Shipment{ID: db.NewID("sh"), OrderID: o.ID, Carrier: in.Carrier, Status: "label_created"}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO shipments(id, merchant_id, order_id, carrier, status) VALUES ($1,$2,$3,$4,$5)`,
		s.ID, o.MerchantID, s.OrderID, s.Carrier, s.Status); err != nil {
		return nil, err
	}
	_, err := r.Tx.Exec(ctx, `UPDATE orders SET status='fulfilling' WHERE id=$1`, o.ID)
	return s, err
}

func (m *Module) setStatus(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		Status string `json:"status"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	next, ok := rank[in.Status]
	if !ok {
		return nil, core.BadInput("status must be label_created, in_transit or delivered")
	}
	s := r.Target.Data.(*Shipment)
	if next <= rank[s.Status] {
		return nil, core.Conflict("invalid_transition")
	}
	s.Status = in.Status
	if _, err := r.Tx.Exec(ctx, `UPDATE shipments SET status=$2 WHERE id=$1`, s.ID, s.Status); err != nil {
		return nil, err
	}
	if s.Status == "delivered" {
		if _, err := r.Tx.Exec(ctx, `UPDATE orders SET status='delivered' WHERE id=$1`, s.OrderID); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (m *Module) list(ctx context.Context, r *core.Req) (any, error) {
	rows, err := r.Tx.Query(ctx, `SELECT id, order_id, carrier, status FROM shipments WHERE order_id=$1 AND merchant_id=$2 ORDER BY created_at`,
		scope.OrderOf(r).ID, r.Target.MerchantID)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Shipment, error) {
		var s Shipment
		return s, row.Scan(&s.ID, &s.OrderID, &s.Carrier, &s.Status)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": core.NonNil(items)}, nil
}

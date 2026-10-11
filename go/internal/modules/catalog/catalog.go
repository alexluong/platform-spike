// Package catalog: products of a store.
package catalog

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

type Product struct {
	ID         string `json:"id"`
	StoreID    string `json:"storeId"`
	Title      string `json:"title"`
	PriceCents int64  `json:"priceCents"`
}

func storeTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	return scope.Store(ctx, r.Tx, r.Path("sid"))
}

func productTarget(ctx context.Context, r *core.Req) (core.Target, error) {
	var p Product
	var mid string
	err := r.Tx.QueryRow(ctx, `SELECT id, store_id, title, price_cents, merchant_id FROM products WHERE id=$1 FOR UPDATE`, r.Path("pid")).
		Scan(&p.ID, &p.StoreID, &p.Title, &p.PriceCents, &mid)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Target{}, core.ErrNotFound
	} else if err != nil {
		return core.Target{}, err
	}
	return core.StoreTarget(p.StoreID, mid, &p), nil
}

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Action: "product.create", Method: "POST", Path: "/api/stores/{sid}/products", Status: 201, Target: storeTarget, Run: m.create},
		{Action: "product.update", Method: "PATCH", Path: "/api/products/{pid}", Target: productTarget, Run: m.update},
		{Auth: core.AuthPublic, Method: "GET", Path: "/api/stores/{sid}/products", Target: storeTarget, Run: m.list},
	}
}

func (m *Module) create(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		Title      string `json:"title"`
		PriceCents *int64 `json:"priceCents"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Title) == "" || in.PriceCents == nil || *in.PriceCents < 0 || *in.PriceCents > core.MaxCents {
		return nil, core.BadInput("title and priceCents >= 0 are required")
	}
	p := Product{ID: db.NewID("p"), StoreID: r.Target.Resource.ID, Title: strings.TrimSpace(in.Title), PriceCents: *in.PriceCents}
	_, err := r.Tx.Exec(ctx, `INSERT INTO products(id, merchant_id, store_id, title, price_cents) VALUES ($1,$2,$3,$4,$5)`,
		p.ID, r.Target.MerchantID, p.StoreID, p.Title, p.PriceCents)
	return p, err
}

func (m *Module) update(ctx context.Context, r *core.Req) (any, error) {
	var in struct {
		Title      *string `json:"title"`
		PriceCents *int64  `json:"priceCents"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	p := r.Target.Data.(*Product)
	if in.Title != nil {
		if strings.TrimSpace(*in.Title) == "" {
			return nil, core.BadInput("title must not be empty")
		}
		p.Title = strings.TrimSpace(*in.Title)
	}
	if in.PriceCents != nil {
		if *in.PriceCents < 0 || *in.PriceCents > core.MaxCents {
			return nil, core.BadInput("priceCents must be >= 0")
		}
		p.PriceCents = *in.PriceCents
	}
	_, err := r.Tx.Exec(ctx, `UPDATE products SET title=$2, price_cents=$3 WHERE id=$1 AND merchant_id=$4`, p.ID, p.Title, p.PriceCents, r.Target.MerchantID)
	return p, err
}

func (m *Module) list(ctx context.Context, r *core.Req) (any, error) {
	rows, err := r.Tx.Query(ctx, `SELECT id, store_id, title, price_cents FROM products WHERE store_id=$1 AND merchant_id=$2 ORDER BY created_at`,
		r.Target.Resource.ID, r.Target.MerchantID)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Product, error) {
		var p Product
		return p, row.Scan(&p.ID, &p.StoreID, &p.Title, &p.PriceCents)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": core.NonNil(items)}, nil
}

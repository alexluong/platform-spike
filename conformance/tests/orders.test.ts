// SPEC §8 orders, payments, delivery; "state rules are 409, checked after authorization".
import { describe, expect, test } from 'vitest'
import { expectConflict, expectDenied, expectError, expectStatus, ok } from '../src/client'
import type { Items, Order, Payment, Product, Shipment } from '../src/types'
import { merchantWithStore, newCustomer } from '../src/world'

describe('placing orders', () => {
  test('201 Order: prices come from products, client prices ignored, status pending, refundedCents 0', async () => {
    const { m, s } = await merchantWithStore()
    const [p1, p2] = await Promise.all([m.product(s.id, 250), m.product(s.id, 1000)])
    const c = await newCustomer()
    const o = ok(
      await c.api.post<Order>(`/api/stores/${s.id}/orders`, {
        items: [
          { productId: p1.id, qty: 2, unitPriceCents: 1 },
          { productId: p2.id, qty: 1, unitPriceCents: 1 },
        ],
      }),
      201,
    )
    expect(o).toMatchObject({ storeId: s.id, customerId: c.id, totalCents: 1500, status: 'pending', refundedCents: 0 })
    const byProduct = Object.fromEntries(o.items.map((i) => [i.productId, i]))
    expect(byProduct[p1.id]).toMatchObject({ qty: 2, unitPriceCents: 250 })
    expect(byProduct[p2.id]).toMatchObject({ qty: 1, unitPriceCents: 1000 })
  })

  test('an absurd quantity or price is a 400, not a 500 (regression: review-c, total overflowed the DB column)', async () => {
    const { m, s } = await merchantWithStore()
    const p = await m.product(s.id, 100_000)
    const c = await newCustomer()
    expectStatus(await c.api.post(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 1_000_000 }] }), 400)
    expectStatus(await m.owner.api.post(`/api/stores/${s.id}/products`, { title: 'x', priceCents: 3_000_000_000 }), 400)
  })

  test('qty above 1,000,000 → 400 even when the total fits; 1,000,000 is allowed (SPEC §9 bounds)', async () => {
    const { m, s } = await merchantWithStore()
    const p = await m.product(s.id, 1)
    const c = await newCustomer()
    expectError(await c.api.post(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 1_000_001 }] }), 400)
    expect(ok(await c.api.get<Items<Order>>('/api/me/orders'), 200).items).toEqual([])
    const o = ok(await c.api.post<Order>(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 1_000_000 }] }), 201)
    expect(o.totalCents).toBe(1_000_000)
  })

  test('a later price change does not alter an existing order', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.order(s.id, 400)
    ok(await m.owner.api.patch(`/api/products/${o.items[0].productId}`, { priceCents: 9999 }), 200)
    expect((await m.getOrder(o.id)).totalCents).toBe(400)
  })

  test('a product from another store → 4xx, no order', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const p = await m.product(s2.id, 100)
    const c = await newCustomer()
    expectStatus(await c.api.post(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 1 }] }), 400, 404, 409)
    expect(ok(await c.api.get<Items<Order>>('/api/me/orders'), 200).items).toEqual([])
  })

  test('invalid items (empty, qty 0) → 400', async () => {
    const { m, s } = await merchantWithStore()
    const p = await m.product(s.id, 100)
    const c = await newCustomer()
    expectError(await c.api.post(`/api/stores/${s.id}/orders`, { items: [] }), 400)
    expectError(await c.api.post(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 0 }] }), 400)
  })

  test('a quantity whose total overflows → 400, no order', async () => {
    const { m, s } = await merchantWithStore()
    const c = await m.customer()
    const p = await m.product(s.id, 1000)
    // 2^62 × 1000 overflows a 64-bit total.
    const r = await c.api.post(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 4611686018427387904 }] })
    expectStatus(r, 400)
  })

  test('products: public listing shows created products; product.update changes them', async () => {
    const { m, s } = await merchantWithStore()
    const p = await m.product(s.id, 300)
    const upd = ok(await m.owner.api.patch<Product>(`/api/products/${p.id}`, { title: 'Renamed', priceCents: 350 }), 200)
    expect(upd).toMatchObject({ id: p.id, title: 'Renamed', priceCents: 350 })
    const { items } = ok(await m.owner.api.anon().get<Items<Product>>(`/api/stores/${s.id}/products`), 200)
    expect(items.find((x) => x.id === p.id)).toMatchObject({ title: 'Renamed', priceCents: 350 })
  })
})

describe('happy path', () => {
  test('pending → paid → fulfilling → delivered', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.order(s.id, 1234)
    expect(o.status).toBe('pending')

    const pay = ok(await m.owner.api.post<Payment>(`/api/orders/${o.id}/payments/capture`), 201)
    expect(pay).toMatchObject({ orderId: o.id, status: 'captured', amountCents: 1234 })
    expect((await m.getOrder(o.id)).status).toBe('paid')
    const payments = ok(await m.owner.api.get<Items<Payment>>(`/api/orders/${o.id}/payments`), 200).items
    expect(payments.map((p) => p.id)).toContain(pay.id)

    const sh = ok(await m.owner.api.post<Shipment>(`/api/orders/${o.id}/shipments`, { carrier: 'ups' }), 201)
    expect(sh).toMatchObject({ orderId: o.id, carrier: 'ups', status: 'label_created' })
    expect((await m.getOrder(o.id)).status).toBe('fulfilling')

    expect(ok(await m.owner.api.post<Shipment>(`/api/shipments/${sh.id}/status`, { status: 'in_transit' }))).toMatchObject({
      id: sh.id,
      status: 'in_transit',
    })
    expect((await m.getOrder(o.id)).status).toBe('fulfilling')
    expect(ok(await m.owner.api.post<Shipment>(`/api/shipments/${sh.id}/status`, { status: 'delivered' }))).toMatchObject({ status: 'delivered' })
    expect((await m.getOrder(o.id)).status).toBe('delivered')

    const shipments = ok(await m.owner.api.get<Items<Shipment>>(`/api/orders/${o.id}/shipments`), 200).items
    expect(shipments.find((x) => x.id === sh.id)?.status).toBe('delivered')
    // the customer sees the final state
    const c = await m.customer()
    expect(ok(await c.api.get<Order>(`/api/orders/${o.id}`), 200).status).toBe('delivered')
  })
})

describe('cancel', () => {
  test('pending → cancelled', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.order(s.id)
    ok(await m.owner.api.post(`/api/orders/${o.id}/cancel`))
    expect((await m.getOrder(o.id)).status).toBe('cancelled')
  })

  test('paid (not shipped) → cancelled', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.paidOrder(s.id)
    ok(await m.owner.api.post(`/api/orders/${o.id}/cancel`))
    expect((await m.getOrder(o.id)).status).toBe('cancelled')
  })

  test('fulfilling, delivered or cancelled → 409', async () => {
    const { m, s } = await merchantWithStore()
    const shipped = await m.paidOrder(s.id)
    await m.ship(shipped.id)
    const delivered = await m.paidOrder(s.id)
    const sh = await m.ship(delivered.id)
    await m.setShipmentStatus(sh.id, 'delivered')
    const cancelled = await m.order(s.id)
    ok(await m.owner.api.post(`/api/orders/${cancelled.id}/cancel`))
    expectConflict(await m.owner.api.post(`/api/orders/${shipped.id}/cancel`))
    expectConflict(await m.owner.api.post(`/api/orders/${delivered.id}/cancel`))
    expectConflict(await m.owner.api.post(`/api/orders/${cancelled.id}/cancel`))
    expect((await m.getOrder(shipped.id)).status).toBe('fulfilling')
  })

  test('a cancelled order cannot be captured or shipped (409)', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.order(s.id)
    ok(await m.owner.api.post(`/api/orders/${o.id}/cancel`))
    expectConflict(await m.owner.api.post(`/api/orders/${o.id}/payments/capture`))
    expectConflict(await m.owner.api.post(`/api/orders/${o.id}/shipments`, { carrier: 'ups' }))
  })
})

describe('payments and refunds', () => {
  test('capture on a non-pending order → 409', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.paidOrder(s.id)
    expectConflict(await m.owner.api.post(`/api/orders/${o.id}/payments/capture`))
  })

  test('partial refunds add up in refundedCents', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.paidOrder(s.id, 1000)
    expect(ok<Order>(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 300 }), 200).refundedCents).toBe(300)
    expect(ok<Order>(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 200 }), 200).refundedCents).toBe(500)
    expect((await m.getOrder(o.id)).refundedCents).toBe(500)
  })

  test('refunding more than captured → 409 over_refund, nothing refunded', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.paidOrder(s.id, 1000)
    expectConflict(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 1001 }), 'over_refund')
    ok(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 700 }), 200)
    expectConflict(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 301 }), 'over_refund')
    expect((await m.getOrder(o.id)).refundedCents).toBe(700)
    expect(ok<Order>(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 300 }), 200).refundedCents).toBe(1000)
  })

  test('refund on a pending (uncaptured) order → 409', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.order(s.id)
    expectConflict(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 100 }))
  })

  test('refund on a fulfilling order → 409 (order must be paid)', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.paidOrder(s.id)
    await m.ship(o.id)
    expectConflict(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 100 }))
  })

  test('non-positive refund amount → 400', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.paidOrder(s.id)
    expectError(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 0 }), 400)
    expectError(await m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: -5 }), 400)
  })
})

describe('shipments', () => {
  test('shipment on a pending order → 409', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.order(s.id)
    expectConflict(await m.owner.api.post(`/api/orders/${o.id}/shipments`, { carrier: 'ups' }))
  })

  test('status moves forward only: backwards → 409 invalid_transition', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.paidOrder(s.id)
    const sh = await m.ship(o.id)
    await m.setShipmentStatus(sh.id, 'in_transit')
    expectConflict(await m.owner.api.post(`/api/shipments/${sh.id}/status`, { status: 'label_created' }), 'invalid_transition')
    await m.setShipmentStatus(sh.id, 'delivered')
    expectConflict(await m.owner.api.post(`/api/shipments/${sh.id}/status`, { status: 'in_transit' }), 'invalid_transition')
    expect((await m.getOrder(o.id)).status).toBe('delivered')
  })

  test('unknown status value → 400', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.paidOrder(s.id)
    const sh = await m.ship(o.id)
    expectError(await m.owner.api.post(`/api/shipments/${sh.id}/status`, { status: 'lost_at_sea' }), 400)
  })
})

describe('authorization before state rules (403, not 409)', () => {
  test('staff (no payment.capture) capturing an already-paid order → 403', async () => {
    const { m, s } = await merchantWithStore()
    const staff = await m.memberWithRole('staff')
    const o = await m.paidOrder(s.id)
    expectDenied(await staff.api.post(`/api/orders/${o.id}/payments/capture`))
  })

  test('developer (no order.cancel) cancelling a cancelled order → 403', async () => {
    const { m, s } = await merchantWithStore()
    const dev = await m.memberWithRole('developer')
    const o = await m.order(s.id)
    ok(await m.owner.api.post(`/api/orders/${o.id}/cancel`))
    expectDenied(await dev.api.post(`/api/orders/${o.id}/cancel`))
  })

  test('staff (no order.refund) over-refunding → 403, not 409 over_refund', async () => {
    const { m, s } = await merchantWithStore()
    const staff = await m.memberWithRole('staff')
    const o = await m.paidOrder(s.id, 100)
    expectDenied(await staff.api.post(`/api/orders/${o.id}/refund`, { amountCents: 100_000 }))
  })

  test('developer (no shipment.update) moving a shipment backwards → 403, not 409 invalid_transition', async () => {
    const { m, s } = await merchantWithStore()
    const dev = await m.memberWithRole('developer')
    const o = await m.paidOrder(s.id)
    const sh = await m.ship(o.id)
    await m.setShipmentStatus(sh.id, 'delivered')
    expectDenied(await dev.api.post(`/api/shipments/${sh.id}/status`, { status: 'label_created' }))
  })

  test('another merchant’s owner on a state-violating request → 403|404', async () => {
    const [a, b] = await Promise.all([merchantWithStore(), merchantWithStore()])
    const o = await b.m.order(b.s.id)
    expectDenied(await a.m.owner.api.post(`/api/orders/${o.id}/refund`, { amountCents: 100 }), { crossTenant: true })
    expectDenied(await a.m.owner.api.post(`/api/orders/${o.id}/shipments`, { carrier: 'x' }), { crossTenant: true })
  })

  test('refund limit is checked before over_refund: limited role over its limit and over the captured amount → 403', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['order.view', 'order.refund'], m.scope, { refundLimitCents: 100 })
    const o = await m.paidOrder(s.id, 500)
    expectDenied(await u.api.post(`/api/orders/${o.id}/refund`, { amountCents: 1000 }))
  })
})

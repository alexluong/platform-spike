// Orders (SPEC §8). Customers are never in the engine: their access is `customer_id = me` in SQL.
import { and, desc, eq, inArray } from 'drizzle-orm'
import { z } from 'zod'
import { newId } from '../db/ids.js'
import { organization as merchants } from '../db/idp-tables.js'
import { MAX_CENTS, orders, payments, products, shipments, stores } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { conflict, forbidden, invalid, notFound } from '../kernel/errors.js'
import { findOrder, findStore, storeResource } from './lookup.js'

/** Largest quantity per order line (SPEC §9 input bounds). */
export const MAX_QTY = 1_000_000

export const orderOut = (o: typeof orders.$inferSelect) => ({
  id: o.id,
  storeId: o.storeId,
  customerId: o.customerId,
  items: o.items,
  totalCents: o.totalCents,
  status: o.status,
  refundedCents: o.refundedCents,
})

export function orderActions() {
  const place = defineAction({
    id: 'order.place',
    mutating: true,
    kinds: ['customer'],
    input: z.object({
      storeId: z.string(),
      items: z.array(z.object({ productId: z.string().min(1), qty: z.number().int().min(1).max(MAX_QTY) })).min(1),
    }),
    authorize: async () => null, // customer action, checked in SQL (SPEC §4)
    async run({ tx, principal, emit }, i) {
      const [s] = await tx
        .select({ id: stores.id, merchantId: stores.merchantId, status: merchants.status })
        .from(stores)
        .innerJoin(merchants, eq(merchants.id, stores.merchantId))
        .where(eq(stores.id, i.storeId))
      if (!s) throw notFound('store')
      if (s.status === 'suspended') throw forbidden('merchant_suspended')
      const ids = [...new Set(i.items.map((x) => x.productId))]
      const rows = await tx
        .select()
        .from(products)
        .where(and(eq(products.storeId, s.id), inArray(products.id, ids)))
      const byId = new Map(rows.map((p) => [p.id, p]))
      const items = i.items.map((x) => {
        const p = byId.get(x.productId)
        if (!p) throw invalid('invalid_input', `product ${x.productId} not in this store`)
        return { productId: p.id, qty: x.qty, unitPriceCents: p.priceCents }
      })
      const totalCents = items.reduce((n, x) => n + x.qty * x.unitPriceCents, 0)
      if (totalCents > MAX_CENTS) throw invalid('invalid_input', 'order total too large')
      const [o] = await tx
        .insert(orders)
        .values({ id: newId('o'), merchantId: s.merchantId, storeId: s.id, customerId: principal.id, items, totalCents, status: 'pending' })
        .returning()
      emit({ type: 'order.placed', orderId: o!.id })
      return orderOut(o!)
    },
  })

  const listForStore = defineAction({
    id: 'order.list',
    mutating: false,
    input: z.object({ storeId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'order.view', resource: storeResource((await findStore(db, principal, i.storeId)).id) }),
    async run({ tx, principal }, i) {
      const s = await findStore(tx, principal, i.storeId)
      const rows = await tx
        .select()
        .from(orders)
        .where(and(eq(orders.storeId, s.id), eq(orders.merchantId, s.merchantId)))
        .orderBy(desc(orders.createdAt))
      return { items: rows.map(orderOut) }
    },
  })

  const view = defineAction({
    id: 'order.view',
    mutating: false,
    input: z.object({ orderId: z.string() }),
    authorize: async ({ db, principal }, i) => {
      if (principal.kind === 'customer') {
        const [o] = await db
          .select({ id: orders.id })
          .from(orders)
          .where(and(eq(orders.id, i.orderId), eq(orders.customerId, principal.id)))
        if (!o) throw notFound('order')
        return null
      }
      return { action: 'order.view', resource: storeResource((await findOrder(db, principal, i.orderId)).storeId) }
    },
    async run({ tx }, i) {
      const [o] = await tx.select().from(orders).where(eq(orders.id, i.orderId))
      return orderOut(o!)
    },
  })

  const mine = defineAction({
    id: 'order.view_own',
    mutating: false,
    kinds: ['customer'],
    input: z.object({}),
    authorize: async () => null,
    async run({ tx, principal }) {
      const rows = await tx.select().from(orders).where(eq(orders.customerId, principal.id)).orderBy(desc(orders.createdAt))
      return { items: rows.map(orderOut) }
    },
  })

  const cancel = defineAction({
    id: 'order.cancel',
    mutating: true,
    input: z.object({ orderId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'order.cancel', resource: storeResource((await findOrder(db, principal, i.orderId)).storeId) }),
    async run({ tx, emit }, i) {
      const [o] = await tx.select().from(orders).where(eq(orders.id, i.orderId)).for('update')
      if (o!.status !== 'pending' && o!.status !== 'paid') throw conflict('invalid_transition', `cannot cancel a ${o!.status} order`)
      const [sh] = await tx.select({ id: shipments.id }).from(shipments).where(eq(shipments.orderId, o!.id)).limit(1)
      if (sh) throw conflict('invalid_transition', 'order already shipped')
      const [u] = await tx.update(orders).set({ status: 'cancelled' }).where(eq(orders.id, o!.id)).returning()
      emit({ type: 'order.cancelled', orderId: o!.id })
      return orderOut(u!)
    },
  })

  const refund = defineAction({
    id: 'order.refund',
    mutating: true,
    input: z.object({ orderId: z.string(), amountCents: z.number().int().positive() }),
    // The limit is a condition in the policy: the amount goes in as context.
    authorize: async ({ db, principal }, i) => ({
      action: 'order.refund',
      resource: storeResource((await findOrder(db, principal, i.orderId)).storeId),
      context: { amountCents: i.amountCents },
    }),
    async run({ tx, emit }, i) {
      const [o] = await tx.select().from(orders).where(eq(orders.id, i.orderId)).for('update')
      if (o!.status !== 'paid') throw conflict('invalid_transition', `cannot refund a ${o!.status} order`)
      const caps = await tx
        .select()
        .from(payments)
        .where(and(eq(payments.orderId, o!.id), eq(payments.status, 'captured')))
      const captured = caps.reduce((n, p) => n + p.amountCents, 0)
      if (captured === 0) throw conflict('invalid_transition', 'no captured payment') // unreachable: a paid order is captured
      if (o!.refundedCents + i.amountCents > captured) throw conflict('over_refund', 'refund exceeds captured amount')
      await tx.insert(payments).values({ id: newId('pay'), merchantId: o!.merchantId, orderId: o!.id, status: 'refunded', amountCents: i.amountCents })
      const [u] = await tx
        .update(orders)
        .set({ refundedCents: o!.refundedCents + i.amountCents })
        .where(eq(orders.id, o!.id))
        .returning()
      emit({ type: 'order.refunded', orderId: o!.id, amountCents: i.amountCents })
      return orderOut(u!)
    },
  })

  return [place, listForStore, view, mine, cancel, refund]
}

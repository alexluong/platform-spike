// Payments: a fake provider (SPEC §8).
import { asc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { newId } from '../db/ids.js'
import { orders, payments } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { conflict } from '../kernel/errors.js'
import { findOrder, storeResource } from './lookup.js'

const paymentOut = (p: typeof payments.$inferSelect) => ({ id: p.id, orderId: p.orderId, status: p.status, amountCents: p.amountCents })

export function paymentActions() {
  const capture = defineAction({
    id: 'payment.capture',
    mutating: true,
    input: z.object({ orderId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'payment.capture', resource: storeResource((await findOrder(db, principal, i.orderId)).storeId) }),
    async run({ tx, emit }, i) {
      const [o] = await tx.select().from(orders).where(eq(orders.id, i.orderId)).for('update')
      if (o!.status !== 'pending') throw conflict('invalid_transition', `cannot capture a ${o!.status} order`)
      const [p] = await tx.insert(payments).values({ id: newId('pay'), merchantId: o!.merchantId, orderId: o!.id, status: 'captured', amountCents: o!.totalCents }).returning()
      await tx.update(orders).set({ status: 'paid' }).where(eq(orders.id, o!.id))
      emit({ type: 'payment.captured', orderId: o!.id, paymentId: p!.id })
      return paymentOut(p!)
    },
  })

  const list = defineAction({
    id: 'payment.view',
    mutating: false,
    input: z.object({ orderId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'payment.view', resource: storeResource((await findOrder(db, principal, i.orderId)).storeId) }),
    async run({ tx }, i) {
      const rows = await tx.select().from(payments).where(eq(payments.orderId, i.orderId)).orderBy(asc(payments.createdAt))
      return { items: rows.map(paymentOut) }
    },
  })

  return [capture, list]
}

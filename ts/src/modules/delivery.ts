// Shipments (SPEC §8): forward-only status.
import { asc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { newId } from '../db/ids.js'
import { orders, shipments, type ShipmentStatus } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { conflict } from '../kernel/errors.js'
import { findOrder, findShipment, storeResource } from './lookup.js'

const ORDER: ShipmentStatus[] = ['label_created', 'in_transit', 'delivered']
const shipmentOut = (s: typeof shipments.$inferSelect) => ({ id: s.id, orderId: s.orderId, carrier: s.carrier, status: s.status })

export function deliveryActions() {
  const create = defineAction({
    id: 'shipment.create',
    mutating: true,
    input: z.object({ orderId: z.string(), carrier: z.string().min(1) }),
    authorize: async ({ db, principal }, i) => ({ action: 'shipment.create', resource: storeResource((await findOrder(db, principal, i.orderId)).storeId) }),
    async run({ tx, emit }, i) {
      const [o] = await tx.select().from(orders).where(eq(orders.id, i.orderId)).for('update')
      if (o!.status !== 'paid') throw conflict('invalid_transition', `cannot ship a ${o!.status} order`)
      const [s] = await tx
        .insert(shipments)
        .values({ id: newId('sh'), merchantId: o!.merchantId, storeId: o!.storeId, orderId: o!.id, carrier: i.carrier, status: 'label_created' })
        .returning()
      await tx.update(orders).set({ status: 'fulfilling' }).where(eq(orders.id, o!.id))
      emit({ type: 'shipment.created', shipmentId: s!.id })
      return shipmentOut(s!)
    },
  })

  const setStatus = defineAction({
    id: 'shipment.update',
    mutating: true,
    input: z.object({ shipmentId: z.string(), status: z.enum(['label_created', 'in_transit', 'delivered']) }),
    authorize: async ({ db, principal }, i) => ({ action: 'shipment.update', resource: storeResource((await findShipment(db, principal, i.shipmentId)).storeId) }),
    async run({ tx, emit }, i) {
      const [s] = await tx.select().from(shipments).where(eq(shipments.id, i.shipmentId)).for('update')
      if (ORDER.indexOf(i.status) <= ORDER.indexOf(s!.status)) throw conflict('invalid_transition', `${s!.status} → ${i.status}`)
      const [u] = await tx.update(shipments).set({ status: i.status }).where(eq(shipments.id, s!.id)).returning()
      if (i.status === 'delivered') await tx.update(orders).set({ status: 'delivered' }).where(eq(orders.id, s!.orderId))
      emit({ type: 'shipment.status', shipmentId: s!.id, status: i.status })
      return shipmentOut(u!)
    },
  })

  const list = defineAction({
    id: 'shipment.view',
    mutating: false,
    input: z.object({ orderId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'shipment.view', resource: storeResource((await findOrder(db, principal, i.orderId)).storeId) }),
    async run({ tx }, i) {
      const rows = await tx.select().from(shipments).where(eq(shipments.orderId, i.orderId)).orderBy(asc(shipments.createdAt))
      return { items: rows.map(shipmentOut) }
    },
  })

  return [create, setStatus, list]
}

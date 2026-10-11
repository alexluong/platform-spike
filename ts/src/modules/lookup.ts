// Resource lookups shared by modules. Tenant isolation, first layer: for merchant principals
// (users, agents) every lookup is scoped by merchant in SQL; the engine checks again.
import { and, eq, type SQL } from 'drizzle-orm'
import type { PgColumn } from 'drizzle-orm/pg-core'
import type { Queryable } from '../db/client.js'
import { orders, products, shipments, stores } from '../db/schema.js'
import type { Resource } from '../kernel/authz.js'
import { notFound } from '../kernel/errors.js'
import type { Principal } from '../kernel/principal.js'

/** Merchant the principal is confined to in SQL; undefined = not confined (platform, apps). */
export function tenantOf(p: Principal): string | undefined {
  if (p.kind === 'user' || p.kind === 'agent') return p.merchantId ?? '__none__'
  return undefined
}

export const scoped = (col: PgColumn, p: Principal, cond: SQL): SQL => {
  const t = tenantOf(p)
  return t === undefined ? cond : and(cond, eq(col, t))!
}

export const storeResource = (id: string): Resource => ({ type: 'store', id })
export const merchantResource = (id: string): Resource => ({ type: 'merchant', id })
export const platformResource: Resource = { type: 'platform', id: 'platform' }

export async function findStore(db: Queryable, p: Principal, id: string) {
  const [s] = await db.select().from(stores).where(scoped(stores.merchantId, p, eq(stores.id, id)))
  if (!s) throw notFound('store')
  return s
}
export async function findOrder(db: Queryable, p: Principal, id: string) {
  const [o] = await db.select().from(orders).where(scoped(orders.merchantId, p, eq(orders.id, id)))
  if (!o) throw notFound('order')
  return o
}
export async function findProduct(db: Queryable, p: Principal, id: string) {
  const [x] = await db.select().from(products).where(scoped(products.merchantId, p, eq(products.id, id)))
  if (!x) throw notFound('product')
  return x
}
export async function findShipment(db: Queryable, p: Principal, id: string) {
  const [x] = await db.select().from(shipments).where(scoped(shipments.merchantId, p, eq(shipments.id, id)))
  if (!x) throw notFound('shipment')
  return x
}

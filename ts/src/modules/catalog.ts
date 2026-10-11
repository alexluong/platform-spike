// Products (SPEC §9 Store modules).
import { desc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { newId } from '../db/ids.js'
import { products, stores } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { notFound } from '../kernel/errors.js'
import { findProduct, findStore, storeResource } from './lookup.js'

const productOut = (p: typeof products.$inferSelect) => ({ id: p.id, storeId: p.storeId, title: p.title, priceCents: p.priceCents })

export function catalogActions() {
  const create = defineAction({
    id: 'product.create',
    mutating: true,
    input: z.object({ storeId: z.string(), title: z.string().min(1), priceCents: z.number().int().nonnegative() }),
    authorize: async ({ db, principal }, i) => ({ action: 'product.create', resource: storeResource((await findStore(db, principal, i.storeId)).id) }),
    async run({ tx, principal, emit }, i) {
      const s = await findStore(tx, principal, i.storeId)
      const [p] = await tx.insert(products).values({ id: newId('p'), merchantId: s.merchantId, storeId: s.id, title: i.title, priceCents: i.priceCents }).returning()
      emit({ type: 'product.created', productId: p!.id })
      return productOut(p!)
    },
  })

  const update = defineAction({
    id: 'product.update',
    mutating: true,
    input: z.object({ productId: z.string(), title: z.string().min(1).optional(), priceCents: z.number().int().nonnegative().optional() }),
    authorize: async ({ db, principal }, i) => ({ action: 'product.update', resource: storeResource((await findProduct(db, principal, i.productId)).storeId) }),
    async run({ tx, emit }, i) {
      const set: Partial<typeof products.$inferInsert> = {}
      if (i.title !== undefined) set.title = i.title
      if (i.priceCents !== undefined) set.priceCents = i.priceCents
      const [p] = Object.keys(set).length
        ? await tx.update(products).set(set).where(eq(products.id, i.productId)).returning()
        : await tx.select().from(products).where(eq(products.id, i.productId))
      emit({ type: 'product.updated', productId: i.productId })
      return productOut(p!)
    },
  })

  const listPublic = defineAction({
    id: 'product.list_public',
    mutating: false,
    public: true,
    input: z.object({ storeId: z.string() }),
    authorize: async () => null,
    async run({ tx }, i) {
      const [s] = await tx.select({ id: stores.id }).from(stores).where(eq(stores.id, i.storeId))
      if (!s) throw notFound('store')
      const rows = await tx.select().from(products).where(eq(products.storeId, s.id)).orderBy(desc(products.createdAt))
      return { items: rows.map(productOut) }
    },
  })

  return [create, update, listPublic]
}

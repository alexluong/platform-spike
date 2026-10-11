// Stores (SPEC §9). The list uses the engine's resource search (Cerbos PlanResources).
import { and, desc, eq, inArray } from 'drizzle-orm'
import { z } from 'zod'
import { newId } from '../db/ids.js'
import { merchants, stores } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { type Authorizer, subjectOf } from '../kernel/authz.js'
import { notFound } from '../kernel/errors.js'
import { findStore, storeResource, tenantOf } from './lookup.js'
import { merchantCheck } from './merchants.js'

const storeOut = (s: typeof stores.$inferSelect) => ({ id: s.id, merchantId: s.merchantId, name: s.name })

export function storeActions(deps: { authz: Pick<Authorizer, 'searchResources' | 'evaluateMany'> }) {
  const create = defineAction({
    id: 'store.create',
    mutating: true,
    input: z.object({ merchantId: z.string(), name: z.string().min(1) }),
    authorize: async ({ db, principal }, i) => ({ action: 'store.create', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ tx, emit }, i) {
      const [s] = await tx.insert(stores).values({ id: newId('s'), merchantId: i.merchantId, name: i.name }).returning()
      emit({ type: 'store.created', storeId: s!.id })
      return storeOut(s!)
    },
  })

  const view = defineAction({
    id: 'store.view',
    mutating: false,
    input: z.object({ storeId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'store.view', resource: storeResource((await findStore(db, principal, i.storeId)).id) }),
    async run({ tx, principal }, i) {
      return storeOut(await findStore(tx, principal, i.storeId))
    },
  })

  /** Stores of a merchant the caller has store.view on. No action check of its own (SPEC: "—"),
   *  except for platform staff: their only way in is break-glass, and every break-glass request must
   *  be audited, which happens only for checks the executor runs (a resource search isn't one). */
  const list = defineAction({
    id: 'store.list',
    mutating: false,
    input: z.object({ merchantId: z.string() }),
    authorize: async ({ db, principal }, i) =>
      principal.kind === 'platform' ? { action: 'store.view', resource: await merchantCheck(db, principal, i.merchantId) } : null,
    async run({ tx, principal }, i) {
      const t = tenantOf(principal)
      const [m] = await tx.select().from(merchants).where(eq(merchants.id, i.merchantId))
      if (!m) throw notFound('merchant')
      if (t !== undefined && t !== m.id) return { items: [] }
      const subject = subjectOf(principal)
      const filter = deps.authz.searchResources
        ? await deps.authz.searchResources({
            subject,
            action: { name: 'store.view' },
            resource: { type: 'store', properties: { merchantId: m.id, status: m.status } },
          })
        : ({ kind: 'unsupported' } as const)
      const base = eq(stores.merchantId, m.id)
      if (filter.kind === 'none') return { items: [] }
      if (filter.kind === 'ids' && filter.ids.length === 0) return { items: [] }
      const rows = await tx
        .select()
        .from(stores)
        .where(filter.kind === 'ids' ? and(base, inArray(stores.id, filter.ids)) : base)
        .orderBy(desc(stores.createdAt))
      if (filter.kind !== 'unsupported') return { items: rows.map(storeOut) }
      // Fallback when the plan can't be turned into SQL: check each store.
      const ds = await deps.authz.evaluateMany({
        subject,
        evaluations: rows.map((s) => ({ action: { name: 'store.view' }, resource: storeResource(s.id) })),
      })
      return { items: rows.filter((_, n) => ds[n]!.decision).map(storeOut) }
    },
  })

  return [create, view, list]
}

// Platform staff: merchants, suspension, break-glass, audit (SPEC §7).
import { desc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { newId } from '../db/ids.js'
import { appUsers, audit, breakGlass, members, merchants, roleAssignments } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { conflict, invalid, notFound } from '../kernel/errors.js'
import { merchantResource, platformResource } from './lookup.js'

const merchantOut = (m: typeof merchants.$inferSelect) => ({ id: m.id, name: m.name, status: m.status })

export function platformActions() {
  const create = defineAction({
    id: 'platform.merchant.create',
    mutating: true,
    kinds: ['platform'],
    input: z.object({ name: z.string().min(1), ownerUserId: z.string().min(1) }),
    authorize: async () => ({ action: 'platform.merchant.create', resource: platformResource }),
    async run({ tx, emit }, input) {
      const [owner] = await tx.select().from(appUsers).where(eq(appUsers.id, input.ownerUserId))
      if (!owner || owner.kind !== 'user') throw invalid('invalid_input', 'ownerUserId must be a merchant user')
      const [existing] = await tx.select().from(members).where(eq(members.userId, owner.id))
      if (existing) throw conflict('already_member', 'user already belongs to a merchant')
      const id = newId('m')
      const [m] = await tx.insert(merchants).values({ id, name: input.name }).returning()
      await tx.insert(members).values({ userId: owner.id, merchantId: id })
      await tx.insert(roleAssignments).values({ id: newId('ra'), merchantId: id, userId: owner.id, roleId: 'owner', scopeType: 'merchant', scopeId: id })
      emit({ type: 'merchant.created', merchantId: id, ownerUserId: owner.id })
      return merchantOut(m!)
    },
  })

  const list = defineAction({
    id: 'platform.merchant.view',
    mutating: false,
    kinds: ['platform'],
    input: z.object({}),
    authorize: async () => ({ action: 'platform.merchant.view', resource: platformResource }),
    async run({ tx }) {
      const rows = await tx.select().from(merchants).orderBy(desc(merchants.createdAt))
      return { items: rows.map(merchantOut) }
    },
  })

  const setStatus = (id: string, status: 'active' | 'suspended') =>
    defineAction({
      id,
      mutating: true,
      kinds: ['platform'],
      input: z.object({ merchantId: z.string() }),
      authorize: async () => ({ action: 'platform.merchant.suspend', resource: platformResource }),
      async run({ tx, emit }, input) {
        const [m] = await tx.update(merchants).set({ status }).where(eq(merchants.id, input.merchantId)).returning()
        if (!m) throw notFound('merchant')
        emit({ type: `merchant.${status}`, merchantId: m.id })
        return { id: m.id, status: m.status }
      },
    })

  const openBreakGlass = defineAction({
    id: 'platform.break_glass',
    mutating: true,
    kinds: ['platform'],
    input: z.object({ merchantId: z.string().min(1), reason: z.string().min(1), minutes: z.number().int().positive().max(24 * 60) }),
    authorize: async ({ db }, input) => {
      const [m] = await db.select({ id: merchants.id }).from(merchants).where(eq(merchants.id, input.merchantId))
      if (!m) throw notFound('merchant')
      return { action: 'platform.break_glass', resource: merchantResource(m.id) }
    },
    async run({ tx, principal }, input) {
      const expiresAt = new Date(Date.now() + input.minutes * 60_000)
      const id = newId('bg')
      await tx.insert(breakGlass).values({ id, actor: principal.id, merchantId: input.merchantId, reason: input.reason, expiresAt })
      await tx.insert(audit).values({ actor: principal.id, action: 'platform.break_glass', merchantId: input.merchantId })
      return { id, expiresAt: expiresAt.toISOString() }
    },
  })

  const auditView = defineAction({
    id: 'platform.audit.view',
    mutating: false,
    kinds: ['platform'],
    input: z.object({ merchantId: z.string().optional() }),
    authorize: async () => ({ action: 'platform.audit.view', resource: platformResource }),
    async run({ tx }, input) {
      const q = tx.select().from(audit)
      const rows = await (input.merchantId ? q.where(eq(audit.merchantId, input.merchantId)) : q).orderBy(desc(audit.at), desc(audit.id)).limit(500)
      return { items: rows.map((r) => ({ actor: r.actor, action: r.action, merchantId: r.merchantId, at: r.at.toISOString() })) }
    },
  })

  return [create, list, setStatus('platform.merchant.suspend', 'suspended'), setStatus('platform.merchant.reinstate', 'active'), openBreakGlass, auditView]
}

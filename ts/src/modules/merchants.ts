// Merchant profile and members (SPEC §9 Merchant).
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { appUsers, members, merchants, roleAssignments } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { conflict, invalid, notFound } from '../kernel/errors.js'
import { merchantResource, tenantOf } from './lookup.js'
import { assertNotLastOwner } from './roles.js'

const mid = z.object({ merchantId: z.string() })

/** Resolve a merchant the caller may address (SQL tenant scope first). */
export async function merchantCheck(db: import('../db/client.js').Queryable, p: import('../kernel/principal.js').Principal, merchantId: string) {
  const t = tenantOf(p)
  if (t !== undefined && t !== merchantId) throw notFound('merchant')
  const [m] = await db.select({ id: merchants.id }).from(merchants).where(eq(merchants.id, merchantId))
  if (!m) throw notFound('merchant')
  return merchantResource(m.id)
}

export function merchantActions() {
  const view = defineAction({
    id: 'merchant.view',
    mutating: false,
    input: mid,
    authorize: async ({ db, principal }, i) => ({ action: 'merchant.view', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ tx }, i) {
      const [m] = await tx.select().from(merchants).where(eq(merchants.id, i.merchantId))
      return { id: m!.id, name: m!.name, status: m!.status }
    },
  })

  const addMember = defineAction({
    id: 'member.add',
    mutating: true,
    input: mid.extend({ userId: z.string().min(1) }),
    authorize: async ({ db, principal }, i) => ({ action: 'member.manage', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ tx, emit }, i) {
      const [u] = await tx.select().from(appUsers).where(eq(appUsers.id, i.userId))
      if (!u || u.kind !== 'user') throw invalid('invalid_input', 'userId must be a merchant user')
      const [existing] = await tx.select().from(members).where(eq(members.userId, u.id))
      if (existing) throw conflict('already_member', 'user already belongs to a merchant')
      await tx.insert(members).values({ userId: u.id, merchantId: i.merchantId })
      emit({ type: 'member.added', userId: u.id })
      return { userId: u.id, merchantId: i.merchantId }
    },
  })

  const removeMember = defineAction({
    id: 'member.remove',
    mutating: true,
    input: mid.extend({ userId: z.string().min(1) }),
    authorize: async ({ db, principal }, i) => {
      const at = await merchantCheck(db, principal, i.merchantId)
      const checks = [{ action: 'member.manage', resource: at }]
      // Removing a member removes their roles: taking away `owner` is owner-only.
      const [own] = await db
        .select({ id: roleAssignments.id })
        .from(roleAssignments)
        .where(and(eq(roleAssignments.userId, i.userId), eq(roleAssignments.merchantId, i.merchantId), eq(roleAssignments.roleId, 'owner')))
        .limit(1)
      if (own) checks.push({ action: 'role.manage_owner', resource: at })
      return checks
    },
    async run({ tx, emit }, i) {
      const [m] = await tx
        .select()
        .from(members)
        .where(and(eq(members.userId, i.userId), eq(members.merchantId, i.merchantId)))
      if (!m) throw notFound('member')
      await assertNotLastOwner(tx, i.merchantId, i.userId)
      await tx.delete(roleAssignments).where(and(eq(roleAssignments.userId, i.userId), eq(roleAssignments.merchantId, i.merchantId)))
      await tx.delete(members).where(eq(members.userId, i.userId))
      emit({ type: 'member.removed', userId: i.userId })
      return null
    },
  })

  return [view, addMember, removeMember]
}

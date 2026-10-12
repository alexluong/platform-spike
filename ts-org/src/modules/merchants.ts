// Merchant profile, members and invitations (SPEC §9 Merchant, §15.2). Merchants, members and
// invitations are the IdP's records (organization plugin): read here in SQL, written through the
// tenancy port inside the action's transaction. Who may change them stays an app decision (§3
// member.manage through can()); the IdP's own role checks are not used.
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import type { Queryable } from '../db/client.js'
import { member, organization as merchants } from '../db/idp-tables.js'
import { appUsers, roleAssignments } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { conflict, invalid, notFound } from '../kernel/errors.js'
import type { Principal } from '../kernel/principal.js'
import type { InvitationRecord } from '../kernel/tenancy.js'
import { merchantResource, tenantOf } from './lookup.js'
import { assertNotLastOwner } from './roles.js'

const mid = z.object({ merchantId: z.string() })

/** Resolve a merchant the caller may address (SQL tenant scope first). */
export async function merchantCheck(db: Queryable, p: Principal, merchantId: string) {
  const t = tenantOf(p)
  if (t !== undefined && t !== merchantId) throw notFound('merchant')
  const [m] = await db.select({ id: merchants.id }).from(merchants).where(eq(merchants.id, merchantId))
  if (!m) throw notFound('merchant')
  return merchantResource(m.id)
}

const invitationOut = (i: InvitationRecord) => ({ id: i.id, email: i.email, status: i.status, expiresAt: i.expiresAt.toISOString() })

export function merchantActions() {
  const view = defineAction({
    id: 'merchant.view',
    mutating: false,
    input: mid,
    authorize: async ({ db, principal }, i) => ({ action: 'merchant.view', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ tx }, i) {
      const [m] = await tx.select().from(merchants).where(eq(merchants.id, i.merchantId))
      return { id: m!.id, name: m!.name, status: m!.status ?? 'active' }
    },
  })

  /** Direct add (§15.1: kept for the suite's helpers): the user joins the organization at once. */
  const addMember = defineAction({
    id: 'member.add',
    mutating: true,
    input: mid.extend({ userId: z.string().min(1) }),
    authorize: async ({ db, principal }, i) => ({ action: 'member.manage', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ tx, idp, emit }, i) {
      const [u] = await tx.select().from(appUsers).where(eq(appUsers.id, i.userId))
      if (!u || u.kind !== 'user') throw invalid('invalid_input', 'userId must be a merchant user')
      const [existing] = await tx.select({ id: member.id }).from(member).where(eq(member.userId, u.id))
      if (existing) throw conflict('already_member', 'user already belongs to a merchant')
      await idp.addMember(i.merchantId, u.id) // the unique index on member(userId) closes the race
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
    async run({ tx, idp, emit }, i) {
      const [m] = await tx
        .select({ id: member.id })
        .from(member)
        .where(and(eq(member.userId, i.userId), eq(member.organizationId, i.merchantId)))
      if (!m) throw notFound('member')
      await assertNotLastOwner(tx, i.merchantId, i.userId)
      await tx.delete(roleAssignments).where(and(eq(roleAssignments.userId, i.userId), eq(roleAssignments.merchantId, i.merchantId)))
      if (!(await idp.removeMember(i.merchantId, i.userId))) throw notFound('member')
      emit({ type: 'member.removed', userId: i.userId })
      return null
    },
  })

  // ---------- invitations (§15.2) ----------

  const invite = defineAction({
    id: 'invitation.create',
    mutating: true,
    input: mid.extend({ email: z.string().email() }),
    authorize: async ({ db, principal }, i) => ({ action: 'member.manage', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ idp, principal, emit }, i) {
      const inv = await idp.invite(i.merchantId, i.email, principal.id)
      emit({ type: 'invitation.created', invitationId: inv.id })
      return invitationOut(inv)
    },
  })

  const listInvitations = defineAction({
    id: 'invitation.list',
    mutating: false,
    input: mid,
    authorize: async ({ db, principal }, i) => ({ action: 'member.manage', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ idp }, i) {
      return { items: (await idp.listInvitations(i.merchantId)).map(invitationOut) }
    },
  })

  const cancelInvitation = defineAction({
    id: 'invitation.cancel',
    mutating: true,
    input: mid.extend({ invitationId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'member.manage', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ idp, emit }, i) {
      const inv = await idp.findInvitation(i.invitationId)
      if (!inv || inv.organizationId !== i.merchantId) throw notFound('invitation') // another merchant's: hidden
      if (!(await idp.cancelInvitation(inv.id))) throw conflict('invalid_transition', 'invitation is not pending')
      emit({ type: 'invitation.canceled', invitationId: inv.id })
      return null
    },
  })

  /** The invitee accepts. No engine check: who may accept is the IdP's rule (the recipient, matched
   *  by email). One merchant per user (§2) is checked here first (409) and by the unique index. */
  const acceptInvitation = defineAction({
    id: 'invitation.accept',
    mutating: true,
    kinds: ['user'],
    input: z.object({ invitationId: z.string() }),
    authorize: async () => null,
    async run({ tx, idp, principal, emit }, i) {
      const [existing] = await tx.select({ id: member.id }).from(member).where(eq(member.userId, principal.id))
      if (existing) throw conflict('already_member', 'user already belongs to a merchant')
      const { organizationId } = await idp.acceptInvitation(i.invitationId, principal.credential)
      emit({ type: 'invitation.accepted', invitationId: i.invitationId, userId: principal.id })
      return { merchantId: organizationId }
    },
  })

  return [view, addMember, removeMember, invite, listInvitations, cancelInvitation, acceptInvitation]
}

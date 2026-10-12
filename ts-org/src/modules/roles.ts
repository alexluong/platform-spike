// Roles and assignments (SPEC §3). Custom roles are rows; the guardrails run through can().
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import type { Queryable, Tx } from '../db/client.js'
import { newId } from '../db/ids.js'
import { member, organization as merchants } from '../db/idp-tables.js'
import { MAX_CENTS, roleAssignments, roles, stores } from '../db/schema.js'
import { defineAction, type Can } from '../kernel/action.js'
import type { Resource } from '../kernel/authz.js'
import { SYSTEM_ROLES, isGrantable, systemRole } from '../kernel/catalog.js'
import { conflict, forbidden, invalid, notFound } from '../kernel/errors.js'
import { assertHoldsAll, assertRefundLimitAtLeast } from './guardrails.js'
import { merchantResource, storeResource } from './lookup.js'
import { merchantCheck } from './merchants.js'

type RoleOut = { id: string; name: string; system: boolean; permissions: string[]; refundLimitCents?: number }

const roleOut = (r: typeof roles.$inferSelect): RoleOut => ({
  id: r.id,
  name: r.name,
  system: false,
  permissions: r.permissions,
  ...(r.refundLimitCents != null ? { refundLimitCents: r.refundLimitCents } : {}),
})

const scopeSchema = z.object({ type: z.enum(['merchant', 'store']), id: z.string().min(1) })
const permsSchema = z.array(z.string())

function assertGrantable(perms: string[]) {
  const bad = perms.filter((p) => !isGrantable(p))
  if (bad.length) throw invalid('not_grantable', `not grantable: ${bad.join(', ')}`)
}

/** Look up a role of this merchant: system roles from code, custom from the DB. */
async function findRole(db: Queryable, merchantId: string, roleId: string) {
  const sys = systemRole(roleId)
  if (sys) return { system: true as const, id: sys.id, permissions: [...sys.permissions], refundLimitCents: null }
  const [r] = await db
    .select()
    .from(roles)
    .where(and(eq(roles.id, roleId), eq(roles.merchantId, merchantId)))
  if (!r) throw notFound('role')
  return { system: false as const, id: r.id, permissions: r.permissions, refundLimitCents: r.refundLimitCents, row: r }
}

/** Guardrail: may the caller hand out (or take back) `role` at `at`. */
async function guard(can: Can, role: { permissions: string[]; refundLimitCents: number | null }, at: Resource) {
  await assertHoldsAll(can, role.permissions, at)
  if (role.permissions.includes('order.refund')) await assertRefundLimitAtLeast(can, role.refundLimitCents, at)
}

/** 409 last_owner if removing `userId`'s owner assignment(s) would leave the merchant with none. */
export async function assertNotLastOwner(tx: Tx, merchantId: string, userId: string, onlyAssignmentId?: string) {
  await tx.select({ id: merchants.id }).from(merchants).where(eq(merchants.id, merchantId)).for('update')
  const owners = await tx
    .select({ id: roleAssignments.id, userId: roleAssignments.userId })
    .from(roleAssignments)
    .where(and(eq(roleAssignments.merchantId, merchantId), eq(roleAssignments.roleId, 'owner'), eq(roleAssignments.scopeType, 'merchant')))
  const removed = owners.filter((o) => (onlyAssignmentId ? o.id === onlyAssignmentId : o.userId === userId))
  if (removed.length > 0 && removed.length === owners.length) throw conflict('last_owner', 'cannot remove the last owner')
}

async function scopeResource(db: Queryable, merchantId: string, scope: { type: 'merchant' | 'store'; id: string }): Promise<Resource> {
  if (scope.type === 'merchant') {
    if (scope.id !== merchantId) throw invalid('invalid_input', 'scope merchant must be this merchant')
    return merchantResource(merchantId)
  }
  const [s] = await db
    .select({ id: stores.id })
    .from(stores)
    .where(and(eq(stores.id, scope.id), eq(stores.merchantId, merchantId)))
  if (!s) throw notFound('store') // another merchant's store is hidden like any cross-tenant resource
  return storeResource(s.id)
}

export function roleActions() {
  const mid = z.object({ merchantId: z.string() })

  const list = defineAction({
    id: 'role.list',
    mutating: false,
    input: mid,
    authorize: async ({ db, principal }, i) => ({ action: 'merchant.view', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ tx }, i) {
      const custom = await tx.select().from(roles).where(eq(roles.merchantId, i.merchantId)).orderBy(roles.createdAt)
      const system: RoleOut[] = SYSTEM_ROLES.map((r) => ({ id: r.id, name: r.name, system: true, permissions: [...r.permissions] }))
      return { items: [...system, ...custom.map(roleOut)] }
    },
  })

  const create = defineAction({
    id: 'role.create',
    mutating: true,
    input: mid.extend({ name: z.string().min(1), permissions: permsSchema, refundLimitCents: z.number().int().nonnegative().max(MAX_CENTS).nullish() }),
    authorize: async ({ db, principal }, i) => ({ action: 'role.manage', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ tx, can, emit }, i) {
      assertGrantable(i.permissions)
      const permissions = [...new Set(i.permissions)]
      const limit = i.refundLimitCents ?? null
      await guard(can, { permissions, refundLimitCents: limit }, merchantResource(i.merchantId))
      const [r] = await tx.insert(roles).values({ id: newId('role'), merchantId: i.merchantId, name: i.name, permissions, refundLimitCents: limit }).returning()
      emit({ type: 'role.created', roleId: r!.id })
      return roleOut(r!)
    },
  })

  const update = defineAction({
    id: 'role.update',
    mutating: true,
    input: mid.extend({
      roleId: z.string(),
      name: z.string().min(1).optional(),
      permissions: permsSchema.optional(),
      refundLimitCents: z.number().int().nonnegative().max(MAX_CENTS).nullish(),
    }),
    authorize: async ({ db, principal }, i) => ({ action: 'role.manage', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ tx, can, emit }, i) {
      const role = await findRole(tx, i.merchantId, i.roleId)
      if (role.system) throw forbidden('system_role', 'system roles cannot be edited')
      if (i.permissions) assertGrantable(i.permissions)
      const permissions = i.permissions ? [...new Set(i.permissions)] : role.permissions
      const limit = i.refundLimitCents !== undefined ? i.refundLimitCents : role.refundLimitCents
      const at = merchantResource(i.merchantId)
      await guard(can, role, at) // must hold what the role grants today…
      await guard(can, { permissions, refundLimitCents: limit }, at) // …and after the edit
      const [r] = await tx
        .update(roles)
        .set({ name: i.name ?? role.row.name, permissions, refundLimitCents: limit })
        .where(eq(roles.id, role.id))
        .returning()
      emit({ type: 'role.updated', roleId: r!.id })
      return roleOut(r!)
    },
  })

  const remove = defineAction({
    id: 'role.delete',
    mutating: true,
    input: mid.extend({ roleId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'role.manage', resource: await merchantCheck(db, principal, i.merchantId) }),
    async run({ tx, can, emit }, i) {
      const role = await findRole(tx, i.merchantId, i.roleId)
      if (role.system) throw forbidden('system_role', 'system roles cannot be deleted')
      await guard(can, role, merchantResource(i.merchantId))
      // Cascade: assignments go with the role (same transaction).
      await tx.delete(roleAssignments).where(and(eq(roleAssignments.roleId, role.id), eq(roleAssignments.merchantId, i.merchantId)))
      await tx.delete(roles).where(eq(roles.id, role.id))
      emit({ type: 'role.deleted', roleId: role.id })
      return null
    },
  })

  const assign = defineAction({
    id: 'role.assign',
    mutating: true,
    input: mid.extend({ userId: z.string().min(1), roleId: z.string().min(1), scope: scopeSchema }),
    authorize: async ({ db, principal }, i) => {
      await merchantCheck(db, principal, i.merchantId)
      const at = await scopeResource(db, i.merchantId, i.scope)
      const checks = [{ action: 'role.manage', resource: at }]
      if (i.roleId === 'owner') checks.push({ action: 'role.manage_owner', resource: merchantResource(i.merchantId) })
      return checks
    },
    async run({ tx, can, emit }, i) {
      const role = await findRole(tx, i.merchantId, i.roleId)
      const at = await scopeResource(tx, i.merchantId, i.scope)
      await guard(can, role, at)
      const [m] = await tx
        .select()
        .from(member)
        .where(and(eq(member.userId, i.userId), eq(member.organizationId, i.merchantId)))
      if (!m) throw invalid('not_member', 'user is not a member of this merchant')
      const [dup] = await tx
        .select({ id: roleAssignments.id })
        .from(roleAssignments)
        .where(
          and(
            eq(roleAssignments.merchantId, i.merchantId),
            eq(roleAssignments.userId, i.userId),
            eq(roleAssignments.roleId, role.id),
            eq(roleAssignments.scopeType, i.scope.type),
            eq(roleAssignments.scopeId, i.scope.id),
          ),
        )
      if (dup) throw conflict('already_assigned', 'the user already holds this role at this scope')
      const [a] = await tx
        .insert(roleAssignments)
        .values({ id: newId('ra'), merchantId: i.merchantId, userId: i.userId, roleId: role.id, scopeType: i.scope.type, scopeId: i.scope.id })
        .returning()
      emit({ type: 'role.assigned', assignmentId: a!.id })
      return { id: a!.id, userId: a!.userId, roleId: a!.roleId, scope: { type: a!.scopeType, id: a!.scopeId } }
    },
  })

  const unassign = defineAction({
    id: 'role.unassign',
    mutating: true,
    input: mid.extend({ assignmentId: z.string() }),
    authorize: async ({ db, principal }, i) => {
      await merchantCheck(db, principal, i.merchantId)
      const [a] = await db
        .select()
        .from(roleAssignments)
        .where(and(eq(roleAssignments.id, i.assignmentId), eq(roleAssignments.merchantId, i.merchantId)))
      if (!a) throw notFound('assignment')
      const at = a.scopeType === 'merchant' ? merchantResource(i.merchantId) : storeResource(a.scopeId)
      const checks = [{ action: 'role.manage', resource: at }]
      if (a.roleId === 'owner') checks.push({ action: 'role.manage_owner', resource: merchantResource(i.merchantId) })
      return checks
    },
    async run({ tx, can, emit }, i) {
      const [a] = await tx.select().from(roleAssignments).where(eq(roleAssignments.id, i.assignmentId))
      if (!a) throw notFound('assignment')
      const role = await findRole(tx, i.merchantId, a.roleId).catch(() => null)
      const at = a.scopeType === 'merchant' ? merchantResource(i.merchantId) : storeResource(a.scopeId)
      if (role) await guard(can, role, at)
      if (a.roleId === 'owner' && a.scopeType === 'merchant') await assertNotLastOwner(tx, i.merchantId, a.userId, a.id)
      await tx.delete(roleAssignments).where(eq(roleAssignments.id, a.id))
      emit({ type: 'role.unassigned', assignmentId: a.id })
      return null
    },
  })

  return [list, create, update, remove, assign, unassign]
}


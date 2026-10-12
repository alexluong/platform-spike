// Access resolution: the PIP. Turns role assignments, installs, grants and break-glass rows into
// the attributes the policy engine evaluates. Custom roles stay data in our DB; the engine only
// ever sees "this principal holds these permissions at these scopes".
import { and, eq, isNull, max } from 'drizzle-orm'
import type { Queryable } from '../db/client.js'
import { member, organization as merchants } from '../db/idp-tables.js'
import { agentGrants, agents, appInstalls, appUsers, breakGlass, roleAssignments, roles, stores } from '../db/schema.js'
import { systemRole } from '../kernel/catalog.js'

export interface Access {
  owner: boolean
  merchantPerms: string[]
  /** one entry per merchant-scope role holding order.refund; -1 = no limit */
  merchantRefundLimits: number[]
  stores: Record<string, { perms: string[]; refundLimits: number[] }>
}

export interface SubjectAttributes {
  roles: string[]
  attr: Record<string, unknown>
}

export type ResourceAttributes = {
  merchantId?: string
  storeId?: string
  status?: string
}

const emptyAccess = (): Access => ({ owner: false, merchantPerms: [], merchantRefundLimits: [], stores: {} })

/** Effective access of a merchant user, straight from assignments (no cache: edits apply on the next request). */
export async function accessOf(db: Queryable, userId: string): Promise<{ merchantId: string | null; access: Access }> {
  // membership is the IdP's (organization plugin's member table, same Postgres; SPEC §15.1)
  const [m] = await db.select({ merchantId: member.organizationId }).from(member).where(eq(member.userId, userId))
  if (!m) return { merchantId: null, access: emptyAccess() }
  const rows = await db
    .select({
      roleId: roleAssignments.roleId,
      scopeType: roleAssignments.scopeType,
      scopeId: roleAssignments.scopeId,
      perms: roles.permissions,
      limit: roles.refundLimitCents,
    })
    .from(roleAssignments)
    .leftJoin(roles, eq(roles.id, roleAssignments.roleId))
    .where(and(eq(roleAssignments.userId, userId), eq(roleAssignments.merchantId, m.merchantId)))
  const access = emptyAccess()
  const merchantSet = new Set<string>()
  const storeSets: Record<string, Set<string>> = {}
  for (const r of rows) {
    const sys = systemRole(r.roleId)
    const perms: readonly string[] = sys ? sys.permissions : (r.perms ?? [])
    const limit = sys ? -1 : (r.limit ?? -1)
    if (r.scopeType === 'merchant') {
      if (r.roleId === 'owner') access.owner = true
      perms.forEach((p) => merchantSet.add(p))
      if (perms.includes('order.refund')) access.merchantRefundLimits.push(limit)
    } else {
      const s = (access.stores[r.scopeId] ??= { perms: [], refundLimits: [] })
      const set = (storeSets[r.scopeId] ??= new Set())
      perms.forEach((p) => set.add(p))
      if (perms.includes('order.refund')) s.refundLimits.push(limit)
    }
  }
  access.merchantPerms = [...merchantSet].sort()
  for (const [sid, set] of Object.entries(storeSets)) access.stores[sid]!.perms = [...set].sort()
  return { merchantId: m.merchantId, access }
}

export function makeAccessResolver(db: Queryable) {
  return {
    async subject(kind: string, id: string): Promise<SubjectAttributes> {
      switch (kind) {
        case 'user': {
          const { merchantId, access } = await accessOf(db, id)
          return { roles: ['user'], attr: { merchantId: merchantId ?? '', access } }
        }
        case 'platform': {
          const [u] = await db.select({ role: appUsers.platformRole }).from(appUsers).where(eq(appUsers.id, id))
          const rows = await db
            .select({ merchantId: breakGlass.merchantId, expiresAt: max(breakGlass.expiresAt) })
            .from(breakGlass)
            .where(eq(breakGlass.actor, id))
            .groupBy(breakGlass.merchantId)
          const bg = Object.fromEntries(rows.map((r) => [r.merchantId, new Date(r.expiresAt as unknown as string).toISOString()]))
          return { roles: [u?.role ?? 'none'], attr: { breakGlass: bg } }
        }
        case 'app': {
          const rows = await db.select({ storeId: appInstalls.storeId, scopes: appInstalls.scopes }).from(appInstalls).where(eq(appInstalls.appId, id))
          const installs: Record<string, string[]> = {}
          for (const r of rows) installs[r.storeId] = [...new Set([...(installs[r.storeId] ?? []), ...r.scopes])]
          return { roles: ['app'], attr: { installs } }
        }
        case 'agent': {
          const [a] = await db.select({ merchantId: agents.merchantId }).from(agents).where(eq(agents.id, id))
          // Unrevoked grants, expired ones included: the policy compares expiresAt to now().
          const rows = await db
            .select()
            .from(agentGrants)
            .where(and(eq(agentGrants.agentId, id), isNull(agentGrants.revokedAt)))
          const granters = new Map<string, Access>()
          for (const g of rows) {
            if (!granters.has(g.grantedBy)) {
              const r = await accessOf(db, g.grantedBy)
              // a granter who left the merchant holds nothing there any more
              granters.set(g.grantedBy, r.merchantId === g.merchantId ? r.access : emptyAccess())
            }
          }
          const grants: Record<string, unknown[]> = {}
          for (const g of rows) {
            ;(grants[g.storeId] ??= []).push({ perms: g.permissions, expiresAt: g.expiresAt.toISOString(), granter: granters.get(g.grantedBy) })
          }
          return { roles: ['agent'], attr: { merchantId: a?.merchantId ?? '', grants } }
        }
        default:
          return { roles: [kind], attr: {} }
      }
    },

    async resource(type: string, id: string): Promise<ResourceAttributes | null> {
      if (type === 'platform') return {}
      if (type === 'merchant') {
        const [m] = await db.select({ status: merchants.status }).from(merchants).where(eq(merchants.id, id))
        return m ? { merchantId: id, status: m.status ?? 'active' } : null
      }
      if (type === 'store') {
        const [s] = await db
          .select({ merchantId: stores.merchantId, status: merchants.status })
          .from(stores)
          .innerJoin(merchants, eq(merchants.id, stores.merchantId))
          .where(eq(stores.id, id))
        return s ? { merchantId: s.merchantId, storeId: id, status: s.status ?? 'active' } : null
      }
      return null
    },

    async merchantStatus(merchantId: string) {
      const [m] = await db.select({ status: merchants.status }).from(merchants).where(eq(merchants.id, merchantId))
      return m?.status ?? null
    },
  }
}
export type AccessResolver = ReturnType<typeof makeAccessResolver>

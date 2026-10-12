// RelationSync for SpiceDB: outbox events → relationship writes (the relay calls `apply`).
//
// d's events are thin (`{type, <id>}`), unlike Go's, which carry the object's full desired state.
// So each event names an object to *reconcile*: read its current state from the app DB (inside the
// relay's transaction) and make SpiceDB match it, deleting what the DB no longer has. Re-applying is
// idempotent and order-insensitive (the latest state wins), which is what a relay that retries
// needs. Shape of the relationships: Go's spicedb.go (`apply`, `syncRole`), same schema.
import { and, eq, max } from 'drizzle-orm'
import type { Tx } from '../../db/client.js'
import { member, organization } from '../../db/idp-tables.js'
import { agentGrants, appInstalls, appUsers, breakGlass, roleAssignments, roles, stores } from '../../db/schema.js'
import { isGrantable, NEVER_FOR_APPS, type Permission, SYSTEM_ROLES, systemRole } from '../../kernel/catalog.js'
import { PermanentSyncError, type RelationSync, type SyncEvent } from '../../outbox/relay.js'
import { del, deleteWhere, isPermanent, obj, PLATFORM_ID, read, type Rel, rel, relKey, type SpiceClient, subj, touch, write } from './client.js'
import { perm } from './schema.js'

/** Events that change nothing SpiceDB knows about. */
const IGNORED = new Set([
  'invitation.created',
  'invitation.canceled',
  'agent.registered',
  'app.registered',
  'product.created',
  'product.updated',
  'order.placed',
  'order.cancelled',
  'order.refunded',
  'payment.captured',
  'shipment.created',
  'shipment.status',
])

const WILDCARDS = ['user', 'agent', 'app']

export function makeSpiceDbSync(c: SpiceClient): RelationSync {
  const last = (ts: (string | undefined)[]) => ts.filter(Boolean).at(-1)

  /** Make the relationships matching `current` equal `desired`: delete extras, touch the rest. */
  async function converge(current: Rel[], desired: Rel[]) {
    const want = new Set(desired.map(relKey))
    const extras = current.filter((r) => !want.has(relKey(r))).map((r) => ({ ...r, optionalCaveat: undefined, optionalExpiresAt: undefined }))
    return write(c, [...del(extras), ...touch(desired)])
  }

  async function merchant(q: Tx, id: string) {
    const [m] = await q.select({ status: organization.status }).from(organization).where(eq(organization.id, id))
    if (!m) return undefined // merchants are never deleted; a row the relay can't see yet isn't ours to remove
    const mo = obj('merchant', id)
    const suspended = WILDCARDS.map((t) => rel(mo, 'suspended', subj(t, '*')))
    return write(c, [
      ...touch([rel(mo, 'platform', subj('platform', PLATFORM_ID)), rel(mo, 'any_user', subj('user', '*'))]),
      ...(m.status === 'suspended' ? touch(suspended) : del(suspended)),
    ])
  }

  async function store(q: Tx, id: string) {
    const [s] = await q.select({ merchantId: stores.merchantId }).from(stores).where(eq(stores.id, id))
    if (!s) return undefined
    const so = obj('store', id)
    return write(c, touch([rel(so, 'merchant', subj('merchant', s.merchantId)), rel(so, 'any_user', subj('user', '*'))]))
  }

  async function role(q: Tx, id: string) {
    let def: { permissions: readonly string[]; limit: number | null } | undefined
    const sys = systemRole(id)
    if (sys) def = { permissions: sys.permissions, limit: null }
    else {
      const [r] = await q.select({ permissions: roles.permissions, limit: roles.refundLimitCents }).from(roles).where(eq(roles.id, id))
      if (r) def = { permissions: r.permissions, limit: r.limit }
    }
    if (!def) return deleteWhere(c, { resourceType: 'role', resourceId: id })
    const ro = obj('role', id)
    const desired: Rel[] = []
    for (const p of def.permissions) {
      if (!isGrantable(p)) continue
      for (const t of ['user', 'agent']) {
        const caveat = p === 'order.refund' && def.limit != null ? { name: 'refund_limit', context: { limit: def.limit } } : undefined
        desired.push(rel(ro, perm(p), subj(t, '*'), { caveat }))
      }
    }
    if (id === 'owner') desired.push(rel(ro, 'role_manage_owner', subj('user', '*')))
    return converge(await read(c, { resourceType: 'role', resourceId: id }), desired)
  }

  async function assignment(q: Tx, id: string) {
    const [a] = await q.select().from(roleAssignments).where(eq(roleAssignments.id, id))
    const binding = subj('role_binding', id)
    if (a) {
      const bo = obj('role_binding', id)
      return write(
        c,
        touch([
          rel(bo, 'subject', subj('user', a.userId)),
          rel(bo, 'subject', subj('user', a.userId, 'delegate')),
          rel(bo, 'role', subj('role', a.roleId)),
          rel(obj(a.scopeType, a.scopeId), 'binding', binding),
        ]),
      )
    }
    // Gone from the DB (unassigned, member removed, role deleted): the row no longer says at which
    // scope, so delete by subject at both scope types.
    return last([
      await deleteWhere(c, { resourceType: 'merchant', relation: 'binding', subjectType: 'role_binding', subjectId: id }),
      await deleteWhere(c, { resourceType: 'store', relation: 'binding', subjectType: 'role_binding', subjectId: id }),
      await deleteWhere(c, { resourceType: 'role_binding', resourceId: id }),
    ])
  }

  /** A user's membership and every binding of theirs: SpiceDB ← member row + role_assignments. */
  async function user(q: Tx, id: string) {
    const [m] = await q.select({ merchantId: member.organizationId }).from(member).where(eq(member.userId, id))
    const tokens = [
      await converge(
        await read(c, { resourceType: 'merchant', relation: 'member', subjectType: 'user', subjectId: id }),
        m ? [rel(obj('merchant', m.merchantId), 'member', subj('user', id))] : [],
      ),
    ]
    const inDb = (await q.select({ id: roleAssignments.id }).from(roleAssignments).where(eq(roleAssignments.userId, id))).map((r) => r.id)
    const inEngine = (await read(c, { resourceType: 'role_binding', relation: 'subject', subjectType: 'user', subjectId: id })).map((r) => r.resource!.objectId)
    for (const aid of new Set([...inDb, ...inEngine])) tokens.push(await assignment(q, aid))
    return last(tokens)
  }

  async function install(q: Tx, id: string) {
    const [i] = await q.select().from(appInstalls).where(eq(appInstalls.id, id))
    if (i) {
      const io = obj('app_install', id)
      const scopes = i.scopes.filter((p): p is Permission => isGrantable(p) && !NEVER_FOR_APPS.includes(p))
      return write(c, touch([rel(obj('store', i.storeId), 'install', subj('app_install', id)), ...scopes.map((p) => rel(io, perm(p), subj('app', i.appId)))]))
    }
    return last([
      await deleteWhere(c, { resourceType: 'store', relation: 'install', subjectType: 'app_install', subjectId: id }),
      await deleteWhere(c, { resourceType: 'app_install', resourceId: id }),
    ])
  }

  async function grant(q: Tx, id: string) {
    const [g] = await q.select().from(agentGrants).where(eq(agentGrants.id, id))
    if (g && !g.revokedAt && g.expiresAt > new Date()) {
      const go = obj('agent_grant', id)
      const expiresAt = g.expiresAt
      return write(
        c,
        touch([
          rel(go, 'agent', subj('agent', g.agentId), { expiresAt }),
          rel(obj('user', g.grantedBy), 'delegate', subj('agent_grant', id, 'agent')), // expiry comes from g#agent
          rel(obj('store', g.storeId), 'grant', subj('agent_grant', id)),
          ...g.permissions.filter(isGrantable).map((p) => rel(go, perm(p), subj('agent', g.agentId), { expiresAt })),
        ]),
      )
    }
    // revoked, expired (SpiceDB has dropped or will drop the expiring part) or unknown
    return last([
      await deleteWhere(c, { resourceType: 'user', relation: 'delegate', subjectType: 'agent_grant', subjectId: id }),
      await deleteWhere(c, { resourceType: 'store', relation: 'grant', subjectType: 'agent_grant', subjectId: id }),
      await deleteWhere(c, { resourceType: 'agent_grant', resourceId: id }),
    ])
  }

  /** The staff member's break-glass on that merchant, expiring at the latest open grant. */
  async function breakGlassOf(q: Tx, id: string) {
    const [b] = await q.select({ actor: breakGlass.actor, merchantId: breakGlass.merchantId }).from(breakGlass).where(eq(breakGlass.id, id))
    if (!b) return undefined
    const [{ until } = { until: null }] = await q
      .select({ until: max(breakGlass.expiresAt) })
      .from(breakGlass)
      .where(and(eq(breakGlass.actor, b.actor), eq(breakGlass.merchantId, b.merchantId)))
    const expiresAt = until ? new Date(until as unknown as string) : null
    if (!expiresAt || expiresAt <= new Date()) return undefined
    return write(c, touch([rel(obj('merchant', b.merchantId), 'break_glass_viewer', subj('staff', b.actor), { expiresAt })]))
  }

  async function staff(q: Tx, id: string) {
    const [u] = await q.select({ role: appUsers.platformRole }).from(appUsers).where(eq(appUsers.id, id))
    const relation = u?.role ? { platform_admin: 'admin', support: 'support' }[u.role] : undefined
    if (u?.role && !relation) throw new PermanentSyncError(`unknown platform role ${u.role}`)
    const current = [
      ...(await read(c, { resourceType: 'platform', resourceId: PLATFORM_ID, relation: 'admin', subjectType: 'staff', subjectId: id })),
      ...(await read(c, { resourceType: 'platform', resourceId: PLATFORM_ID, relation: 'support', subjectType: 'staff', subjectId: id })),
    ]
    return converge(current, relation ? [rel(obj('platform', PLATFORM_ID), relation, subj('staff', id))] : [])
  }

  async function route(ev: SyncEvent, q: Tx): Promise<string | undefined> {
    const id = (k: string) => {
      const v = ev[k]
      if (typeof v !== 'string' || !v) throw new PermanentSyncError(`${ev.type}: missing ${k}`)
      return v
    }
    switch (ev.type) {
      case 'merchant.created':
        return last([await merchant(q, id('merchantId')), await user(q, id('ownerUserId'))])
      case 'merchant.suspended':
      case 'merchant.active':
        return merchant(q, id('merchantId'))
      case 'member.added':
      case 'member.removed':
        return user(q, id('userId'))
      case 'store.created':
        return store(q, id('storeId'))
      case 'role.created':
      case 'role.updated':
        return role(q, id('roleId'))
      case 'role.deleted': {
        // The role's assignments went with it (same transaction, no event each): reconcile every
        // binding that still points at the role.
        const tokens = [await role(q, id('roleId'))]
        const bindings = await read(c, { resourceType: 'role_binding', relation: 'role', subjectType: 'role', subjectId: id('roleId') })
        for (const b of bindings) tokens.push(await assignment(q, b.resource!.objectId))
        return last(tokens)
      }
      case 'role.assigned':
      case 'role.unassigned':
        return assignment(q, id('assignmentId'))
      case 'app.installed':
      case 'app.uninstalled':
        return install(q, id('installId'))
      case 'agent.granted':
      case 'agent.revoked':
        return grant(q, id('grantId'))
      case 'break_glass.opened':
        return breakGlassOf(q, id('breakGlassId'))
      case 'platform_role.granted':
        return staff(q, id('userId'))
      case 'system_roles.sync': {
        const tokens: (string | undefined)[] = []
        for (const r of SYSTEM_ROLES) tokens.push(await role(q, r.id))
        return last(tokens)
      }
    }
    if (IGNORED.has(ev.type)) return undefined
    throw new PermanentSyncError(`spicedb: unhandled event ${ev.type}`)
  }

  return {
    async apply(ev, q) {
      try {
        return await route(ev, q)
      } catch (err) {
        if (err instanceof PermanentSyncError || !isPermanent(err)) throw err
        throw new PermanentSyncError(err instanceof Error ? err.message : String(err), err)
      }
    },
  }
}

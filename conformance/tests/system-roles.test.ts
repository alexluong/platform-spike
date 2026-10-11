// SPEC §3 system roles (owner/admin/developer/staff) against §4 catalog; owner-only rules; last owner.
import { beforeAll, describe, expect, test } from 'vitest'
import { expectConflict, expectDenied, expectError, expectStatus, ok, sortedSet, type Res } from '../src/client'
import { atMerchant, atStore, SYSTEM_ROLES } from '../src/catalog'
import type { Items, Order, Product, Role, Shipment, Store, ClientCreds, Install } from '../src/types'
import {
  type Actor,
  type MerchantWorld,
  installApp,
  merchantWithStore,
  newUser,
  registerAgent,
  registerApp,
  storeScope,
  uniq,
} from '../src/world'

type SystemRole = keyof typeof SYSTEM_ROLES
const ROLES: SystemRole[] = ['owner', 'admin', 'developer', 'staff']

interface RoleWorld {
  m: MerchantWorld
  s: Store
  actor: Actor
  product: Product
  pendingCancel: Order
  pendingCapture: Order
  paidRefund: Order
  paidShip: Order
  shipment: Shipment
  spareUser: Actor
  app: ClientCreds
  install: Install
  agent: ClientCreds
}

async function roleWorld(role: SystemRole): Promise<RoleWorld> {
  const { m, s } = await merchantWithStore()
  const actor = await m.memberWithRole(role, m.scope, role)
  const [product, pendingCancel, pendingCapture, paidRefund, paidShip, shippedOrder, spareUser, app, other] = await Promise.all([
    m.product(s.id, 700),
    m.order(s.id, 1000),
    m.order(s.id, 1000),
    m.paidOrder(s.id, 1000),
    m.paidOrder(s.id, 1000),
    m.paidOrder(s.id, 1000),
    newUser('user', { label: 'spare' }),
    registerApp(['product.view']),
    registerApp(['product.view']),
  ])
  const shipment = await m.ship(shippedOrder.id)
  const install = await installApp(m.owner, s.id, other.id, ['product.view'])
  const agent = await registerAgent(actor)
  return { m, s, actor, product, pendingCancel, pendingCapture, paidRefund, paidShip, shipment, spareUser, app, install, agent }
}

/** One HTTP probe per catalog action that has an endpoint (merchant.update has none; see AMBIGUITIES.md). */
const PROBES: [string, (w: RoleWorld) => Promise<Res>][] = [
  ['merchant.view', (w) => w.actor.api.get(`/api/merchants/${w.m.id}`)],
  ['merchant.view (roles list)', (w) => w.actor.api.get(`/api/merchants/${w.m.id}/roles`)],
  ['store.create', (w) => w.actor.api.post(`/api/merchants/${w.m.id}/stores`, { name: uniq('store') })],
  ['member.manage', (w) => w.actor.api.post(`/api/merchants/${w.m.id}/members`, { userId: w.spareUser.id })],
  // every system role holds store.view, so the guardrail cannot be the reason for a denial here
  ['role.manage', (w) => w.actor.api.post(`/api/merchants/${w.m.id}/roles`, { name: uniq('role'), permissions: ['store.view'] })],
  ['store.view', (w) => w.actor.api.get(`/api/stores/${w.s.id}`)],
  ['product.create', (w) => w.actor.api.post(`/api/stores/${w.s.id}/products`, { title: uniq('p'), priceCents: 100 })],
  ['product.update', (w) => w.actor.api.patch(`/api/products/${w.product.id}`, { title: uniq('renamed') })],
  ['order.view', (w) => w.actor.api.get(`/api/stores/${w.s.id}/orders`)],
  ['order.view (single)', (w) => w.actor.api.get(`/api/orders/${w.paidRefund.id}`)],
  ['order.cancel', (w) => w.actor.api.post(`/api/orders/${w.pendingCancel.id}/cancel`)],
  ['order.refund', (w) => w.actor.api.post(`/api/orders/${w.paidRefund.id}/refund`, { amountCents: 100 })],
  ['payment.capture', (w) => w.actor.api.post(`/api/orders/${w.pendingCapture.id}/payments/capture`)],
  ['payment.view', (w) => w.actor.api.get(`/api/orders/${w.paidRefund.id}/payments`)],
  ['shipment.create', (w) => w.actor.api.post(`/api/orders/${w.paidShip.id}/shipments`, { carrier: 'dhl' })],
  ['shipment.update', (w) => w.actor.api.post(`/api/shipments/${w.shipment.id}/status`, { status: 'in_transit' })],
  ['shipment.view', (w) => w.actor.api.get(`/api/orders/${w.paidShip.id}/shipments`)],
  ['app.install', (w) => w.actor.api.post(`/api/stores/${w.s.id}/apps`, { appId: w.app.id, scopes: ['product.view'] })],
  ['app.uninstall', (w) => w.actor.api.delete(`/api/stores/${w.s.id}/apps/${w.install.id}`)],
  ['app.view', (w) => w.actor.api.get(`/api/stores/${w.s.id}/apps`)],
  [
    'agent.grant',
    (w) => w.actor.api.post(`/api/stores/${w.s.id}/agent-grants`, { agentId: w.agent.id, permissions: ['store.view'], expiresInSeconds: 600 }),
  ],
]

for (const role of ROLES) {
  describe(`system role ${role} at merchant scope`, () => {
    let w: RoleWorld
    beforeAll(async () => {
      w = await roleWorld(role)
    })

    test.each(PROBES)(`%s`, async (label, probe) => {
      const action = label.split(' ')[0]
      const res = await probe(w)
      if (SYSTEM_ROLES[role].includes(action)) ok(res)
      else expectDenied(res)
    })

    test('/api/me/permissions?storeId= is exactly the role’s store-scope actions', async () => {
      const got = ok(await w.actor.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${w.s.id}`), 200).actions
      expect(sortedSet(got)).toEqual(atStore(SYSTEM_ROLES[role]))
    })

    test('/api/me/permissions?merchantId= is exactly the role’s merchant-scope actions', async () => {
      const got = ok(await w.actor.api.get<{ actions: string[] }>(`/api/me/permissions?merchantId=${w.m.id}`), 200).actions
      expect(sortedSet(got)).toEqual(atMerchant(SYSTEM_ROLES[role]))
    })
  })
}

describe('system roles are listed and immutable', () => {
  test('GET roles lists owner/admin/developer/staff as system roles with the §3 permissions', async () => {
    const { m } = await merchantWithStore()
    const roles = ok(await m.owner.api.get<Items<Role>>(`/api/merchants/${m.id}/roles`), 200).items
    for (const r of ROLES) {
      const found = roles.find((x) => x.id === r)
      expect(found, `system role ${r} in ${JSON.stringify(roles)}`).toBeDefined()
      expect(found!.system).toBe(true)
      expect(sortedSet(found!.permissions)).toEqual(sortedSet(SYSTEM_ROLES[r]))
    }
  })

  test('PATCH or DELETE of a system role is rejected (4xx) and the role is unchanged', async () => {
    const { m } = await merchantWithStore()
    expectStatus(await m.owner.api.patch(`/api/merchants/${m.id}/roles/staff`, { permissions: ['order.view'] }), 400, 403, 409)
    expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/roles/developer`), 400, 403, 409)
    const roles = ok(await m.owner.api.get<Items<Role>>(`/api/merchants/${m.id}/roles`), 200).items
    expect(sortedSet(roles.find((x) => x.id === 'staff')!.permissions)).toEqual(sortedSet(SYSTEM_ROLES.staff))
    expect(roles.some((x) => x.id === 'developer')).toBe(true)
  })
})

describe('store-scoped system role', () => {
  test('staff at store s1 acts on s1 only', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const staff = await m.memberWithRole('staff', storeScope(s))
    ok(await staff.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await staff.api.post(`/api/stores/${s.id}/products`, { title: uniq('p'), priceCents: 100 }), 201)
    expectDenied(await staff.api.get(`/api/stores/${s2.id}/orders`))
    expectDenied(await staff.api.post(`/api/stores/${s2.id}/products`, { title: uniq('p'), priceCents: 100 }))
  })
})

describe('owner-only rules', () => {
  test('owner can assign owner', async () => {
    const { m } = await merchantWithStore()
    const u = await m.member()
    ok(await m.owner.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: 'owner', scope: m.scope }), 201)
    // the new owner can manage roles
    ok(await u.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.view'] }), 201)
  })

  test('admin cannot assign owner (403), but can assign admin', async () => {
    const { m } = await merchantWithStore()
    const admin = await m.memberWithRole('admin')
    const u = await m.member()
    expectDenied(await admin.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: 'owner', scope: m.scope }))
    expectDenied(await admin.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: admin.id, roleId: 'owner', scope: m.scope }))
    ok(await admin.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: 'admin', scope: m.scope }), 201)
  })

  test('admin cannot remove an owner assignment or an owner member; owner can', async () => {
    const { m } = await merchantWithStore()
    const admin = await m.memberWithRole('admin')
    const owner2 = await m.memberWithRole('owner')
    expectDenied(await admin.api.delete(`/api/merchants/${m.id}/role-assignments/${owner2.assignment.id}`))
    expectDenied(await admin.api.delete(`/api/merchants/${m.id}/members/${owner2.id}`))
    ok(await owner2.api.get(`/api/merchants/${m.id}`), 200) // still an owner
    expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/role-assignments/${owner2.assignment.id}`), 204)
    expectDenied(await owner2.api.post(`/api/merchants/${m.id}/stores`, { name: uniq('store') }))
  })
})

describe('last owner', () => {
  test('removing the only owner as a member → 409 last_owner', async () => {
    const { m } = await merchantWithStore()
    expectConflict(await m.owner.api.delete(`/api/merchants/${m.id}/members/${m.owner.id}`), 'last_owner')
    ok(await m.owner.api.get(`/api/merchants/${m.id}`), 200)
  })

  test('with two owners one can go; then the remaining owner assignment cannot be removed (409 last_owner)', async () => {
    const { m } = await merchantWithStore()
    const owner2 = await m.memberWithRole('owner')
    // original owner leaves (allowed: owner2 remains)
    expectStatus(await owner2.api.delete(`/api/merchants/${m.id}/members/${m.owner.id}`), 204)
    expectDenied(await m.owner.api.get(`/api/merchants/${m.id}`), { crossTenant: true }) // no longer a member
    // owner2 is now the last owner: removing that assignment is a state violation
    expectConflict(await owner2.api.delete(`/api/merchants/${m.id}/role-assignments/${owner2.assignment.id}`), 'last_owner')
    expectConflict(await owner2.api.delete(`/api/merchants/${m.id}/members/${owner2.id}`), 'last_owner')
    ok(await owner2.api.get(`/api/merchants/${m.id}`), 200)
  })

  test('a caller without member.manage gets 403, not 409, on the last owner', async () => {
    const { m } = await merchantWithStore()
    const staff = await m.memberWithRole('staff')
    const res = await staff.api.delete(`/api/merchants/${m.id}/members/${m.owner.id}`)
    expectError(res, 403)
  })
})

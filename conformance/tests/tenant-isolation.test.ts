// SPEC §1.6 tenant isolation, §2 customers per store, §9 cross-tenant 403|404 (never 200).
import { beforeAll, describe, expect, test } from 'vitest'
import { expectDenied, expectStatus, ok, type Res } from '../src/client'
import { FORBIDDEN_APP_SCOPES, STORE_SCOPE_ACTIONS } from '../src/catalog'
import type { Assignment, ClientCreds, Grant, Install, Items, Order, Product, Role, Shipment, Store } from '../src/types'
import {
  type Actor,
  type ClientActor,
  type MerchantWorld,
  clientActor,
  grantAgent,
  installApp,
  installedApp,
  merchantWithStore,
  newCustomer,
  newUser,
  registerAgent,
  registerApp,
  storeScope,
  uniq,
} from '../src/world'
import type { Api } from '../src/client'

interface Victim {
  m: MerchantWorld
  s: Store
  product: Product
  pending: Order
  paid: Order
  paidForShip: Order
  shipment: Shipment
  role: Role
  member: Actor & { assignment: Assignment }
  install: Install
  grant: Grant
  appToInstall: ClientCreds
  spare: Actor
}

interface Attacker {
  m: MerchantWorld
  s: Store
  app: ClientActor
  agent: ClientActor
  agentCreds: ClientCreds
}

let B: Victim
let A: Attacker

beforeAll(async () => {
  const [b, a] = await Promise.all([merchantWithStore(), merchantWithStore()])
  // Victim merchant B with one of everything.
  const [product, pending, paid, paidForShip, shippedOrder, role, appForInstall, appToInstall, spare] = await Promise.all([
    b.m.product(b.s.id, 900),
    b.m.order(b.s.id, 1000),
    b.m.paidOrder(b.s.id, 1000),
    b.m.paidOrder(b.s.id, 1000),
    b.m.paidOrder(b.s.id, 1000),
    b.m.role(['order.view']),
    registerApp(['order.view']),
    registerApp(['product.view']),
    newUser('user', { label: 'spare' }),
  ])
  const shipment = await b.m.ship(shippedOrder.id)
  const member = await b.m.memberWithRole(role.id, storeScope(b.s))
  const install = await installApp(b.m.owner, b.s.id, appForInstall.id, ['order.view'])
  const bAgent = await registerAgent(b.m.owner)
  const grant = await grantAgent(b.m.owner, b.s.id, bAgent.id, ['order.view'])
  B = { m: b.m, s: b.s, product, pending, paid, paidForShip, shipment, role, member, install, grant, appToInstall, spare }

  // Attacker merchant A: an owner, an app and an agent with broad powers on A's store.
  const appScopes = STORE_SCOPE_ACTIONS.filter((x) => !(FORBIDDEN_APP_SCOPES as readonly string[]).includes(x))
  const app = await installedApp(a.m.owner, a.s.id, appScopes)
  const agentCreds = await registerAgent(a.m.owner)
  const agentPerms = STORE_SCOPE_ACTIONS.filter((x) => x !== 'role.manage' && x !== 'agent.grant')
  await grantAgent(a.m.owner, a.s.id, agentCreds.id, agentPerms)
  const agent = await clientActor(agentCreds, 'agent-A')
  A = { m: a.m, s: a.s, app, agent, agentCreds }
})

/** Every merchant/store endpoint of §9, aimed at merchant B. */
const SWEEP: [string, (api: Api) => Promise<Res>][] = [
  ['GET merchant', (x) => x.get(`/api/merchants/${B.m.id}`)],
  ['POST member', (x) => x.post(`/api/merchants/${B.m.id}/members`, { userId: B.spare.id })],
  ['DELETE member', (x) => x.delete(`/api/merchants/${B.m.id}/members/${B.member.id}`)],
  ['GET roles', (x) => x.get(`/api/merchants/${B.m.id}/roles`)],
  ['POST role', (x) => x.post(`/api/merchants/${B.m.id}/roles`, { name: uniq('evil'), permissions: ['order.view'] })],
  ['PATCH role', (x) => x.patch(`/api/merchants/${B.m.id}/roles/${B.role.id}`, { permissions: ['order.view', 'order.refund'] })],
  ['DELETE role', (x) => x.delete(`/api/merchants/${B.m.id}/roles/${B.role.id}`)],
  [
    'POST role-assignment',
    (x) => x.post(`/api/merchants/${B.m.id}/role-assignments`, { userId: B.member.id, roleId: 'admin', scope: { type: 'merchant', id: B.m.id } }),
  ],
  ['DELETE role-assignment', (x) => x.delete(`/api/merchants/${B.m.id}/role-assignments/${B.member.assignment.id}`)],
  ['POST store', (x) => x.post(`/api/merchants/${B.m.id}/stores`, { name: uniq('evil') })],
  ['GET store', (x) => x.get(`/api/stores/${B.s.id}`)],
  ['POST product', (x) => x.post(`/api/stores/${B.s.id}/products`, { title: 'evil', priceCents: 1 })],
  ['PATCH product', (x) => x.patch(`/api/products/${B.product.id}`, { priceCents: 1 })],
  ['GET store orders', (x) => x.get(`/api/stores/${B.s.id}/orders`)],
  ['GET order', (x) => x.get(`/api/orders/${B.paid.id}`)],
  ['POST cancel', (x) => x.post(`/api/orders/${B.pending.id}/cancel`)],
  ['POST refund', (x) => x.post(`/api/orders/${B.paid.id}/refund`, { amountCents: 100 })],
  ['POST capture', (x) => x.post(`/api/orders/${B.pending.id}/payments/capture`)],
  ['GET payments', (x) => x.get(`/api/orders/${B.paid.id}/payments`)],
  ['POST shipment', (x) => x.post(`/api/orders/${B.paidForShip.id}/shipments`, { carrier: 'evil' })],
  ['POST shipment status', (x) => x.post(`/api/shipments/${B.shipment.id}/status`, { status: 'delivered' })],
  ['GET shipments', (x) => x.get(`/api/orders/${B.paidForShip.id}/shipments`)],
  ['POST app install', (x) => x.post(`/api/stores/${B.s.id}/apps`, { appId: B.appToInstall.id, scopes: ['product.view'] })],
  ['DELETE app install', (x) => x.delete(`/api/stores/${B.s.id}/apps/${B.install.id}`)],
  ['GET apps', (x) => x.get(`/api/stores/${B.s.id}/apps`)],
  ['POST agent-grant', (x) => x.post(`/api/stores/${B.s.id}/agent-grants`, { agentId: A.agentCreds.id, permissions: ['order.view'], expiresInSeconds: 600 })],
  ['DELETE agent-grant', (x) => x.delete(`/api/stores/${B.s.id}/agent-grants/${B.grant.id}`)],
]

describe('owner of merchant A against merchant B', () => {
  test.each(SWEEP)('%s → 403|404', async (_name, call) => {
    expectDenied(await call(A.m.owner.api), { crossTenant: true })
  })

  test('GET B stores → 403|404, or 200 with no items', async () => {
    const res = await A.m.owner.api.get<Items<Store>>(`/api/merchants/${B.m.id}/stores`)
    if (res.status === 200) expect(res.body.items).toEqual([])
    else expectDenied(res, { crossTenant: true })
  })

  test('/api/me/permissions on B → 403|404, or 200 with no actions', async () => {
    for (const q of [`storeId=${B.s.id}`, `merchantId=${B.m.id}`]) {
      const res = await A.m.owner.api.get<{ actions: string[] }>(`/api/me/permissions?${q}`)
      if (res.status === 200) expect(res.body.actions).toEqual([])
      else expectDenied(res, { crossTenant: true })
    }
  })

  test('cannot reach B through A’s own merchant path (assignment scoped to B’s store)', async () => {
    const aRole = await A.m.role(['order.view'])
    const aMember = await A.m.member()
    const res = await A.m.owner.api.post(`/api/merchants/${A.m.id}/role-assignments`, { userId: aMember.id, roleId: aRole.id, scope: storeScope(B.s) })
    expectStatus(res, 400, 403, 404)
    expectDenied(await aMember.api.get(`/api/stores/${B.s.id}/orders`), { crossTenant: true })
  })

  test('cannot assign A’s role to a member of B (4xx)', async () => {
    const aRole = await A.m.role(['order.view'])
    const res = await A.m.owner.api.post(`/api/merchants/${A.m.id}/role-assignments`, { userId: B.member.id, roleId: aRole.id, scope: A.m.scope })
    expectStatus(res, 400, 403, 404, 409)
  })
})

describe('app of merchant A against merchant B', () => {
  test.each(SWEEP.filter(([n]) => !/member|role|agent-grant|app install/.test(n)))('%s → 403|404', async (_name, call) => {
    expectDenied(await call(A.app.api), { crossTenant: true })
  })
})

describe('agent of merchant A against merchant B', () => {
  test.each(SWEEP.filter(([n]) => !/member|role|app install|agent-grant/.test(n)))('%s → 403|404', async (_name, call) => {
    expectDenied(await call(A.agent.api), { crossTenant: true })
  })

  test('B cannot grant A’s agent on B’s store (4xx)', async () => {
    const res = await B.m.owner.api.post(`/api/stores/${B.s.id}/agent-grants`, { agentId: A.agentCreds.id, permissions: ['order.view'], expiresInSeconds: 600 })
    expectStatus(res, 400, 403, 404)
    expectDenied(await A.agent.api.get(`/api/stores/${B.s.id}/orders`), { crossTenant: true })
  })
})

describe('customers', () => {
  test('a customer reads their own order; another customer cannot', async () => {
    const { m, s } = await merchantWithStore()
    const [c1, c2] = await Promise.all([newCustomer('c1'), newCustomer('c2')])
    const o = await m.order(s.id, 1000, c1)
    expect(ok(await c1.api.get<Order>(`/api/orders/${o.id}`), 200)).toMatchObject({ id: o.id, customerId: c1.id })
    expectStatus(await c2.api.get(`/api/orders/${o.id}`), 403, 404)
  })

  test('/api/me/orders returns only own orders, across stores', async () => {
    const [x, y] = await Promise.all([merchantWithStore(), merchantWithStore()])
    const [c1, c2] = await Promise.all([newCustomer('c1'), newCustomer('c2')])
    const o1 = await x.m.order(x.s.id, 1000, c1)
    const o2 = await y.m.order(y.s.id, 2000, c1)
    const other = await x.m.order(x.s.id, 3000, c2)
    const mine = ok(await c1.api.get<Items<Order>>('/api/me/orders'), 200).items.map((o) => o.id)
    expect(mine).toContain(o1.id)
    expect(mine).toContain(o2.id)
    expect(mine).not.toContain(other.id)
    expect(mine.length).toBe(2)
    const theirs = ok(await c2.api.get<Items<Order>>('/api/me/orders'), 200).items.map((o) => o.id)
    expect(theirs).toEqual([other.id])
  })

  test('a customer has no merchant permissions, even on their own order or store', async () => {
    const { m, s } = await merchantWithStore()
    const c = await newCustomer()
    const o = await m.order(s.id, 1000, c)
    expectDenied(await c.api.get(`/api/stores/${s.id}/orders`))
    expectDenied(await c.api.post(`/api/orders/${o.id}/payments/capture`))
    expectDenied(await c.api.post(`/api/orders/${o.id}/cancel`))
    expectDenied(await c.api.post(`/api/orders/${o.id}/refund`, { amountCents: 1 }))
    expectDenied(await c.api.get(`/api/orders/${o.id}/payments`))
    expectDenied(await c.api.post(`/api/stores/${s.id}/products`, { title: 'x', priceCents: 1 }))
    expectDenied(await c.api.get(`/api/merchants/${m.id}`))
    expectDenied(await c.api.post('/api/agents', { name: uniq('agent') }))
    expect(ok(await c.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s.id}`), 200).actions).toEqual([])
  })

  test('a merchant user is not a customer: /api/me/orders and order placement → 403', async () => {
    const { m, s } = await merchantWithStore()
    const p = await m.product(s.id)
    expectDenied(await m.owner.api.post(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 1 }] }))
    expectDenied(await m.owner.api.get('/api/me/orders'))
  })

  test('merchant users with order.view see the store’s orders, not other stores’', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const [o1, o2] = await Promise.all([m.order(s.id), m.order(s2.id)])
    const ids = ok(await m.owner.api.get<Items<Order>>(`/api/stores/${s.id}/orders`), 200).items.map((o) => o.id)
    expect(ids).toContain(o1.id)
    expect(ids).not.toContain(o2.id)
  })
})

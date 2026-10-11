// SPEC §7 platform staff (without break-glass) and suspension; §9 platform endpoints.
import { describe, expect, test } from 'vitest'
import { expectDenied, expectStatus, ok } from '../src/client'
import type { Items, Merchant, Order, Role } from '../src/types'
import {
  grantedAgent,
  installedApp,
  merchantWithStore,
  newCustomer,
  newMerchant,
  newSupport,
  newUser,
  platformAdmin,
  registerApp,
  uniq,
} from '../src/world'

describe('platform admin: merchants', () => {
  test('creates a merchant → 201 {id, name, status: active}; owner gets owner at merchant scope', async () => {
    const admin = await platformAdmin()
    const owner = await newUser('user', { label: 'owner' })
    const name = uniq('merchant')
    const m = ok(await admin.api.post<Merchant>('/api/platform/merchants', { name, ownerUserId: owner.id }), 201)
    expect(m).toMatchObject({ name, status: 'active' })
    expect(typeof m.id).toBe('string')
    // owner holds every grantable permission there
    ok(await owner.api.get(`/api/merchants/${m.id}`), 200)
    ok(await owner.api.post(`/api/merchants/${m.id}/stores`, { name: uniq('store') }), 201)
  })

  test('lists merchants (includes a newly created one)', async () => {
    const admin = await platformAdmin()
    const m = await newMerchant()
    const body = ok(await admin.api.get<Items<Merchant>>('/api/platform/merchants'), 200)
    expect(body.items.find((x) => x.id === m.id)).toMatchObject({ id: m.id, name: m.name, status: 'active' })
  })

  test('suspend → {status: suspended}; reinstate → {status: active}; list reflects it', async () => {
    const admin = await platformAdmin()
    const m = await newMerchant()
    expect(ok(await admin.api.post(`/api/platform/merchants/${m.id}/suspend`), 200)).toMatchObject({ id: m.id, status: 'suspended' })
    let list = ok(await admin.api.get<Items<Merchant>>('/api/platform/merchants'), 200)
    expect(list.items.find((x) => x.id === m.id)?.status).toBe('suspended')
    expect(ok(await admin.api.post(`/api/platform/merchants/${m.id}/reinstate`), 200)).toMatchObject({ id: m.id, status: 'active' })
    list = ok(await admin.api.get<Items<Merchant>>('/api/platform/merchants'), 200)
    expect(list.items.find((x) => x.id === m.id)?.status).toBe('active')
  })
})

describe('support', () => {
  test('can list merchants', async () => {
    const [support, m] = await Promise.all([newSupport(), newMerchant()])
    const body = ok(await support.api.get<Items<Merchant>>('/api/platform/merchants'), 200)
    expect(body.items.some((x) => x.id === m.id)).toBe(true)
  })

  test('cannot create merchants', async () => {
    const [support, owner] = await Promise.all([newSupport(), newUser('user')])
    expectDenied(await support.api.post('/api/platform/merchants', { name: uniq('merchant'), ownerUserId: owner.id }))
  })

  test('cannot suspend or reinstate', async () => {
    const [support, m] = await Promise.all([newSupport(), newMerchant()])
    expectDenied(await support.api.post(`/api/platform/merchants/${m.id}/suspend`))
    await m.suspend()
    expectDenied(await support.api.post(`/api/platform/merchants/${m.id}/reinstate`))
  })

  test('cannot register apps or view the audit log', async () => {
    const [support, m] = await Promise.all([newSupport(), newMerchant()])
    expectDenied(await support.api.post('/api/platform/apps', { name: uniq('app'), scopes: ['product.view'] }))
    expectDenied(await support.api.get(`/api/platform/audit?merchantId=${m.id}`))
  })
})

describe('non-platform principals on platform endpoints', () => {
  test('merchant owner and customer are denied on every platform endpoint', async () => {
    const [m, customer] = await Promise.all([newMerchant(), newCustomer()])
    for (const who of [m.owner, customer]) {
      expectDenied(await who.api.get('/api/platform/merchants'))
      expectDenied(await who.api.post('/api/platform/merchants', { name: uniq('merchant'), ownerUserId: who.id }))
      expectDenied(await who.api.post(`/api/platform/merchants/${m.id}/suspend`))
      expectDenied(await who.api.post(`/api/platform/merchants/${m.id}/reinstate`))
      expectDenied(await who.api.post('/api/platform/apps', { name: uniq('app'), scopes: ['product.view'] }))
      expectDenied(await who.api.post('/api/platform/break-glass', { merchantId: m.id, reason: 'x', minutes: 5 }))
      expectDenied(await who.api.get(`/api/platform/audit?merchantId=${m.id}`))
    }
  })
})

describe('platform staff have no access to merchant data without break-glass', () => {
  for (const kind of ['platform_admin', 'support'] as const) {
    test(`${kind}: reads and writes on merchant data → 403`, async () => {
      const staff = kind === 'platform_admin' ? await platformAdmin() : await newSupport()
      const { m, s } = await merchantWithStore()
      const order = await m.paidOrder(s.id, 1000)
      const product = await m.product(s.id)
      // reads
      expectDenied(await staff.api.get(`/api/merchants/${m.id}`))
      expectDenied(await staff.api.get(`/api/merchants/${m.id}/roles`))
      expectDenied(await staff.api.get(`/api/stores/${s.id}`))
      expectDenied(await staff.api.get(`/api/stores/${s.id}/orders`))
      expectDenied(await staff.api.get(`/api/orders/${order.id}`))
      expectDenied(await staff.api.get(`/api/orders/${order.id}/payments`))
      expectDenied(await staff.api.get(`/api/stores/${s.id}/apps`))
      // writes
      expectDenied(await staff.api.post(`/api/stores/${s.id}/products`, { title: 'x', priceCents: 1 }))
      expectDenied(await staff.api.patch(`/api/products/${product.id}`, { title: 'hacked' }))
      expectDenied(await staff.api.post(`/api/orders/${order.id}/refund`, { amountCents: 100 }))
      expectDenied(await staff.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.view'] }))
      // permissions report nothing
      const perms = ok(await staff.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s.id}`), 200)
      expect(perms.actions).toEqual([])
    })
  }
})

describe('suspended merchant', () => {
  test('users get 403 merchant_suspended on reads and writes; reinstate restores', async () => {
    const { m, s } = await merchantWithStore()
    const staff = await m.memberWithRole('staff')
    await m.suspend()
    for (const who of [m.owner, staff]) {
      expectDenied(await who.api.get(`/api/merchants/${m.id}`), { code: 'merchant_suspended' })
      expectDenied(await who.api.get(`/api/stores/${s.id}/orders`), { code: 'merchant_suspended' })
      expectDenied(await who.api.post(`/api/stores/${s.id}/products`, { title: 'x', priceCents: 1 }), { code: 'merchant_suspended' })
    }
    expectDenied(await m.owner.api.post(`/api/merchants/${m.id}/stores`, { name: uniq('store') }), { code: 'merchant_suspended' })
    expectDenied(await m.owner.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.view'] }), {
      code: 'merchant_suspended',
    })
    await m.reinstate()
    ok(await m.owner.api.get(`/api/merchants/${m.id}`), 200)
    ok(await staff.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await m.owner.api.post(`/api/stores/${s.id}/products`, { title: uniq('p'), priceCents: 100 }), 201)
  })

  test('apps and agents get 403 merchant_suspended; reinstate restores', async () => {
    const { m, s } = await merchantWithStore()
    const app = await installedApp(m.owner, s.id, ['order.view'])
    const agent = await grantedAgent(m.owner, s.id, ['order.view'])
    ok(await app.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
    await m.suspend()
    expectDenied(await app.api.get(`/api/stores/${s.id}/orders`), { code: 'merchant_suspended' })
    expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`), { code: 'merchant_suspended' })
    await m.reinstate()
    ok(await app.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
  })

  test('an app of another merchant does not learn that a merchant is suspended (regression: review-c)', async () => {
    const [{ m, s }, B] = await Promise.all([merchantWithStore(), merchantWithStore()])
    const app = await installedApp(B.m.owner, B.s.id, ['order.view'])
    await m.suspend()
    const res = await app.api.get(`/api/stores/${s.id}/orders`)
    expectDenied(res, { crossTenant: true })
    expect(res.body?.error?.code).not.toBe('merchant_suspended')
  })

  test('customers cannot place orders (403); reinstate restores', async () => {
    const { m, s } = await merchantWithStore()
    const p = await m.product(s.id, 500)
    const c = await m.customer()
    await m.suspend()
    expectDenied(await c.api.post(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 1 }] }))
    await m.reinstate()
    const o = ok(await c.api.post<Order>(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 1 }] }), 201)
    expect(o.status).toBe('pending')
  })

  test('platform actions still work on a suspended merchant', async () => {
    const admin = await platformAdmin()
    const support = await newSupport()
    const m = await newMerchant()
    await m.suspend()
    const list = ok(await admin.api.get<Items<Merchant>>('/api/platform/merchants'), 200)
    expect(list.items.find((x) => x.id === m.id)?.status).toBe('suspended')
    ok(await support.api.get('/api/platform/merchants'), 200)
    ok(await admin.api.get(`/api/platform/audit?merchantId=${m.id}`), 200)
    ok(await support.api.post('/api/platform/break-glass', { merchantId: m.id, reason: 'investigating', minutes: 5 }), 201)
    expect((await registerApp(['product.view'])).clientId).toBeTruthy()
  })

  test('suspending one merchant does not affect another', async () => {
    const [a, b] = await Promise.all([merchantWithStore(), merchantWithStore()])
    await a.m.suspend()
    ok(await b.m.owner.api.get<Items<Role>>(`/api/merchants/${b.m.id}/roles`), 200)
    ok(await b.m.owner.api.get(`/api/stores/${b.s.id}/orders`), 200)
    expectStatus(await a.m.owner.api.get(`/api/stores/${a.s.id}/orders`), 403)
  })
})

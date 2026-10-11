// SPEC §5 apps: registration, forbidden scopes, install guardrails, scope-exact access, uninstall.
import { describe, expect, test } from 'vitest'
import { expectDenied, expectError, expectStatus, ok, sortedSet } from '../src/client'
import { FORBIDDEN_APP_SCOPES } from '../src/catalog'
import type { ClientCreds, Install, Items } from '../src/types'
import { clientActor, installApp, installedApp, merchantWithStore, newSupport, platformAdmin, registerApp, uniq } from '../src/world'

describe('registration', () => {
  test('platform admin registers an app → 201 {id, clientId, clientSecret}', async () => {
    const admin = await platformAdmin()
    const app = ok(await admin.api.post<ClientCreds>('/api/platform/apps', { name: uniq('app'), scopes: ['order.view', 'product.create'] }), 201)
    expect(typeof app.id).toBe('string')
    expect(app.clientId).toBeTruthy()
    expect(app.clientSecret).toBeTruthy()
  })

  test('support, merchant owner and customer cannot register apps', async () => {
    const [support, { m }] = await Promise.all([newSupport(), merchantWithStore()])
    const c = await m.customer()
    for (const who of [support, m.owner, c]) {
      expectDenied(await who.api.post('/api/platform/apps', { name: uniq('app'), scopes: ['order.view'] }))
    }
  })

  test.each(FORBIDDEN_APP_SCOPES.map((x) => [x]))('requesting %s → 400 not_grantable_to_apps', async (scope) => {
    const admin = await platformAdmin()
    expectError(await admin.api.post('/api/platform/apps', { name: uniq('app'), scopes: ['order.view', scope] }), 400, 'not_grantable_to_apps')
  })

  test('requesting a non-grantable platform action → 400', async () => {
    const admin = await platformAdmin()
    expectError(await admin.api.post('/api/platform/apps', { name: uniq('app'), scopes: ['platform.merchant.view'] }), 400, [
      'not_grantable',
      'not_grantable_to_apps',
      'invalid_input',
    ])
  })
})

describe('install', () => {
  test('owner installs with scopes ⊆ requested → 201 {id, appId, storeId, scopes}; listed via app.view', async () => {
    const { m, s } = await merchantWithStore()
    const app = await registerApp(['order.view', 'product.create', 'payment.view'])
    const inst = ok(await m.owner.api.post<Install>(`/api/stores/${s.id}/apps`, { appId: app.id, scopes: ['order.view', 'product.create'] }), 201)
    expect(inst).toMatchObject({ appId: app.id, storeId: s.id })
    expect(sortedSet(inst.scopes)).toEqual(['order.view', 'product.create'])
    const list = ok(await m.owner.api.get<Items<Install>>(`/api/stores/${s.id}/apps`), 200).items
    expect(list.find((x) => x.id === inst.id)).toMatchObject({ appId: app.id, storeId: s.id })
  })

  test('scopes not ⊆ requested → 400', async () => {
    const { m, s } = await merchantWithStore()
    const app = await registerApp(['order.view'])
    expectError(await m.owner.api.post(`/api/stores/${s.id}/apps`, { appId: app.id, scopes: ['order.view', 'payment.view'] }), 400)
  })

  test('installer must hold every scope at that store → 403 escalation', async () => {
    const { m, s } = await merchantWithStore()
    const dev = await m.memberWithRole('developer') // app.install, order.view, product.view; no payment.view
    const app = await registerApp(['order.view', 'payment.view'])
    expectDenied(await dev.api.post(`/api/stores/${s.id}/apps`, { appId: app.id, scopes: ['order.view', 'payment.view'] }), { code: 'escalation' })
    ok(await dev.api.post(`/api/stores/${s.id}/apps`, { appId: app.id, scopes: ['order.view'] }), 201)
  })

  test('scope held only at another store does not count → 403 escalation', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const u = await m.memberWithPerms(['app.install'], m.scope)
    const pv = await m.role(['payment.view'])
    await m.assign(u, pv.id, { type: 'store', id: s2.id })
    const app = await registerApp(['payment.view'])
    expectDenied(await u.api.post(`/api/stores/${s.id}/apps`, { appId: app.id, scopes: ['payment.view'] }), { code: 'escalation' })
    ok(await u.api.post(`/api/stores/${s2.id}/apps`, { appId: app.id, scopes: ['payment.view'] }), 201)
  })

  test('without app.install → 403', async () => {
    const { m, s } = await merchantWithStore()
    const staff = await m.memberWithRole('staff')
    const app = await registerApp(['order.view'])
    expectDenied(await staff.api.post(`/api/stores/${s.id}/apps`, { appId: app.id, scopes: ['order.view'] }))
  })
})

describe('app token access', () => {
  test('exactly its scopes on the installed store', async () => {
    const { m, s } = await merchantWithStore()
    const creds = await registerApp(['order.view', 'product.create', 'payment.view'])
    await installApp(m.owner, s.id, creds.id, ['order.view', 'product.create'])
    const app = await clientActor(creds, 'app')
    const pending = await m.order(s.id)
    const paid = await m.paidOrder(s.id)

    ok(await app.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await app.api.get(`/api/orders/${paid.id}`), 200)
    ok(await app.api.post(`/api/stores/${s.id}/products`, { title: uniq('p'), priceCents: 100 }), 201)
    // requested at registration but not granted at install
    expectDenied(await app.api.get(`/api/orders/${paid.id}/payments`))
    // never requested
    expectDenied(await app.api.post(`/api/orders/${pending.id}/payments/capture`))
    expectDenied(await app.api.post(`/api/orders/${pending.id}/cancel`))
    expectDenied(await app.api.post(`/api/orders/${paid.id}/refund`, { amountCents: 1 }))
    expectDenied(await app.api.get(`/api/stores/${s.id}/apps`))
    expect((await m.getOrder(pending.id)).status).toBe('pending')
  })

  test('nothing on another store of the same merchant', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const app = await installedApp(m.owner, s.id, ['order.view', 'product.create'])
    const o2 = await m.order(s2.id)
    expectDenied(await app.api.get(`/api/stores/${s2.id}/orders`))
    expectDenied(await app.api.get(`/api/orders/${o2.id}`))
    expectDenied(await app.api.post(`/api/stores/${s2.id}/products`, { title: 'x', priceCents: 1 }))
  })

  test('no merchant-level or role actions', async () => {
    const { m, s } = await merchantWithStore()
    const app = await installedApp(m.owner, s.id, ['order.view'])
    expectDenied(await app.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('r'), permissions: ['order.view'] }))
    expectDenied(await app.api.post(`/api/merchants/${m.id}/stores`, { name: uniq('s') }))
    expectDenied(await app.api.post('/api/agents', { name: uniq('agent') }))
  })

  test('/api/me/permissions for an app = its scopes at the installed store, none elsewhere', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const app = await installedApp(m.owner, s.id, ['order.view', 'product.create'])
    expect(sortedSet(ok(await app.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s.id}`), 200).actions)).toEqual([
      'order.view',
      'product.create',
    ])
    expect(ok(await app.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s2.id}`), 200).actions).toEqual([])
  })

  test('uninstall cuts access on the next request', async () => {
    const { m, s } = await merchantWithStore()
    const app = await installedApp(m.owner, s.id, ['order.view'])
    ok(await app.api.get(`/api/stores/${s.id}/orders`), 200)
    expectStatus(await m.owner.api.delete(`/api/stores/${s.id}/apps/${app.install.id}`), 204)
    expectDenied(await app.api.get(`/api/stores/${s.id}/orders`))
    const list = ok(await m.owner.api.get<Items<Install>>(`/api/stores/${s.id}/apps`), 200).items
    expect(list.some((x) => x.id === app.install.id)).toBe(false)
  })

  test('without app.uninstall → 403 and the app keeps working', async () => {
    const { m, s } = await merchantWithStore()
    const staff = await m.memberWithRole('staff')
    const app = await installedApp(m.owner, s.id, ['order.view'])
    expectDenied(await staff.api.delete(`/api/stores/${s.id}/apps/${app.install.id}`))
    ok(await app.api.get(`/api/stores/${s.id}/orders`), 200)
  })

  test('one app installed on two merchants: uninstalling in one leaves the other', async () => {
    const [a, b] = await Promise.all([merchantWithStore(), merchantWithStore()])
    const creds = await registerApp(['order.view'])
    const ia = await installApp(a.m.owner, a.s.id, creds.id, ['order.view'])
    await installApp(b.m.owner, b.s.id, creds.id, ['order.view'])
    const app = await clientActor(creds, 'app')
    ok(await app.api.get(`/api/stores/${a.s.id}/orders`), 200)
    ok(await app.api.get(`/api/stores/${b.s.id}/orders`), 200)
    expectStatus(await a.m.owner.api.delete(`/api/stores/${a.s.id}/apps/${ia.id}`), 204)
    expectDenied(await app.api.get(`/api/stores/${a.s.id}/orders`))
    ok(await app.api.get(`/api/stores/${b.s.id}/orders`), 200)
  })
})

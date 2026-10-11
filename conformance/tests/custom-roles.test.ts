// SPEC §3 custom roles: grantable-only, scopes, union, live edits, delete, deny-by-default, refund limits.
import { describe, expect, test } from 'vitest'
import { expectDenied, expectError, expectStatus, ok, sortedSet } from '../src/client'
import { GRANTABLE } from '../src/catalog'
import type { Items, Order, Role, Store } from '../src/types'
import { merchantWithStore, storeScope, uniq } from '../src/world'

describe('creating custom roles', () => {
  test('grantable permissions → 201 Role; listed with system: false and exact permissions', async () => {
    const { m } = await merchantWithStore()
    const perms = ['order.view', 'order.refund', 'payment.view']
    const name = uniq('role')
    const r = ok(await m.owner.api.post<Role>(`/api/merchants/${m.id}/roles`, { name, permissions: perms, refundLimitCents: 500 }), 201)
    expect(r).toMatchObject({ name, system: false, refundLimitCents: 500 })
    expect(sortedSet(r.permissions)).toEqual(sortedSet(perms))
    const listed = ok(await m.owner.api.get<Items<Role>>(`/api/merchants/${m.id}/roles`), 200).items.find((x) => x.id === r.id)
    expect(listed).toMatchObject({ id: r.id, name, system: false, refundLimitCents: 500 })
    expect(sortedSet(listed!.permissions)).toEqual(sortedSet(perms))
  })

  test.each([['platform.merchant.view'], ['platform.break_glass'], ['platform.audit.view'], ['platform.merchant.create']])(
    'a non-grantable permission (%s) → 400 not_grantable',
    async (perm) => {
      const { m } = await merchantWithStore()
      expectError(await m.owner.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.view', perm] }), 400, 'not_grantable')
    },
  )

  test('an unknown action id → 400', async () => {
    const { m } = await merchantWithStore()
    expectError(await m.owner.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.teleport'] }), 400, [
      'not_grantable',
      'invalid_input',
    ])
  })

  test('PATCH adding a non-grantable permission → 400 not_grantable', async () => {
    const { m } = await merchantWithStore()
    const r = await m.role(['order.view'])
    expectError(await m.owner.api.patch(`/api/merchants/${m.id}/roles/${r.id}`, { permissions: ['order.view', 'platform.merchant.suspend'] }), 400, 'not_grantable')
  })

  test('a member with no roles can do nothing', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.member()
    expectDenied(await u.api.get(`/api/stores/${s.id}/orders`))
    expectDenied(await u.api.get(`/api/stores/${s.id}`))
    expect(ok(await u.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s.id}`), 200).actions).toEqual([])
  })
})

describe('assignment scope', () => {
  test('merchant scope applies to every store, including one created later', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const u = await m.memberWithPerms(['order.view'], m.scope)
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await u.api.get(`/api/stores/${s2.id}/orders`), 200)
    const s3 = await m.store()
    ok(await u.api.get(`/api/stores/${s3.id}/orders`), 200)
  })

  test('store scope applies to that store only', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const u = await m.memberWithPerms(['order.view', 'store.view'], storeScope(s))
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await u.api.get(`/api/stores/${s.id}`), 200)
    expectDenied(await u.api.get(`/api/stores/${s2.id}/orders`))
    expectDenied(await u.api.get(`/api/stores/${s2.id}`))
  })

  test('GET /merchants/:mid/stores returns only stores the caller has store.view on', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const u = await m.memberWithPerms(['store.view'], storeScope(s))
    const ids = ok(await u.api.get<Items<Store>>(`/api/merchants/${m.id}/stores`), 200).items.map((x) => x.id)
    expect(ids).toEqual([s.id])
    const all = ok(await m.owner.api.get<Items<Store>>(`/api/merchants/${m.id}/stores`), 200).items.map((x) => x.id)
    expect(sortedSet(all)).toEqual(sortedSet([s.id, s2.id]))
  })

  test('permissions are the union of roles at the store and at the merchant', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const o1 = await m.paidOrder(s.id)
    const o2 = await m.paidOrder(s2.id)
    const u = await m.memberWithPerms(['order.view'], storeScope(s))
    const payView = await m.role(['payment.view'])
    await m.assign(u, payView.id, m.scope)
    // s1: order.view (store) + payment.view (merchant)
    ok(await u.api.get(`/api/orders/${o1.id}`), 200)
    ok(await u.api.get(`/api/orders/${o1.id}/payments`), 200)
    // s2: only payment.view (merchant)
    expectDenied(await u.api.get(`/api/orders/${o2.id}`))
    ok(await u.api.get(`/api/orders/${o2.id}/payments`), 200)
  })

  test('removing an assignment removes its access on the next request', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['order.view'], storeScope(s))
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
    expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/role-assignments/${u.assignment.id}`), 204)
    expectDenied(await u.api.get(`/api/stores/${s.id}/orders`))
  })

  test('removing a member removes their assignments', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['order.view'])
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
    expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/members/${u.id}`), 204)
    expectDenied(await u.api.get(`/api/stores/${s.id}/orders`), { crossTenant: true })
  })
})

describe('editing and deleting roles', () => {
  test('adding a permission takes effect on the very next request', async () => {
    const { m, s } = await merchantWithStore()
    const [o1, o2] = await Promise.all([m.order(s.id), m.order(s.id)])
    const u = await m.memberWithPerms(['order.view'])
    expectDenied(await u.api.post(`/api/orders/${o1.id}/payments/capture`))
    const r = ok(await m.owner.api.patch<Role>(`/api/merchants/${m.id}/roles/${u.role.id}`, { permissions: ['order.view', 'payment.capture'] }), 200)
    expect(sortedSet(r.permissions)).toEqual(['order.view', 'payment.capture'])
    ok(await u.api.post(`/api/orders/${o1.id}/payments/capture`), 201)
    ok(await u.api.post(`/api/orders/${o2.id}/payments/capture`), 201)
  })

  test('removing a permission takes effect on the very next request', async () => {
    const { m, s } = await merchantWithStore()
    const [o1, o2] = await Promise.all([m.order(s.id), m.order(s.id)])
    const u = await m.memberWithPerms(['order.view', 'payment.capture'])
    ok(await u.api.post(`/api/orders/${o1.id}/payments/capture`), 201)
    ok(await m.owner.api.patch(`/api/merchants/${m.id}/roles/${u.role.id}`, { permissions: ['order.view'] }), 200)
    expectDenied(await u.api.post(`/api/orders/${o2.id}/payments/capture`))
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await m.owner.api.patch(`/api/merchants/${m.id}/roles/${u.role.id}`, { permissions: ['payment.view'] }), 200)
    expectDenied(await u.api.get(`/api/stores/${s.id}/orders`))
  })

  test('an edit applies to every holder of the role', async () => {
    const { m, s } = await merchantWithStore()
    const r = await m.role(['store.view'])
    const [u1, u2] = await Promise.all([m.memberWithRole(r.id), m.memberWithRole(r.id, storeScope(s))])
    expectDenied(await u1.api.get(`/api/stores/${s.id}/orders`))
    ok(await m.owner.api.patch(`/api/merchants/${m.id}/roles/${r.id}`, { permissions: ['store.view', 'order.view'] }), 200)
    ok(await u1.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await u2.api.get(`/api/stores/${s.id}/orders`), 200)
  })

  test('renaming a role keeps its permissions', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['order.view'])
    const name = uniq('renamed')
    const r = ok(await m.owner.api.patch<Role>(`/api/merchants/${m.id}/roles/${u.role.id}`, { name }), 200)
    expect(r.name).toBe(name)
    expect(sortedSet(r.permissions)).toEqual(['order.view'])
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
  })

  test('deleting a role removes access on the next request and removes it from the list', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['order.view'])
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
    expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/roles/${u.role.id}`), 204)
    expectDenied(await u.api.get(`/api/stores/${s.id}/orders`))
    const roles = ok(await m.owner.api.get<Items<Role>>(`/api/merchants/${m.id}/roles`), 200).items
    expect(roles.some((x) => x.id === u.role.id)).toBe(false)
    // the removed assignment is gone too
    expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/role-assignments/${u.assignment.id}`), 404)
  })
})

describe('deny by default', () => {
  test('a custom role with every grantable permission except order.refund cannot refund', async () => {
    const { m, s } = await merchantWithStore()
    const allButRefund = GRANTABLE.filter((a) => a !== 'order.refund')
    const u = await m.memberWithPerms(allButRefund)
    const o = await m.paidOrder(s.id, 1000)
    expectDenied(await u.api.post(`/api/orders/${o.id}/refund`, { amountCents: 100 }))
    const perms = ok(await u.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s.id}`), 200).actions
    expect(perms).not.toContain('order.refund')
  })

  test('a custom role holds exactly the permissions listed (no implied view/neighbour permissions)', async () => {
    const { m, s } = await merchantWithStore()
    const o = await m.paidOrder(s.id)
    const u = await m.memberWithPerms(['payment.capture'])
    expectDenied(await u.api.get(`/api/stores/${s.id}/orders`)) // order.view not implied
    expectDenied(await u.api.get(`/api/orders/${o.id}/payments`)) // payment.view not implied
    expectDenied(await u.api.get(`/api/stores/${s.id}`)) // store.view not implied
  })
})

describe('refund limit', () => {
  async function refunder(limits: (number | undefined)[]) {
    const { m, s } = await merchantWithStore()
    const roles = await Promise.all(limits.map((l) => m.role(['order.view', 'order.refund'], l)))
    const u = await m.member('refunder')
    for (const r of roles) await m.assign(u, r.id, m.scope)
    return { m, s, u }
  }
  const refund = (u: { api: any }, o: Order, amountCents: number) => u.api.post(`/api/orders/${o.id}/refund`, { amountCents })

  test('under the limit → 200 Order with refundedCents', async () => {
    const { m, s, u } = await refunder([500])
    const o = await m.paidOrder(s.id, 2000)
    const after = ok<Order>(await refund(u, o, 499), 200)
    expect(after).toMatchObject({ id: o.id, refundedCents: 499 })
  })

  test('at the limit → 200', async () => {
    const { m, s, u } = await refunder([500])
    const o = await m.paidOrder(s.id, 2000)
    expect(ok<Order>(await refund(u, o, 500), 200).refundedCents).toBe(500)
  })

  test('over the limit → 403, nothing refunded', async () => {
    const { m, s, u } = await refunder([500])
    const o = await m.paidOrder(s.id, 2000)
    expectDenied(await refund(u, o, 501))
    expect((await m.getOrder(o.id)).refundedCents).toBe(0)
  })

  test('the limit applies per refund request, not cumulatively', async () => {
    const { m, s, u } = await refunder([500])
    const o = await m.paidOrder(s.id, 2000)
    ok(await refund(u, o, 400), 200)
    expect(ok<Order>(await refund(u, o, 400), 200).refundedCents).toBe(800)
  })

  test('several roles: the highest limit wins', async () => {
    const { m, s, u } = await refunder([500, 1500])
    const o = await m.paidOrder(s.id, 5000)
    ok(await refund(u, o, 1200), 200)
    ok(await refund(u, o, 1500), 200)
    expectDenied(await refund(u, o, 1501))
  })

  test('several roles: no limit beats any limit', async () => {
    const { m, s, u } = await refunder([500, undefined])
    const o = await m.paidOrder(s.id, 5000)
    ok(await refund(u, o, 4000), 200)
  })

  test('a limited role at the store and an unlimited one at another store: the store’s own roles count', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const limited = await m.role(['order.view', 'order.refund'], 500)
    const unlimited = await m.role(['order.view', 'order.refund'])
    const u = await m.member('refunder')
    await m.assign(u, limited.id, storeScope(s))
    await m.assign(u, unlimited.id, storeScope(s2))
    const o1 = await m.paidOrder(s.id, 2000)
    const o2 = await m.paidOrder(s2.id, 2000)
    expectDenied(await refund(u, o1, 1000))
    ok(await refund(u, o2, 1000), 200)
  })

  test('changing a role’s limit applies on the next request', async () => {
    const { m, s, u } = await refunder([500])
    const roles = ok(await m.owner.api.get<Items<Role>>(`/api/merchants/${m.id}/roles`), 200).items.filter((r) => !r.system)
    const o = await m.paidOrder(s.id, 5000)
    expectDenied(await refund(u, o, 900))
    ok(await m.owner.api.patch(`/api/merchants/${m.id}/roles/${roles[0].id}`, { refundLimitCents: 1000 }), 200)
    ok(await refund(u, o, 900), 200)
  })

  test('system roles have no limit', async () => {
    const { m, s } = await merchantWithStore()
    const admin = await m.memberWithRole('admin')
    const o = await m.paidOrder(s.id, 9_999_00)
    ok(await admin.api.post(`/api/orders/${o.id}/refund`, { amountCents: 9_999_00 }), 200)
  })
})

// SPEC §9 GET /api/me/permissions (batch can / AuthZEN action search): exact sets per scope.
// Reading used (see AMBIGUITIES.md): each action is reported only at the resource type its §4
// scope names; `role.manage` (merchant or store) appears at both.
import { describe, expect, test } from 'vitest'
import { expectError, ok, sortedSet } from '../src/client'
import { atMerchant, atStore } from '../src/catalog'
import { merchantWithStore, newCustomer, platformAdmin, storeScope } from '../src/world'
import type { Api } from '../src/client'

const perms = async (api: Api, q: string) => sortedSet(ok(await api.get<{ actions: string[] }>(`/api/me/permissions?${q}`), 200).actions)

const ROLE = ['merchant.view', 'store.create', 'role.manage', 'store.view', 'order.view', 'order.refund', 'payment.capture']

describe('custom role at store scope', () => {
  test('?storeId= of that store → exactly the role’s store-scope actions', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(ROLE, storeScope(s))
    expect(await perms(u.api, `storeId=${s.id}`)).toEqual(atStore(ROLE))
    expect(atStore(ROLE)).toEqual(['order.refund', 'order.view', 'payment.capture', 'role.manage', 'store.view'])
  })

  test('?storeId= of another store → []', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const u = await m.memberWithPerms(ROLE, storeScope(s))
    expect(await perms(u.api, `storeId=${s2.id}`)).toEqual([])
  })

  test('?merchantId= → [] (a store assignment grants nothing on the merchant)', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(ROLE, storeScope(s))
    expect(await perms(u.api, `merchantId=${m.id}`)).toEqual([])
  })
})

describe('custom role at merchant scope', () => {
  test('?storeId= of any store → exactly the role’s store-scope actions', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const u = await m.memberWithPerms(ROLE, m.scope)
    expect(await perms(u.api, `storeId=${s.id}`)).toEqual(atStore(ROLE))
    expect(await perms(u.api, `storeId=${s2.id}`)).toEqual(atStore(ROLE))
  })

  test('?merchantId= → exactly the role’s merchant-scope actions', async () => {
    const { m } = await merchantWithStore()
    const u = await m.memberWithPerms(ROLE, m.scope)
    expect(await perms(u.api, `merchantId=${m.id}`)).toEqual(atMerchant(ROLE))
    expect(atMerchant(ROLE)).toEqual(['merchant.view', 'role.manage', 'store.create'])
  })
})

describe('union and live changes', () => {
  test('store role + merchant role → union at the store, merchant role only at other stores', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const u = await m.memberWithPerms(['order.view', 'order.cancel'], storeScope(s))
    const r2 = await m.role(['payment.view', 'merchant.view'])
    await m.assign(u, r2.id, m.scope)
    expect(await perms(u.api, `storeId=${s.id}`)).toEqual(['order.cancel', 'order.view', 'payment.view'])
    expect(await perms(u.api, `storeId=${s2.id}`)).toEqual(['payment.view'])
    expect(await perms(u.api, `merchantId=${m.id}`)).toEqual(['merchant.view'])
  })

  test('editing the role changes the result on the next request', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['order.view'], m.scope)
    expect(await perms(u.api, `storeId=${s.id}`)).toEqual(['order.view'])
    ok(await m.owner.api.patch(`/api/merchants/${m.id}/roles/${u.role.id}`, { permissions: ['shipment.view', 'shipment.update'] }), 200)
    expect(await perms(u.api, `storeId=${s.id}`)).toEqual(['shipment.update', 'shipment.view'])
  })
})

describe('principals with nothing', () => {
  test('customer → []', async () => {
    const { s } = await merchantWithStore()
    const c = await newCustomer()
    expect(await perms(c.api, `storeId=${s.id}`)).toEqual([])
  })

  test('platform admin without break-glass → [] at store and merchant', async () => {
    const [{ m, s }, admin] = await Promise.all([merchantWithStore(), platformAdmin()])
    expect(await perms(admin.api, `storeId=${s.id}`)).toEqual([])
    expect(await perms(admin.api, `merchantId=${m.id}`)).toEqual([])
  })
})

describe('input', () => {
  test('neither storeId nor merchantId → 400', async () => {
    const { m } = await merchantWithStore()
    expectError(await m.owner.api.get('/api/me/permissions'), 400)
  })
})

// SPEC §3 guardrails: role.manage holders cannot escalate (permissions, limits, scope).
import { describe, expect, test } from 'vitest'
import { expectDenied, expectStatus, ok, sortedSet } from '../src/client'
import type { Items, Role } from '../src/types'
import { merchantWithStore, storeScope, uniq } from '../src/world'

/** Merchant with a role manager holding role.manage + order.view (+ extras) at merchant scope. */
async function withManager(extra: string[] = [], refundLimitCents?: number) {
  const { m, s } = await merchantWithStore()
  const mgr = await m.memberWithPerms(['role.manage', 'merchant.view', 'order.view', ...extra], m.scope, { refundLimitCents, label: 'mgr' })
  return { m, s, mgr }
}

const ESC = { code: 'escalation' }

describe('permissions guardrail', () => {
  test('can create a role with permissions it holds', async () => {
    const { m, mgr } = await withManager()
    ok(await mgr.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.view'] }), 201)
  })

  test('cannot create a role with a permission it lacks → 403 escalation', async () => {
    const { m, mgr } = await withManager()
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.view', 'order.refund'] }), ESC)
    const roles = ok(await m.owner.api.get<Items<Role>>(`/api/merchants/${m.id}/roles`), 200).items
    expect(roles.filter((r) => !r.system && r.permissions.includes('order.refund'))).toEqual([])
  })

  test('cannot edit a role to add a permission it lacks → 403 escalation; role unchanged', async () => {
    const { m, mgr } = await withManager()
    const r = await m.role(['order.view'])
    expectDenied(await mgr.api.patch(`/api/merchants/${m.id}/roles/${r.id}`, { permissions: ['order.view', 'payment.capture'] }), ESC)
    const after = ok(await m.owner.api.get<Items<Role>>(`/api/merchants/${m.id}/roles`), 200).items.find((x) => x.id === r.id)
    expect(sortedSet(after!.permissions)).toEqual(['order.view'])
  })

  test('cannot edit (even rename) a role holding a permission it lacks → 403 escalation', async () => {
    const { m, mgr } = await withManager()
    const r = await m.role(['order.view', 'payment.capture'])
    expectDenied(await mgr.api.patch(`/api/merchants/${m.id}/roles/${r.id}`, { name: uniq('renamed') }), ESC)
  })

  test('can edit a role within its own permissions', async () => {
    const { m, mgr } = await withManager()
    const r = await m.role(['merchant.view'])
    ok(await mgr.api.patch(`/api/merchants/${m.id}/roles/${r.id}`, { permissions: ['merchant.view', 'order.view'] }), 200)
  })

  test('cannot delete a role holding a permission it lacks → 403 escalation; can delete one within its own', async () => {
    const { m, mgr } = await withManager()
    const big = await m.role(['order.view', 'payment.capture'])
    const small = await m.role(['order.view'])
    expectDenied(await mgr.api.delete(`/api/merchants/${m.id}/roles/${big.id}`), ESC)
    expectStatus(await mgr.api.delete(`/api/merchants/${m.id}/roles/${small.id}`), 204)
  })

  test('cannot assign a custom role with a permission it lacks → 403 escalation', async () => {
    const { m, s, mgr } = await withManager()
    const r = await m.role(['payment.capture'])
    const u = await m.member()
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: r.id, scope: m.scope }), ESC)
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: r.id, scope: storeScope(s) }), ESC)
    // and cannot hand it to itself
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: mgr.id, roleId: r.id, scope: m.scope }), ESC)
  })

  test('cannot assign a system role holding permissions it lacks (admin, staff) → 403 escalation', async () => {
    const { m, mgr } = await withManager()
    const u = await m.member()
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: 'admin', scope: m.scope }), ESC)
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: 'staff', scope: m.scope }), ESC)
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: mgr.id, roleId: 'admin', scope: m.scope }), ESC)
  })

  test('can assign a role within its own permissions; the assignee gets access', async () => {
    const { m, s, mgr } = await withManager()
    const r = await m.role(['order.view'])
    const u = await m.member()
    ok(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: r.id, scope: m.scope }), 201)
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
  })

  test('permission held only at a store: assign at that store OK, at merchant scope → 403 escalation', async () => {
    const { m, s, mgr } = await withManager()
    const refundAtS = await m.role(['order.refund'])
    await m.assign(mgr, refundAtS.id, storeScope(s))
    const r = await m.role(['order.refund'])
    const u = await m.member()
    ok(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: r.id, scope: storeScope(s) }), 201)
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: r.id, scope: m.scope }), ESC)
  })

  test('without role.manage: create/edit/delete/assign → 403 (not escalation-specific)', async () => {
    const { m } = await merchantWithStore()
    const staff = await m.memberWithRole('staff')
    const r = await m.role(['order.view'])
    const u = await m.member()
    expectDenied(await staff.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.view'] }))
    expectDenied(await staff.api.patch(`/api/merchants/${m.id}/roles/${r.id}`, { name: uniq('x') }))
    expectDenied(await staff.api.delete(`/api/merchants/${m.id}/roles/${r.id}`))
    expectDenied(await staff.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: r.id, scope: m.scope }))
    const a = await m.assign(u, r.id)
    expectDenied(await staff.api.delete(`/api/merchants/${m.id}/role-assignments/${a.id}`))
  })
})

describe('refund limit guardrail', () => {
  test('limited manager: can create a role at or below its own limit', async () => {
    const { m, mgr } = await withManager(['order.refund'], 1000)
    ok(await mgr.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.refund'], refundLimitCents: 500 }), 201)
    ok(await mgr.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.refund'], refundLimitCents: 1000 }), 201)
  })

  test('limited manager: a higher limit → 403 escalation', async () => {
    const { m, mgr } = await withManager(['order.refund'], 1000)
    expectDenied(
      await mgr.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.refund'], refundLimitCents: 1001 }),
      ESC,
    )
  })

  test('limited manager: no limit (absent) is above any limit → 403 escalation', async () => {
    const { m, mgr } = await withManager(['order.refund'], 1000)
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.refund'] }), ESC)
  })

  test('limited manager: cannot raise an existing role’s limit above its own → 403 escalation', async () => {
    const { m, mgr } = await withManager(['order.refund'], 1000)
    const r = await m.role(['order.refund'], 500)
    expectDenied(await mgr.api.patch(`/api/merchants/${m.id}/roles/${r.id}`, { refundLimitCents: 2000 }), ESC)
    ok(await mgr.api.patch(`/api/merchants/${m.id}/roles/${r.id}`, { refundLimitCents: 800 }), 200)
  })

  test('limited manager: cannot assign a role whose limit exceeds its own → 403 escalation', async () => {
    const { m, mgr } = await withManager(['order.refund'], 1000)
    const high = await m.role(['order.refund'], 5000)
    const low = await m.role(['order.refund'], 900)
    const u = await m.member()
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: high.id, scope: m.scope }), ESC)
    ok(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: low.id, scope: m.scope }), 201)
  })

  test('unlimited manager: may create a role with any or no limit', async () => {
    const { m, mgr } = await withManager(['order.refund'])
    ok(await mgr.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.refund'], refundLimitCents: 10_000_00 }), 201)
    ok(await mgr.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.refund'] }), 201)
  })
})

describe('scope guardrail', () => {
  test('store-scoped role.manage: assign at its store OK; at merchant scope or another store → 403', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const mgr = await m.memberWithPerms(['role.manage', 'order.view'], storeScope(s), { label: 'store-mgr' })
    const r = await m.role(['order.view'])
    const u = await m.member()
    ok(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: r.id, scope: storeScope(s) }), 201)
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: r.id, scope: m.scope }))
    expectDenied(await mgr.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: r.id, scope: storeScope(s2) }))
    expectDenied(await u.api.get(`/api/stores/${s2.id}/orders`))
  })

  test('store-scoped role.manage cannot unassign a merchant-scope assignment', async () => {
    const { m, s } = await merchantWithStore()
    const mgr = await m.memberWithPerms(['role.manage', 'order.view'], storeScope(s), { label: 'store-mgr' })
    const u = await m.memberWithPerms(['order.view'], m.scope)
    expectDenied(await mgr.api.delete(`/api/merchants/${m.id}/role-assignments/${u.assignment.id}`))
    ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
  })
})

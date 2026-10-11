// SPEC §6 agents: registration, grants (subset of the granter's permissions), expiry, revoke,
// live dependency on the granting user's permissions, granting user's refund limit.
import { describe, expect, test } from 'vitest'
import { expectDenied, expectStatus, ok, sortedSet } from '../src/client'
import type { ClientCreds, Grant } from '../src/types'
import { clientActor, grantAgent, grantedAgent, merchantWithStore, newSupport, newUser, registerAgent, sleep, storeScope, uniq } from '../src/world'

describe('registration', () => {
  test('any merchant user registers an agent → 201 {id, clientId, clientSecret}', async () => {
    const { m } = await merchantWithStore()
    const staff = await m.memberWithRole('staff')
    for (const who of [m.owner, staff]) {
      const a = ok(await who.api.post<ClientCreds>('/api/agents', { name: uniq('agent') }), 201)
      expect(typeof a.id).toBe('string')
      expect(a.clientId).toBeTruthy()
      expect(a.clientSecret).toBeTruthy()
    }
  })

  test('platform staff, customers and users without a merchant cannot register agents', async () => {
    const [support, { m }, loner] = await Promise.all([newSupport(), merchantWithStore(), newUser('user')])
    const c = await m.customer()
    for (const who of [support, c, loner]) expectDenied(await who.api.post('/api/agents', { name: uniq('agent') }))
  })

  test('an agent with no grant can do nothing', async () => {
    const { m, s } = await merchantWithStore()
    const agent = await clientActor(await registerAgent(m.owner), 'agent')
    expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`))
    expectDenied(await agent.api.get(`/api/stores/${s.id}`))
  })
})

describe('grants', () => {
  test('grant → 201 {id, expiresAt}; agent can do the granted actions on that store only', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const creds = await registerAgent(m.owner)
    const before = Date.now()
    const g = ok(
      await m.owner.api.post<Grant>(`/api/stores/${s.id}/agent-grants`, { agentId: creds.id, permissions: ['order.view', 'payment.capture'], expiresInSeconds: 600 }),
      201,
    )
    expect(typeof g.id).toBe('string')
    const exp = Date.parse(g.expiresAt)
    expect(exp).toBeGreaterThan(before + 600_000 - 120_000)
    expect(exp).toBeLessThan(before + 600_000 + 120_000)

    const agent = await clientActor(creds, 'agent')
    const [o, o2] = await Promise.all([m.order(s.id), m.order(s2.id)])
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await agent.api.post(`/api/orders/${o.id}/payments/capture`), 201)
    // not granted
    expectDenied(await agent.api.post(`/api/stores/${s.id}/products`, { title: 'x', priceCents: 1 }))
    expectDenied(await agent.api.get(`/api/orders/${o.id}/payments`))
    // other store
    expectDenied(await agent.api.get(`/api/stores/${s2.id}/orders`))
    expectDenied(await agent.api.post(`/api/orders/${o2.id}/payments/capture`))
  })

  test('/api/me/permissions for an agent = granted actions at that store, none elsewhere', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const agent = await grantedAgent(m.owner, s.id, ['order.view', 'shipment.view'])
    expect(sortedSet(ok(await agent.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s.id}`), 200).actions)).toEqual([
      'order.view',
      'shipment.view',
    ])
    expect(ok(await agent.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s2.id}`), 200).actions).toEqual([])
  })

  test('granting a permission the user lacks at that store → 403 escalation', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['agent.grant', 'order.view'], storeScope(s), { label: 'granter' })
    const creds = await registerAgent(u)
    expectDenied(
      await u.api.post(`/api/stores/${s.id}/agent-grants`, { agentId: creds.id, permissions: ['order.view', 'payment.capture'], expiresInSeconds: 600 }),
      { code: 'escalation' },
    )
    ok(await u.api.post(`/api/stores/${s.id}/agent-grants`, { agentId: creds.id, permissions: ['order.view'], expiresInSeconds: 600 }), 201)
  })

  test('without agent.grant at the store → 403', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const staff = await m.memberWithRole('staff')
    const creds = await registerAgent(staff)
    expectDenied(await staff.api.post(`/api/stores/${s.id}/agent-grants`, { agentId: creds.id, permissions: ['order.view'], expiresInSeconds: 600 }))
    // agent.grant at s only does not allow granting on s2
    const u = await m.memberWithPerms(['agent.grant', 'order.view'], storeScope(s))
    const c2 = await registerAgent(u)
    expectDenied(await u.api.post(`/api/stores/${s2.id}/agent-grants`, { agentId: c2.id, permissions: ['order.view'], expiresInSeconds: 600 }))
  })

  test('revoke (DELETE grant → 204) cuts access on the next request', async () => {
    const { m, s } = await merchantWithStore()
    const agent = await grantedAgent(m.owner, s.id, ['order.view'])
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
    expectStatus(await m.owner.api.delete(`/api/stores/${s.id}/agent-grants/${agent.grant.id}`), 204)
    expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`))
  })

  test('revoking needs agent.grant', async () => {
    const { m, s } = await merchantWithStore()
    const staff = await m.memberWithRole('staff')
    const agent = await grantedAgent(m.owner, s.id, ['order.view'])
    expectDenied(await staff.api.delete(`/api/stores/${s.id}/agent-grants/${agent.grant.id}`))
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
  })

  test(
    'expiry holds without a cleanup job (expiresInSeconds: 2, wait ~3.5s)',
    async () => {
      const { m, s } = await merchantWithStore()
      const agent = await grantedAgent(m.owner, s.id, ['order.view'], 2)
      ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
      await sleep(3_500)
      expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`))
    },
    45_000,
  )

  test('a second grant on another store is independent', async () => {
    const { m, s } = await merchantWithStore()
    const s2 = await m.store()
    const creds = await registerAgent(m.owner)
    const g1 = await grantAgent(m.owner, s.id, creds.id, ['order.view'])
    await grantAgent(m.owner, s2.id, creds.id, ['order.view'])
    const agent = await clientActor(creds, 'agent')
    expectStatus(await m.owner.api.delete(`/api/stores/${s.id}/agent-grants/${g1.id}`), 204)
    expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`))
    ok(await agent.api.get(`/api/stores/${s2.id}/orders`), 200)
  })
})

describe('grant input', () => {
  test('an absurd expiresInSeconds is a 400, not a 500 (regression: review-c, invalid date)', async () => {
    const { m, s } = await merchantWithStore()
    const creds = await registerAgent(m.owner)
    expectStatus(await m.owner.api.post(`/api/stores/${s.id}/agent-grants`, { agentId: creds.id, permissions: ['order.view'], expiresInSeconds: 1e13 }), 400)
  })
})

describe('the granting user must still hold the action', () => {
  test('removing the granting user’s role assignment cuts the agent off', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['agent.grant', 'order.view'], m.scope, { label: 'granter' })
    const agent = await grantedAgent(u, s.id, ['order.view'])
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
    expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/role-assignments/${u.assignment.id}`), 204)
    expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`))
  })

  test('removing the permission from the granting user’s role cuts the agent off for that action; adding it back restores', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['agent.grant', 'order.view', 'shipment.view'], m.scope, { label: 'granter' })
    const o = await m.paidOrder(s.id)
    const agent = await grantedAgent(u, s.id, ['order.view', 'shipment.view'])
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
    ok(await m.owner.api.patch(`/api/merchants/${m.id}/roles/${u.role.id}`, { permissions: ['agent.grant', 'shipment.view'] }), 200)
    expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`))
    ok(await agent.api.get(`/api/orders/${o.id}/shipments`), 200)
    ok(await m.owner.api.patch(`/api/merchants/${m.id}/roles/${u.role.id}`, { permissions: ['agent.grant', 'order.view', 'shipment.view'] }), 200)
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
  })

  test('removing the granting user from the merchant cuts the agent off', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['agent.grant', 'order.view'], m.scope, { label: 'granter' })
    const agent = await grantedAgent(u, s.id, ['order.view'])
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
    expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/members/${u.id}`), 204)
    expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`))
  })
  test('an agent whose registrant left the merchant can do nothing, even under a teammate’s grant', async () => {
    // The ex-member still holds the agent's client secret. A stack may refuse grants of another
    // user's agent (4xx); if it accepts one, removing the registrant must still cut the agent off.
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['order.view'], m.scope, { label: 'registrant' })
    const creds = await registerAgent(u)
    const r = await m.owner.api.post<Grant>(`/api/stores/${s.id}/agent-grants`, { agentId: creds.id, permissions: ['order.view'], expiresInSeconds: 600 })
    if (r.status !== 201) {
      expect(r.status, r.text).toBeGreaterThanOrEqual(400)
      expect(r.status, r.text).toBeLessThan(500)
      return
    }
    const agent = await clientActor(creds, 'agent')
    ok(await agent.api.get(`/api/stores/${s.id}/orders`), 200)
    expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/members/${u.id}`), 204)
    expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`))
  })
})

describe('agent refunds use the granting user’s limit', () => {
  test('at the granter’s limit → 200; over → 403', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['agent.grant', 'order.view', 'order.refund'], m.scope, { refundLimitCents: 500, label: 'granter' })
    const agent = await grantedAgent(u, s.id, ['order.refund'])
    const o = await m.paidOrder(s.id, 5000)
    ok(await agent.api.post(`/api/orders/${o.id}/refund`, { amountCents: 500 }), 200)
    expectDenied(await agent.api.post(`/api/orders/${o.id}/refund`, { amountCents: 501 }))
    expect((await m.getOrder(o.id)).refundedCents).toBe(500)
  })

  test('raising the granter’s limit raises the agent’s on the next request', async () => {
    const { m, s } = await merchantWithStore()
    const u = await m.memberWithPerms(['agent.grant', 'order.view', 'order.refund'], m.scope, { refundLimitCents: 500, label: 'granter' })
    const agent = await grantedAgent(u, s.id, ['order.refund'])
    const o = await m.paidOrder(s.id, 5000)
    expectDenied(await agent.api.post(`/api/orders/${o.id}/refund`, { amountCents: 1000 }))
    ok(await m.owner.api.patch(`/api/merchants/${m.id}/roles/${u.role.id}`, { refundLimitCents: 2000 }), 200)
    ok(await agent.api.post(`/api/orders/${o.id}/refund`, { amountCents: 1000 }), 200)
  })

  test('an agent granted by an unlimited user has no limit', async () => {
    const { m, s } = await merchantWithStore()
    const agent = await grantedAgent(m.owner, s.id, ['order.refund'])
    const o = await m.paidOrder(s.id, 100_000)
    ok(await agent.api.post(`/api/orders/${o.id}/refund`, { amountCents: 100_000 }), 200)
  })
})

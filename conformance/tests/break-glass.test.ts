// SPEC §7 break-glass: read-only (*.view) access to one merchant until expiry, audited.
import { describe, expect, test } from 'vitest'
import { expectDenied, expectStatus, ok, type Res } from '../src/client'
import { env } from '../src/env'
import type { AuditEntry, BreakGlass, Items } from '../src/types'
import { merchantWithStore, newCustomer, newMerchant, newSupport, openBreakGlass, platformAdmin, sleep } from '../src/world'

async function audit(merchantId: string): Promise<AuditEntry[]> {
  const admin = await platformAdmin()
  return ok(await admin.api.get<Items<AuditEntry>>(`/api/platform/audit?merchantId=${merchantId}`), 200).items
}

const isActor = (e: AuditEntry, who: { id: string; email: string }) => e.actor === who.id || e.actor === who.email

describe('opening a break-glass grant', () => {
  test('support opens one → 201 {id, expiresAt ≈ now + minutes}', async () => {
    const [support, m] = await Promise.all([newSupport(), newMerchant()])
    const before = Date.now()
    const bg = ok(await support.api.post<BreakGlass>('/api/platform/break-glass', { merchantId: m.id, reason: 'ticket 1', minutes: 10 }), 201)
    expect(typeof bg.id).toBe('string')
    const exp = Date.parse(bg.expiresAt)
    expect(Number.isNaN(exp)).toBe(false)
    // generous window for clock skew between the test host and the server
    expect(exp).toBeGreaterThan(before + 10 * 60_000 - 120_000)
    expect(exp).toBeLessThan(before + 10 * 60_000 + 120_000)
  })

  test('platform admin may open one too', async () => {
    const [admin, m] = await Promise.all([platformAdmin(), newMerchant()])
    ok(await admin.api.post('/api/platform/break-glass', { merchantId: m.id, reason: 'ticket 2', minutes: 5 }), 201)
  })

  test('merchant users and customers cannot open one', async () => {
    const [m, other, customer] = await Promise.all([newMerchant(), newMerchant(), newCustomer()])
    expectDenied(await m.owner.api.post('/api/platform/break-glass', { merchantId: m.id, reason: 'x', minutes: 5 }))
    expectDenied(await m.owner.api.post('/api/platform/break-glass', { merchantId: other.id, reason: 'x', minutes: 5 }))
    expectDenied(await customer.api.post('/api/platform/break-glass', { merchantId: m.id, reason: 'x', minutes: 5 }))
  })

  test('the grant itself is audited (action platform.break_glass, actor = opener)', async () => {
    const [support, m] = await Promise.all([newSupport(), newMerchant()])
    await openBreakGlass(support, m.id)
    const entries = await audit(m.id)
    const e = entries.find((x) => x.action === 'platform.break_glass' && isActor(x, support))
    expect(e, JSON.stringify(entries)).toBeDefined()
    expect(e!.merchantId).toBe(m.id)
    expect(Number.isNaN(Date.parse(e!.at))).toBe(false)
  })
})

describe('under break-glass', () => {
  test('*.view reads succeed; each one is audited; entries are newest first', async () => {
    const [support, { m, s }] = await Promise.all([newSupport(), merchantWithStore()])
    const order = await m.paidOrder(s.id, 1200)
    await m.ship(order.id)
    await openBreakGlass(support, m.id)

    const reads: [string, string][] = [
      ['merchant.view', `/api/merchants/${m.id}`],
      ['merchant.view', `/api/merchants/${m.id}/roles`],
      ['store.view', `/api/stores/${s.id}`],
      ['order.view', `/api/stores/${s.id}/orders`],
      ['order.view', `/api/orders/${order.id}`],
      ['payment.view', `/api/orders/${order.id}/payments`],
      ['shipment.view', `/api/orders/${order.id}/shipments`],
      ['app.view', `/api/stores/${s.id}/apps`],
    ]
    for (const [, path] of reads) ok(await support.api.get(path), 200)

    const entries = await audit(m.id)
    const mine = entries.filter((e) => isActor(e, support) && e.action !== 'platform.break_glass')
    expect(mine.length, JSON.stringify(entries)).toBeGreaterThanOrEqual(reads.length)
    for (const e of mine) expect(e.merchantId).toBe(m.id)
    // each read action appears at least as often as it was requested
    const want = new Map<string, number>()
    for (const [a] of reads) want.set(a, (want.get(a) ?? 0) + 1)
    for (const [a, n] of want) {
      expect(mine.filter((e) => e.action === a).length, `audit entries for ${a}: ${JSON.stringify(mine)}`).toBeGreaterThanOrEqual(n)
    }
    // newest first
    const times = entries.map((e) => Date.parse(e.at))
    for (let i = 1; i < times.length; i++) expect(times[i - 1]).toBeGreaterThanOrEqual(times[i])
  })

  test('/api/me/permissions reports only *.view actions', async () => {
    const [support, { m, s }] = await Promise.all([newSupport(), merchantWithStore()])
    await openBreakGlass(support, m.id)
    const perms = ok(await support.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s.id}`), 200).actions
    expect(perms).toContain('order.view')
    expect(perms).toContain('store.view')
    for (const a of perms) expect(a.endsWith('.view'), `non-view action ${a}`).toBe(true)
  })

  test('writes are denied (403), and nothing changes', async () => {
    const [support, { m, s }] = await Promise.all([newSupport(), merchantWithStore()])
    const pending = await m.order(s.id, 800)
    const paid = await m.paidOrder(s.id, 900)
    const product = await m.product(s.id)
    await openBreakGlass(support, m.id)

    const writes: Res[] = [
      await support.api.post(`/api/stores/${s.id}/products`, { title: 'x', priceCents: 1 }),
      await support.api.patch(`/api/products/${product.id}`, { title: 'hacked' }),
      await support.api.post(`/api/orders/${pending.id}/payments/capture`),
      await support.api.post(`/api/orders/${pending.id}/cancel`),
      await support.api.post(`/api/orders/${paid.id}/refund`, { amountCents: 100 }),
      await support.api.post(`/api/orders/${paid.id}/shipments`, { carrier: 'ups' }),
      await support.api.post(`/api/merchants/${m.id}/roles`, { name: 'bg-role', permissions: ['order.view'] }),
      await support.api.post(`/api/merchants/${m.id}/stores`, { name: 'bg-store' }),
      await support.api.post(`/api/merchants/${m.id}/members`, { userId: support.id }),
    ]
    for (const r of writes) expectDenied(r)
    expect((await m.getOrder(pending.id)).status).toBe('pending')
    expect(await m.getOrder(paid.id)).toMatchObject({ status: 'paid', refundedCents: 0 })
  })

  test('grant covers only its merchant', async () => {
    const [support, a, b] = await Promise.all([newSupport(), merchantWithStore(), merchantWithStore()])
    await openBreakGlass(support, a.m.id)
    ok(await support.api.get(`/api/stores/${a.s.id}/orders`), 200)
    expectDenied(await support.api.get(`/api/stores/${b.s.id}/orders`), { crossTenant: true })
    expectDenied(await support.api.get(`/api/merchants/${b.m.id}/roles`), { crossTenant: true })
  })

  test('grant covers only its opener', async () => {
    const [support1, support2, { m, s }] = await Promise.all([newSupport(), newSupport(), merchantWithStore()])
    await openBreakGlass(support1, m.id)
    ok(await support1.api.get(`/api/stores/${s.id}/orders`), 200)
    expectDenied(await support2.api.get(`/api/stores/${s.id}/orders`))
  })
})

describe('break-glass expiry', () => {
  // `minutes` is the only unit (SPEC §7), so this waits just over a minute. SKIP_SLOW=1 skips it.
  test.skipIf(env.skipSlow)(
    'access ends at expiry (minutes: 1, waits ~65s)',
    async () => {
      const [support, { m, s }] = await Promise.all([newSupport(), merchantWithStore()])
      await openBreakGlass(support, m.id, 1)
      ok(await support.api.get(`/api/stores/${s.id}/orders`), 200)
      await sleep(65_000)
      expectStatus(await support.api.get(`/api/stores/${s.id}/orders`), 403)
    },
    120_000,
  )
})

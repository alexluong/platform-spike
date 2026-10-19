// SPEC §16 round 4 (multi-pool identity): workforce, platform, shop and one tenant pool per merchant.
// v4.1 (option A): merchant staff are platform accounts (platform pool); tenant pools hold customers only.
// Runs only on stacks whose driver declares `features: ['multi-pool']` (i, h2); every other stack skips it.
// One describe per §16.6 rule. Merchants whose tenant pool a test uses are polled until `active` (§16.3).
import { describe, expect, test } from 'vitest'
import { type Api, expectDenied, expectStatus, ok, sortedSet } from '../src/client'
import type { Items, Me, Merchant, Order, Store } from '../src/types'
import {
  anon,
  createTenantCustomer,
  jwtIssuer,
  loginTenant,
  loginWithShop,
  multiPool,
  newActiveMerchant,
  newCustomer,
  newEmail,
  newMerchant,
  newPassword,
  newStaff,
  newTenantCustomer,
  newUser,
  platformAdmin,
  relogin,
  reloginTenant,
  tenantIssuer,
  uniq,
  waitActive,
  type MerchantWorld,
} from '../src/world'
import { env } from '../src/env'

async function me(token: string): Promise<Me> {
  return ok(await anon.as(token, 'me').get<Me>('/api/me'), 200)
}

async function perms(api: Api, q: string): Promise<string[]> {
  return sortedSet(ok(await api.get<{ actions: string[] }>(`/api/me/permissions?${q}`), 200).actions)
}

async function place(api: Api, storeId: string, productId: string): Promise<Order> {
  return ok(await api.post<Order>(`/api/stores/${storeId}/orders`, { items: [{ productId, qty: 1 }] }), 201)
}

async function myOrderIds(api: Api): Promise<string[]> {
  return ok(await api.get<Items<Order>>('/api/me/orders'), 200).items.map((o) => o.id).sort()
}

/** Customer ordering at a store it doesn't belong to (§16.6 rule 3: suite accepts 401|403). */
function expectOrderRefused(res: Awaited<ReturnType<Api['post']>>): void {
  expectStatus(res, 401, 403)
}

/** Cross-tenant store list / permissions: 403|404, or 200 with nothing (§9). */
function expectNothingThere(res: Awaited<ReturnType<Api['get']>>): void {
  if (res.status === 200) {
    const b = res.body as { items?: unknown[]; actions?: unknown[] }
    expect(b.items ?? b.actions ?? [], `${res.method} ${res.path} as ${res.actor}: ${res.text}`).toEqual([])
  } else expectDenied(res, { crossTenant: true })
}

/** Active merchant (tenant pool ready) with one store and one product. */
async function activeShop(): Promise<{ m: MerchantWorld; s: Store; productId: string }> {
  const m = await newActiveMerchant()
  const s = await m.store()
  const p = await m.product(s.id, 1000)
  return { m, s, productId: p.id }
}

async function addMember(m: MerchantWorld, user: { id: string }): Promise<void> {
  ok(await m.owner.api.post(`/api/merchants/${m.id}/members`, { userId: user.id }), 201)
}

/** Staff of `m` (a platform account, member of `m`) holding `roleId` (system or custom) at merchant scope. */
function staffWithRole(m: MerchantWorld, roleId: string) {
  return newStaff(m, { roleId })
}

describe.skipIf(!multiPool)('multi-pool', { timeout: 120_000 }, () => {
  // ---------- rule 1 ----------
  describe('1. pools are separate issuers', () => {
    test("two merchants' GET /identity (no auth) issuers are non-empty and differ", async () => {
      const [a, b] = await Promise.all([newActiveMerchant(), newActiveMerchant()])
      const [ia, ib] = await Promise.all([tenantIssuer(a.id), tenantIssuer(b.id)])
      expect(ia).not.toBe(ib)
    })

    test('GET /identity of an unknown merchant → 404', async () => {
      expectStatus(await anon.get(`/api/merchants/${uniq('nope')}/identity`), 404)
    })

    test("tenant customer tokens carry their merchant's issuer; staff tokens the platform issuer (when JWTs)", async () => {
      const [a, b] = await Promise.all([newActiveMerchant(), newActiveMerchant()])
      const [staff, customer, issuerA, issuerB] = await Promise.all([newStaff(a), newTenantCustomer(a.id), tenantIssuer(a.id), tenantIssuer(b.id)])
      const iss = jwtIssuer(customer.token)
      if (iss !== undefined) {
        // opaque tokens: the issuer is checked by introspection, not visible here
        expect(iss).toBe(issuerA)
        expect(iss).not.toBe(issuerB)
      }
      const staffIss = jwtIssuer(staff.token)
      if (staffIss !== undefined) {
        expect(staffIss).not.toBe(issuerA)
        const ownerIss = jwtIssuer(a.owner.token)
        if (ownerIss) expect(staffIss).toBe(ownerIss)
      }
    })

    test('workforce, platform and tenant issuers all differ; shop differs from tenant (when JWTs)', async () => {
      const m = await newActiveMerchant()
      const [admin, buyer, tcustomer, issuer] = await Promise.all([platformAdmin(), newCustomer('shop'), newTenantCustomer(m.id), tenantIssuer(m.id)])
      const workforce = jwtIssuer(admin.token)
      const platform = jwtIssuer(m.owner.token)
      const shop = jwtIssuer(buyer.token)
      const tenant = jwtIssuer(tcustomer.token)
      if (workforce && platform) expect(workforce).not.toBe(platform)
      for (const other of [workforce, platform, shop]) if (other) expect(other).not.toBe(issuer)
      if (tenant && workforce) expect(tenant).not.toBe(workforce)
    })
  })

  // ---------- rule 2 ----------
  describe('2. merchant staff (platform accounts)', () => {
    test('POST /api/_test/merchants/:mid/users needs the test secret → 401|403', async () => {
      const m = await newActiveMerchant()
      expectStatus(await anon.post(`/api/_test/merchants/${m.id}/users`, { email: newEmail('t'), password: newPassword(), kind: 'customer' }), 401, 403)
      expectStatus(
        await anon.post(`/api/_test/merchants/${m.id}/users`, { email: newEmail('t'), password: newPassword(), kind: 'customer' }, { 'x-test-secret': `${env.testSecret}-wrong` }),
        401,
        403,
      )
    })

    test('kind "user" at the tenant test endpoint → 400 (staff are platform accounts)', async () => {
      const m = await newActiveMerchant()
      expectStatus(
        await anon.post(`/api/_test/merchants/${m.id}/users`, { email: newEmail('t'), password: newPassword(), kind: 'user' }, { 'x-test-secret': env.testSecret }),
        400,
      )
    })

    test('a new staff member: /api/me {kind: user, merchantId}, member with no roles', async () => {
      const { m, s } = await activeShop()
      const u = await newStaff(m)
      expect(await me(u.token)).toMatchObject({ id: u.id, kind: 'user', merchantId: m.id })
      expect(await perms(u.api, `merchantId=${m.id}`)).toEqual([])
      expect(await perms(u.api, `storeId=${s.id}`)).toEqual([])
      expectDenied(await u.api.post(`/api/merchants/${m.id}/stores`, { name: uniq('store') }))
      expectDenied(await u.api.get(`/api/stores/${s.id}/orders`))
    })

    test("after the owner assigns a role, they act with exactly that role's permissions (same token)", async () => {
      const { m, s } = await activeShop()
      const u = await newStaff(m)
      const role = await m.role(['store.create', 'product.create'])
      await m.assign(u, role.id)
      expect(await perms(u.api, `merchantId=${m.id}`)).toEqual(['store.create'])
      expect(await perms(u.api, `storeId=${s.id}`)).toEqual(['product.create'])
      const s2 = ok(await u.api.post<Store>(`/api/merchants/${m.id}/stores`, { name: uniq('store') }), 201)
      expect(s2.merchantId).toBe(m.id)
      ok(await u.api.post(`/api/stores/${s.id}/products`, { title: uniq('product'), priceCents: 500 }), 201)
      // nothing beyond the role
      expectDenied(await u.api.get(`/api/stores/${s.id}/orders`))
      expectDenied(await u.api.post(`/api/merchants/${m.id}/roles`, { name: uniq('role'), permissions: ['order.view'] }))
      expectDenied(await u.api.post(`/api/merchants/${m.id}/members`, { userId: m.owner.id }))
    })

    test('removing their membership cuts access on the next request (same token)', async () => {
      const { m, s } = await activeShop()
      const u = await staffWithRole(m, (await m.role(['order.view'])).id)
      ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
      expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/members/${u.id}`), 204)
      expectDenied(await u.api.get(`/api/stores/${s.id}/orders`), { crossTenant: true })
      expect(await perms(u.api, `storeId=${s.id}`).catch(() => [])).toEqual([])
    })

    test("they can't act at a merchant they aren't a member of, even holding admin at their own", async () => {
      const [{ m: a }, { m: b, s: sb }] = await Promise.all([activeShop(), activeShop()])
      const u = await staffWithRole(a, 'admin')
      expectDenied(await u.api.get(`/api/merchants/${b.id}`), { crossTenant: true })
      expectDenied(await u.api.post(`/api/merchants/${b.id}/stores`, { name: uniq('store') }), { crossTenant: true })
      expectDenied(await u.api.get(`/api/stores/${sb.id}/orders`), { crossTenant: true })
      expect(await me(u.token)).toMatchObject({ id: u.id, merchantId: a.id })
    })

    test("they can't call /api/platform/* (403), even holding admin at their merchant", async () => {
      const m = await newActiveMerchant()
      const u = await staffWithRole(m, 'admin')
      expectDenied(await u.api.get('/api/platform/merchants'))
      expectDenied(await u.api.post('/api/platform/merchants', { name: uniq('merchant'), ownerUserId: u.id }))
      expectDenied(await u.api.post('/api/platform/break-glass', { merchantId: m.id, reason: 'x', minutes: 5 }))
      expectDenied(await u.api.get(`/api/platform/audit?merchantId=${m.id}`))
    })

    test("their credentials (and the owner's) don't log in at the merchant's tenant pool", async () => {
      const m = await newActiveMerchant()
      const u = await staffWithRole(m, 'admin')
      await expect(loginTenant(m.id, u.email, u.password), 'staff at the tenant pool').rejects.toThrow()
      await expect(loginTenant(m.id, m.owner.email, m.owner.password), 'owner at the tenant pool').rejects.toThrow()
    })
  })

  // ---------- rule 3 ----------
  describe('3. tenant customers', () => {
    test("order at every store of their merchant; /api/me {kind: customer}, not shop-linked", async () => {
      const { m, s, productId } = await activeShop()
      const s2 = await m.store()
      const p2 = await m.product(s2.id, 700)
      const c = await newTenantCustomer(m.id)
      const me1 = await me(c.token)
      expect(me1).toMatchObject({ id: c.id, kind: 'customer' })
      expect(me1.shopLinked ?? false).toBe(false)
      const o1 = await place(c.api, s.id, productId)
      const o2 = await place(c.api, s2.id, p2.id)
      expect(o1).toMatchObject({ storeId: s.id, totalCents: 1000, status: 'pending' })
      expect(o2).toMatchObject({ storeId: s2.id, totalCents: 700 })
      // the merchant sees it
      const listed = ok(await m.owner.api.get<Items<Order>>(`/api/stores/${s.id}/orders`), 200)
      expect(listed.items.some((o) => o.id === o1.id)).toBe(true)
    })

    test("ordering at another merchant's store → 401|403; no order there", async () => {
      const [a, { m: b, s: sb, productId }] = await Promise.all([activeShop(), activeShop()])
      const c = await newTenantCustomer(a.m.id)
      expectOrderRefused(await c.api.post(`/api/stores/${sb.id}/orders`, { items: [{ productId, qty: 1 }] }))
      expect(ok(await b.owner.api.get<Items<Order>>(`/api/stores/${sb.id}/orders`), 200).items).toEqual([])
    })

    test('GET /api/me/orders shows only their own; another customer\'s order → 403|404', async () => {
      const { m, s, productId } = await activeShop()
      const [c1, c2] = await Promise.all([newTenantCustomer(m.id), newTenantCustomer(m.id)])
      const o1 = await place(c1.api, s.id, productId)
      const o2 = await place(c2.api, s.id, productId)
      expect(await myOrderIds(c1.api)).toEqual([o1.id])
      expect(await myOrderIds(c2.api)).toEqual([o2.id])
      ok(await c1.api.get(`/api/orders/${o1.id}`), 200)
      expectDenied(await c1.api.get(`/api/orders/${o2.id}`), { crossTenant: true })
    })
  })

  // ---------- rule 4 ----------
  describe('4. same email, separate accounts', () => {
    test("same email as a customer in two merchants' pools: separate ids and passwords", async () => {
      const [a, b] = await Promise.all([newActiveMerchant(), newActiveMerchant()])
      const email = newEmail('same-customer')
      const [pa, pb] = [newPassword(), newPassword()]
      const [ua, ub] = await Promise.all([createTenantCustomer(a.id, { email, password: pa }), createTenantCustomer(b.id, { email, password: pb })])
      expect(ua.id).not.toBe(ub.id)
      expect((await me(await loginTenant(a.id, email, pa))).id).toBe(ua.id)
      expect((await me(await loginTenant(b.id, email, pb))).id).toBe(ub.id)
      await expect(loginTenant(b.id, email, pa), "M1's password at M2").rejects.toThrow()
      await expect(loginTenant(a.id, email, pb), "M2's password at M1").rejects.toThrow()
    })

    test('a tenant customer is unknown at another merchant and at the platform-level pools (login there rejects)', async () => {
      const [a, b] = await Promise.all([newActiveMerchant(), newActiveMerchant()])
      const c = await newTenantCustomer(a.id)
      await expect(loginTenant(b.id, c.email, c.password)).rejects.toThrow()
      await expect(relogin(c), 'tenant customer at a platform-level pool').rejects.toThrow()
    })

    test("same email as a staff member of M (platform account) and as M's tenant customer: separate ids and passwords", async () => {
      const m = await newActiveMerchant()
      const email = newEmail('same-staff')
      const staff = await newStaff(m, { email, label: 'same-staff' })
      const t = await createTenantCustomer(m.id, { email })
      expect(t.id).not.toBe(staff.id)
      await expect(loginTenant(m.id, email, staff.password), 'platform password at the tenant pool').rejects.toThrow()
      await expect(relogin({ email, password: t.password }), 'tenant password at the platform pool').rejects.toThrow()
      expect(await me(await relogin(staff))).toMatchObject({ id: staff.id, kind: 'user', merchantId: m.id })
      expect(await me(await loginTenant(m.id, email, t.password))).toMatchObject({ id: t.id, kind: 'customer' })
    })

    test('same email in a tenant customers pool and the shop pool: separate ids and passwords', async () => {
      const m = await newActiveMerchant()
      const email = newEmail('same-shop')
      const buyer = await newUser('customer', { email, label: 'same-shop' })
      const t = await createTenantCustomer(m.id, { email })
      expect(t.id).not.toBe(buyer.id)
      await expect(loginTenant(m.id, email, buyer.password), 'shop password at the tenant pool').rejects.toThrow()
      await expect(relogin({ email, password: t.password }), 'tenant password at the shop pool').rejects.toThrow()
    })
  })

  // ---------- rule 5 ----------
  describe('5. cross-pool tokens', () => {
    test("M1 staff (admin at M1) on M2's merchant and store endpoints → 403|404", async () => {
      const [{ m: a }, { m: b, s: sb, productId }] = await Promise.all([activeShop(), activeShop()])
      const u = await staffWithRole(a, 'admin')
      const order = await place((await newTenantCustomer(b.id)).api, sb.id, productId)
      const x = u.api
      for (const res of [
        await x.get(`/api/merchants/${b.id}`),
        await x.get(`/api/merchants/${b.id}/roles`),
        await x.post(`/api/merchants/${b.id}/stores`, { name: uniq('store') }),
        await x.post(`/api/merchants/${b.id}/roles`, { name: uniq('role'), permissions: ['order.view'] }),
        await x.post(`/api/merchants/${b.id}/members`, { userId: u.id }),
        await x.get(`/api/stores/${sb.id}`),
        await x.get(`/api/stores/${sb.id}/orders`),
        await x.post(`/api/stores/${sb.id}/products`, { title: uniq('product'), priceCents: 1 }),
        await x.get(`/api/orders/${order.id}`),
        await x.post(`/api/orders/${order.id}/cancel`),
      ]) {
        expectDenied(res, { crossTenant: true })
      }
      expectNothingThere(await x.get(`/api/merchants/${b.id}/stores`))
      expectNothingThere(await x.get(`/api/me/permissions?storeId=${sb.id}`))
      expectNothingThere(await x.get(`/api/me/permissions?merchantId=${b.id}`))
    })

    test("M1 tenant customer on M2: order → 401|403, M2's order → 403|404", async () => {
      const [{ m: a }, { m: b, s: sb, productId }] = await Promise.all([activeShop(), activeShop()])
      const [c, cb] = await Promise.all([newTenantCustomer(a.id), newTenantCustomer(b.id)])
      const order = await place(cb.api, sb.id, productId)
      expectOrderRefused(await c.api.post(`/api/stores/${sb.id}/orders`, { items: [{ productId, qty: 1 }] }))
      expectDenied(await c.api.get(`/api/orders/${order.id}`), { crossTenant: true })
    })

    test('staff (admin) on customer endpoints → 403', async () => {
      const { m, s, productId } = await activeShop()
      const u = await staffWithRole(m, 'admin')
      expectDenied(await u.api.post(`/api/stores/${s.id}/orders`, { items: [{ productId, qty: 1 }] }))
      expectDenied(await u.api.get('/api/me/orders'))
    })

    test('tenant customer on staff endpoints of its own merchant → 403', async () => {
      const { m, s, productId } = await activeShop()
      const c = await newTenantCustomer(m.id)
      const order = await place(c.api, s.id, productId)
      for (const res of [
        await c.api.get(`/api/merchants/${m.id}`),
        await c.api.get(`/api/merchants/${m.id}/roles`),
        await c.api.post(`/api/merchants/${m.id}/stores`, { name: uniq('store') }),
        await c.api.post(`/api/merchants/${m.id}/members`, { userId: c.id }),
        await c.api.get(`/api/stores/${s.id}/orders`),
        await c.api.post(`/api/stores/${s.id}/products`, { title: uniq('product'), priceCents: 1 }),
        await c.api.post(`/api/orders/${order.id}/payments/capture`),
        await c.api.post(`/api/orders/${order.id}/cancel`),
        await c.api.post('/api/agents', { name: uniq('agent') }),
        await c.api.get('/api/platform/merchants'),
      ]) {
        expectDenied(res)
      }
      expect(await perms(c.api, `storeId=${s.id}`)).toEqual([])
    })
  })

  // ---------- rule 6 ----------
  describe('6. partners (platform accounts in several merchants)', () => {
    test('member of M1 and M2 with different roles acts per role in each; /api/me lists both', async () => {
      const [{ m: a, s: sa }, { m: b, s: sb }] = await Promise.all([activeShop(), activeShop()])
      const p = await newUser('user', { label: 'partner' })
      await Promise.all([addMember(a, p), addMember(b, p)])
      const [ra, rb] = await Promise.all([a.role(['order.view']), b.role(['product.create'])])
      await Promise.all([a.assign(p, ra.id), b.assign(p, rb.id)])
      ok(await p.api.get(`/api/stores/${sa.id}/orders`), 200)
      expectDenied(await p.api.post(`/api/stores/${sa.id}/products`, { title: uniq('product'), priceCents: 1 }))
      ok(await p.api.post(`/api/stores/${sb.id}/products`, { title: uniq('product'), priceCents: 1 }), 201)
      expectDenied(await p.api.get(`/api/stores/${sb.id}/orders`))
      expect(await perms(p.api, `storeId=${sa.id}`)).toEqual(['order.view'])
      expect(await perms(p.api, `storeId=${sb.id}`)).toEqual(['product.create'])
      const pm = await me(p.token)
      expect(pm).toMatchObject({ id: p.id, kind: 'user' })
      expect(sortedSet(pm.merchantIds ?? [])).toEqual(sortedSet([a.id, b.id]))
    })

    test('a merchant owner can partner at another merchant (owner at M1, role at M2)', async () => {
      const [{ m: a }, { m: b, s: sb }] = await Promise.all([activeShop(), activeShop()])
      await addMember(b, a.owner)
      await b.assign(a.owner, (await b.role(['order.view'])).id)
      ok(await a.owner.api.post(`/api/merchants/${a.id}/stores`, { name: uniq('store') }), 201)
      ok(await a.owner.api.get(`/api/stores/${sb.id}/orders`), 200)
      expectDenied(await a.owner.api.post(`/api/merchants/${b.id}/stores`, { name: uniq('store') }))
      expect(sortedSet((await me(a.owner.token)).merchantIds ?? [])).toEqual(sortedSet([a.id, b.id]))
    })

    test('removal at M1 leaves M2 intact; with one merchant left, merchantId and merchantIds name it', async () => {
      const [{ m: a, s: sa }, { m: b, s: sb }] = await Promise.all([activeShop(), activeShop()])
      const p = await newUser('user', { label: 'partner' })
      await Promise.all([addMember(a, p), addMember(b, p)])
      await Promise.all([a.assign(p, (await a.role(['order.view'])).id), b.assign(p, (await b.role(['order.view'])).id)])
      expectStatus(await a.owner.api.delete(`/api/merchants/${a.id}/members/${p.id}`), 204)
      expectDenied(await p.api.get(`/api/stores/${sa.id}/orders`), { crossTenant: true })
      ok(await p.api.get(`/api/stores/${sb.id}/orders`), 200)
      const pm = await me(p.token)
      expect(pm.merchantId).toBe(b.id)
      expect(pm.merchantIds).toEqual([b.id])
    })
  })

  // ---------- rule 7 ----------
  describe('7. Shop', () => {
    test('§16.5 end to end: Shop token, Shop-linked tenant token, cross-merchant history, local customer apart', async () => {
      const [{ m: m1, s: s1, productId: p1 }, { s: s2, productId: p2 }] = await Promise.all([activeShop(), activeShop()])
      const buyer = await newCustomer('shop')
      // order at M1 with the Shop token (creates M1's customer record linked to the Shop account)
      const o1 = await place(buyer.api, s1.id, p1)
      // Sign in with Shop at M1 → tenant-issued token for the same linked customer
      const linked = anon.as(await loginWithShop(m1.id, buyer), 'shop-linked')
      const lm = ok(await linked.get<Me>('/api/me'), 200)
      expect(lm).toMatchObject({ kind: 'customer', shopLinked: true })
      expect(await myOrderIds(linked)).toEqual([o1.id])
      const o2 = await place(linked, s1.id, p1)
      // order at M2 with the Shop token
      const o3 = await place(buyer.api, s2.id, p2)
      // Shop history: every merchant, including the order placed with the linked tenant token
      expect(await myOrderIds(buyer.api)).toEqual([o1.id, o2.id, o3.id].sort())
      // the M1 tenant token sees only M1's orders
      expect(await myOrderIds(linked)).toEqual([o1.id, o2.id].sort())
      expectDenied(await linked.get(`/api/orders/${o3.id}`), { crossTenant: true })
      // a local M1 customer with the Shop buyer's email is not linked
      const local = await newTenantCustomer(m1.id, { email: buyer.email, label: 'local' })
      expect(local.id).not.toBe(lm.id)
      expect((await me(local.token)).shopLinked ?? false).toBe(false)
      expect(await myOrderIds(local.api)).toEqual([])
      for (const o of [o1, o2, o3]) expectDenied(await local.api.get(`/api/orders/${o.id}`), { crossTenant: true })
      const o4 = await place(local.api, s1.id, p1)
      expect(await myOrderIds(buyer.api)).toEqual([o1.id, o2.id, o3.id].sort())
      expect(await myOrderIds(linked)).toEqual([o1.id, o2.id].sort())
      expect(await myOrderIds(local.api)).toEqual([o4.id])
    })

    test('Sign in with Shop before any order creates the linked record; the Shop token sees its orders; same record next time', async () => {
      const { m, s, productId } = await activeShop()
      const buyer = await newCustomer('shop')
      const linked = anon.as(await loginWithShop(m.id, buyer), 'shop-linked')
      const first = ok(await linked.get<Me>('/api/me'), 200)
      expect(first).toMatchObject({ kind: 'customer', shopLinked: true })
      const o = await place(linked, s.id, productId)
      expect(await myOrderIds(buyer.api)).toEqual([o.id])
      const again = await me(await loginWithShop(m.id, buyer))
      expect(again.id).toBe(first.id)
      // a later Shop-token order at M lands on the same record
      const o2 = await place(buyer.api, s.id, productId)
      expect(await myOrderIds(linked)).toEqual([o.id, o2.id].sort())
    })

    test("the Shop-linked token is issued by the merchant's tenant pool (when a JWT)", async () => {
      const m = await newActiveMerchant()
      const buyer = await newCustomer('shop')
      const [t, issuer] = await Promise.all([loginWithShop(m.id, buyer), tenantIssuer(m.id)])
      const iss = jwtIssuer(t)
      if (iss !== undefined) {
        expect(iss).toBe(issuer)
        const shopIss = jwtIssuer(buyer.token)
        if (shopIss) expect(iss).not.toBe(shopIss)
      }
    })

    test("the Shop-linked token of M1 can't order at M2 (401|403) or use M1's staff endpoints (403)", async () => {
      const [{ m: m1, s: s1 }, { s: s2, productId: p2 }] = await Promise.all([activeShop(), activeShop()])
      const buyer = await newCustomer('shop')
      const linked = anon.as(await loginWithShop(m1.id, buyer), 'shop-linked')
      expectOrderRefused(await linked.post(`/api/stores/${s2.id}/orders`, { items: [{ productId: p2, qty: 1 }] }))
      expectDenied(await linked.get(`/api/stores/${s1.id}/orders`))
      expectDenied(await linked.post(`/api/merchants/${m1.id}/stores`, { name: uniq('store') }))
    })

    test('Sign in with Shop rejects a wrong Shop password and an unknown Shop account', async () => {
      const m = await newActiveMerchant()
      const buyer = await newCustomer('shop')
      await expect(loginWithShop(m.id, { email: buyer.email, password: newPassword() })).rejects.toThrow()
      await expect(loginWithShop(m.id, { email: newEmail('nobody'), password: newPassword() })).rejects.toThrow()
    })
  })

  // ---------- rule 8 ----------
  describe('8. suspension at the pool', () => {
    async function suspendedWorld() {
      const { m, s, productId } = await activeShop()
      const buyer = await newCustomer('shop')
      const [staff, customer, linkedToken] = await Promise.all([staffWithRole(m, 'admin'), newTenantCustomer(m.id), loginWithShop(m.id, buyer)])
      return { m, s, productId, buyer, staff, customer, linked: anon.as(linkedToken, 'shop-linked') }
    }

    test("while suspended, its tenant customers can't log in; Sign in with Shop rejects", async () => {
      const w = await suspendedWorld()
      await w.m.suspend()
      await expect(reloginTenant(w.customer), 'tenant customer').rejects.toThrow()
      await expect(loginWithShop(w.m.id, w.buyer), 'Sign in with Shop').rejects.toThrow()
    })

    test('its staff (platform accounts) still log in and get 403 merchant_suspended there, old and new tokens', async () => {
      const w = await suspendedWorld()
      await w.m.suspend()
      const fresh = anon.as(await relogin(w.staff), 'staff-new')
      for (const api of [w.staff.api, fresh]) {
        expectDenied(await api.get(`/api/merchants/${w.m.id}`), { code: 'merchant_suspended' })
        expectDenied(await api.post(`/api/merchants/${w.m.id}/stores`, { name: uniq('store') }), { code: 'merchant_suspended' })
      }
    })

    test('customer tokens issued earlier (local, Shop-linked, Shop) → 403', async () => {
      const w = await suspendedWorld()
      await w.m.suspend()
      const order = { items: [{ productId: w.productId, qty: 1 }] }
      expectDenied(await w.customer.api.post(`/api/stores/${w.s.id}/orders`, order))
      expectDenied(await w.linked.post(`/api/stores/${w.s.id}/orders`, order))
      expectDenied(await w.buyer.api.post(`/api/stores/${w.s.id}/orders`, order))
    })

    test('reinstating restores tenant login and Sign in with Shop; staff act again with the same token', async () => {
      const w = await suspendedWorld()
      await w.m.suspend()
      await expect(reloginTenant(w.customer)).rejects.toThrow()
      await w.m.reinstate()
      ok(await w.staff.api.get(`/api/merchants/${w.m.id}`), 200)
      const customer = anon.as(await reloginTenant(w.customer), 'tcustomer')
      await place(customer, w.s.id, w.productId)
      const linked = anon.as(await loginWithShop(w.m.id, w.buyer), 'shop-linked')
      expect(ok(await linked.get<Me>('/api/me'), 200)).toMatchObject({ kind: 'customer', shopLinked: true })
      await place(linked, w.s.id, w.productId)
    })

    test('platform accounts act normally elsewhere: the owner logs in; staff of M and M2 act at M2', async () => {
      const [w, { m: other, s: so }] = await Promise.all([suspendedWorld(), activeShop()])
      const p = await newStaff(w.m, { label: 'partner' })
      await addMember(other, p)
      await other.assign(p, (await other.role(['order.view'])).id)
      await w.m.suspend()
      expect((await me(await relogin(w.m.owner))).id).toBe(w.m.owner.id)
      const pt = anon.as(await relogin(p), 'partner')
      ok(await pt.get(`/api/stores/${so.id}/orders`), 200)
      expectDenied(await pt.get(`/api/merchants/${w.m.id}`), { code: 'merchant_suspended' })
      // the Shop buyer still logs in at the shop pool and orders at another merchant
      const bt = anon.as(await relogin(w.buyer), 'shop')
      await place(bt, so.id, (await other.product(so.id, 300)).id)
    })

    test("other merchants' tenant pools are unaffected", async () => {
      const [w, { m: other, s: so, productId }] = await Promise.all([suspendedWorld(), activeShop()])
      const [ostaff, ocustomer] = await Promise.all([staffWithRole(other, 'admin'), newTenantCustomer(other.id)])
      const buyer = await newCustomer('shop')
      await w.m.suspend()
      ok(await ostaff.api.get(`/api/merchants/${other.id}`), 200)
      await place(anon.as(await reloginTenant(ocustomer), 'other-customer'), so.id, productId)
      await place(anon.as(await loginWithShop(other.id, buyer), 'other-linked'), so.id, productId)
    })
  })

  // ---------- rule 9 ----------
  describe('9. provisioning', () => {
    test('a new merchant is 201 active|provisioning and becomes active within 60 s; GET /identity answers', async () => {
      const [admin, owner] = await Promise.all([platformAdmin(), newUser('user', { label: 'owner' })])
      const created = ok(await admin.api.post<Merchant>('/api/platform/merchants', { name: uniq('merchant'), ownerUserId: owner.id }), 201)
      expect(['active', 'provisioning']).toContain(created.status)
      await waitActive({ id: String(created.id), owner })
      expect(typeof (await tenantIssuer(String(created.id)))).toBe('string')
    })

    test('10 merchants created in parallel: all active within 60 s, distinct issuers, working tenant customer logins', { timeout: 240_000 }, async () => {
      const N = 10
      const ms = await Promise.all(Array.from({ length: N }, () => newMerchant()))
      const waited = await Promise.all(ms.map((m) => waitActive(m)))
      expect(Math.max(...waited)).toBeLessThanOrEqual(60_000)
      const issuers = await Promise.all(ms.map((m) => tenantIssuer(m.id)))
      expect(new Set(issuers).size).toBe(N)
      await Promise.all(
        ms.map(async (m, k) => {
          const customer = await newTenantCustomer(m.id)
          expect(await me(customer.token)).toMatchObject({ id: customer.id, kind: 'customer' })
          const iss = jwtIssuer(customer.token)
          if (iss !== undefined) expect(iss).toBe(issuers[k])
        }),
      )
    })
  })
})

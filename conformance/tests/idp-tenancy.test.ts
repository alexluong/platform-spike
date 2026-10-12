// SPEC §15 round 2 (identity-owned tenancy): §15.2 invitations, §15.3 suspension at the IdP.
// Runs only on stacks whose driver declares `features: ['idp-tenancy']` (d, e, a2); a, b, c skip it (§15.4).
import { describe, expect, test } from 'vitest'
import { expectConflict, expectDenied, expectStatus, expectUnauthenticated, ok } from '../src/client'
import type { Invitation, Items, Me } from '../src/types'
import {
  anon,
  driver,
  grantAgent,
  grantedAgent,
  installedApp,
  merchantWithStore,
  newCustomer,
  newMerchant,
  newSupport,
  newUser,
  platformAdmin,
  registerAgent,
  relogin,
  type Actor,
  type MerchantWorld,
} from '../src/world'

const enabled = driver.features?.includes('idp-tenancy') ?? false

/** A user with no merchant yet (the invitee), plus a pending invitation for them from `m`. */
async function invited(m: MerchantWorld, label = 'invitee'): Promise<{ u: Actor; inv: Invitation }> {
  const u = await newUser('user', { label })
  const inv = await m.invite(u.email)
  return { u, inv }
}

function listInvitations(m: MerchantWorld, by: Actor = m.owner) {
  return by.api.get<Items<Invitation>>(`/api/merchants/${m.id}/invitations`)
}

function accept(by: Actor, invitationId: string) {
  return by.api.post<{ merchantId: string }>(`/api/invitations/${invitationId}/accept`)
}

async function me(token: string): Promise<Me> {
  return ok(await anon.as(token, 'me').get<Me>('/api/me'), 200)
}

describe.skipIf(!enabled)('idp-tenancy', () => {
  // ---------- §15.2 invitations ----------

  describe('invitations: create, list, cancel', () => {
    test('invite → 201 {id, email, status: pending}; the list shows it', async () => {
      const m = await newMerchant()
      const u = await newUser('user', { label: 'invitee' })
      const inv = await m.invite(u.email)
      expect(typeof inv.id).toBe('string')
      expect(inv.email.toLowerCase()).toBe(u.email)
      expect(inv.status).toBe('pending')
      const list = ok(await listInvitations(m), 200)
      expect(list.items.find((x) => x.id === inv.id)).toMatchObject({ id: inv.id, status: 'pending' })
    })

    test('a member holding member.manage (custom role) can invite and list', async () => {
      const m = await newMerchant()
      const mgr = await m.memberWithPerms(['member.manage'])
      const u = await newUser('user', { label: 'invitee' })
      const inv = await m.invite(u.email, mgr)
      const list = ok(await listInvitations(m, mgr), 200)
      expect(list.items.some((x) => x.id === inv.id)).toBe(true)
    })

    test('cancel → 204; the invitation is no longer pending', async () => {
      const m = await newMerchant()
      const { inv } = await invited(m)
      expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/invitations/${inv.id}`), 204)
      const list = ok(await listInvitations(m), 200)
      const after = list.items.find((x) => x.id === inv.id)
      expect(after === undefined || after.status !== 'pending').toBe(true)
    })

    test.each([
      ['create', (m: MerchantWorld, u: Actor, _inv: Invitation) => u.api.post(`/api/merchants/${m.id}/invitations`, { email: 'nobody@example.com' })],
      ['list', (m: MerchantWorld, u: Actor, _inv: Invitation) => u.api.get(`/api/merchants/${m.id}/invitations`)],
      ['cancel', (m: MerchantWorld, u: Actor, inv: Invitation) => u.api.delete(`/api/merchants/${m.id}/invitations/${inv.id}`)],
    ])('a member without member.manage cannot %s invitations → 403', async (_what, call) => {
      const m = await newMerchant()
      const [{ inv }, u] = await Promise.all([invited(m), m.memberWithPerms(['merchant.view'])])
      expectDenied(await call(m, u, inv))
    })

    test("another merchant's member.manage holder cannot list them → 403|404", async () => {
      const [a, b] = await Promise.all([newMerchant(), newMerchant()])
      await invited(a)
      expectDenied(await listInvitations(a, b.owner), { crossTenant: true })
    })

    test("another merchant's member.manage holder cannot cancel one → 403|404; it stays pending", async () => {
      const [a, b] = await Promise.all([newMerchant(), newMerchant()])
      const { inv } = await invited(a)
      expectDenied(await b.owner.api.delete(`/api/merchants/${a.id}/invitations/${inv.id}`), { crossTenant: true })
      expectDenied(await b.owner.api.delete(`/api/merchants/${b.id}/invitations/${inv.id}`), { crossTenant: true })
      const list = ok(await listInvitations(a), 200)
      expect(list.items.find((x) => x.id === inv.id)?.status).toBe('pending')
    })

    test("another merchant's invitations do not show in one's own list", async () => {
      const [a, b] = await Promise.all([newMerchant(), newMerchant()])
      const { inv } = await invited(a)
      const list = ok(await listInvitations(b), 200)
      expect(list.items.some((x) => x.id === inv.id)).toBe(false)
    })
  })

  describe('invitations: before acceptance', () => {
    test('the invitee is not a member: assigning them a role → 4xx (not 401, not 2xx)', async () => {
      const m = await newMerchant()
      const [{ u }, role] = await Promise.all([invited(m), m.role(['order.view'])])
      const res = await m.owner.api.post(`/api/merchants/${m.id}/role-assignments`, { userId: u.id, roleId: role.id, scope: m.scope })
      expect(res.status >= 400 && res.status < 500 && res.status !== 401, `assign a non-member: got ${res.status} ${res.text}`).toBe(true)
    })

    test("the invitee's /api/me has no merchantId", async () => {
      const m = await newMerchant()
      const { u } = await invited(m)
      expect((await me(u.token)).merchantId ?? undefined).toBeUndefined()
    })
  })

  describe('invitations: accept', () => {
    test('accept → 200 {merchantId}; /api/me shows the merchant; the new member has no roles', async () => {
      const { m, s } = await merchantWithStore()
      const { u, inv } = await invited(m)
      expect(ok(await accept(u, inv.id), 200)).toMatchObject({ merchantId: m.id })
      expect((await me(u.token)).merchantId).toBe(m.id)
      expectDenied(await u.api.get(`/api/stores/${s.id}/orders`))
      expect(ok(await u.api.get<{ actions: string[] }>(`/api/me/permissions?storeId=${s.id}`), 200).actions).toEqual([])
    })

    test('the email matches case-insensitively', async () => {
      const m = await newMerchant()
      const u = await newUser('user', { label: 'invitee' })
      const inv = await m.invite(u.email.toUpperCase())
      expect(ok(await accept(u, inv.id), 200)).toMatchObject({ merchantId: m.id })
    })

    test('after acceptance roles follow §3: assign → access on the next request (same token)', async () => {
      const { m, s } = await merchantWithStore()
      const { u, inv } = await invited(m)
      ok(await accept(u, inv.id), 200)
      expectDenied(await u.api.get(`/api/stores/${s.id}/orders`))
      const role = await m.role(['order.view'])
      await m.assign(u, role.id)
      ok(await u.api.get(`/api/stores/${s.id}/orders`), 200)
    })

    test('accepting as another user (email mismatch) → 403|404; the invitee can still accept', async () => {
      const m = await newMerchant()
      const [{ u, inv }, other] = await Promise.all([invited(m), newUser('user', { label: 'other' })])
      expectDenied(await accept(other, inv.id), { crossTenant: true })
      expect((await me(other.token)).merchantId ?? undefined).toBeUndefined()
      ok(await accept(u, inv.id), 200)
    })

    test('accepting a cancelled invitation → 404|409; still not a member', async () => {
      const m = await newMerchant()
      const { u, inv } = await invited(m)
      expectStatus(await m.owner.api.delete(`/api/merchants/${m.id}/invitations/${inv.id}`), 204)
      expectStatus(await accept(u, inv.id), 404, 409)
      expect((await me(u.token)).merchantId ?? undefined).toBeUndefined()
    })

    test('accepting an already accepted invitation → 404|409', async () => {
      const m = await newMerchant()
      const { u, inv } = await invited(m)
      ok(await accept(u, inv.id), 200)
      expectStatus(await accept(u, inv.id), 404, 409)
    })

    test('a user who already belongs to a merchant accepting → 409; membership unchanged', async () => {
      const [a, b] = await Promise.all([newMerchant(), newMerchant()])
      const u = await b.member('b-member')
      const inv = await a.invite(u.email)
      expectConflict(await accept(u, inv.id))
      expect((await me(u.token)).merchantId).toBe(b.id)
    })

    // review-d: the second join hit the unique index inside the IdP's accept, which aborted the
    // transaction and answered 500. One merchant per user must hold under races, with a clean 409.
    test('two merchants invite the same user; accepting both at once → one 200, one 409; one merchant', async () => {
      const [a, b] = await Promise.all([newMerchant(), newMerchant()])
      const u = await newUser('user', { label: 'invitee' })
      const [ia, ib] = await Promise.all([a.invite(u.email), b.invite(u.email)])
      const rs = await Promise.all([accept(u, ia.id), accept(u, ib.id)])
      expect(rs.map((r) => r.status).sort(), rs.map((r) => `${r.status} ${r.text}`).join(' | ')).toEqual([200, 409])
      const won = rs[0]!.status === 200 ? a : b
      expect((await me(u.token)).merchantId).toBe(won.id)
    })

    test('accept racing a direct add elsewhere → one 2xx, one 409', async () => {
      const [a, b] = await Promise.all([newMerchant(), newMerchant()])
      const u = await newUser('user', { label: 'invitee' })
      const inv = await a.invite(u.email)
      const rs = await Promise.all([accept(u, inv.id), b.owner.api.post(`/api/merchants/${b.id}/members`, { userId: u.id })])
      const st = rs.map((r) => r.status)
      expect(st.filter((x) => x === 409).length, rs.map((r) => `${r.status} ${r.text}`).join(' | ')).toBe(1)
      expect(st.filter((x) => x >= 200 && x < 300).length).toBe(1)
    })

    test('accept without a token → 401', async () => {
      const m = await newMerchant()
      const { inv } = await invited(m)
      expectUnauthenticated(await anon.post(`/api/invitations/${inv.id}/accept`))
    })
  })

  // ---------- §15.3 suspension at the IdP ----------
  // "Can't log in" = the driver's loginUser/loginClient promise rejects (the IdP refuses, not the app).

  describe('suspension at the IdP', () => {
    test("a suspended merchant's users can't log in (owner and member)", async () => {
      const m = await newMerchant()
      const member = await m.member()
      await m.suspend()
      await expect(relogin(m.owner)).rejects.toThrow()
      await expect(relogin(member)).rejects.toThrow()
    })

    test("a suspended merchant's agents can't get tokens", async () => {
      const m = await newMerchant()
      const creds = await registerAgent(m.owner)
      await m.suspend()
      await expect(driver.loginClient(creds.clientId, creds.clientSecret)).rejects.toThrow()
    })

    test('tokens issued before the suspension get 403 merchant_suspended (users and agents)', async () => {
      const { m, s } = await merchantWithStore()
      const agent = await grantedAgent(m.owner, s.id, ['order.view'])
      await m.suspend()
      expectDenied(await m.owner.api.get(`/api/merchants/${m.id}`), { code: 'merchant_suspended' })
      expectDenied(await agent.api.get(`/api/stores/${s.id}/orders`), { code: 'merchant_suspended' })
    })

    test("reinstating restores users' login; the new token works", async () => {
      const m = await newMerchant()
      const member = await m.member()
      await m.suspend()
      await expect(relogin(m.owner)).rejects.toThrow()
      await m.reinstate()
      for (const who of [m.owner, member]) {
        const token = await relogin(who)
        expect(await me(token)).toMatchObject({ id: who.id, merchantId: m.id })
      }
      ok(await anon.as(await relogin(m.owner), 'owner').get(`/api/merchants/${m.id}`), 200)
    })

    test("reinstating restores agents' tokens; the new token works", async () => {
      const { m, s } = await merchantWithStore()
      const creds = await registerAgent(m.owner)
      await grantAgent(m.owner, s.id, creds.id, ['order.view'])
      await m.suspend()
      await expect(driver.loginClient(creds.clientId, creds.clientSecret)).rejects.toThrow()
      await m.reinstate()
      const token = await driver.loginClient(creds.clientId, creds.clientSecret)
      ok(await anon.as(token, 'agent').get('/api/me'), 200)
      ok(await anon.as(token, 'agent').get(`/api/stores/${s.id}/orders`), 200)
    })

    test('platform staff still log in while a merchant is suspended', async () => {
      const [m, admin, support] = await Promise.all([newMerchant(), platformAdmin(), newSupport()])
      await m.suspend()
      for (const who of [admin, support]) {
        expect(await me(await relogin(who))).toMatchObject({ id: who.id, kind: 'platform' })
      }
    })

    test("a customer of the suspended merchant's store still logs in", async () => {
      const { m, s } = await merchantWithStore()
      const customer = await newCustomer()
      await m.order(s.id, 1000, customer)
      await m.suspend()
      expect(await me(await relogin(customer))).toMatchObject({ id: customer.id, kind: 'customer' })
    })

    test("an app installed on the suspended merchant's store still gets tokens", async () => {
      const { m, s } = await merchantWithStore()
      const app = await installedApp(m.owner, s.id, ['order.view'])
      await m.suspend()
      const token = await driver.loginClient(app.creds.clientId, app.creds.clientSecret)
      expect(typeof token).toBe('string')
    })

    test("another merchant's users still log in", async () => {
      const [a, b] = await Promise.all([newMerchant(), newMerchant()])
      const bMember = await b.member()
      await a.suspend()
      for (const who of [b.owner, bMember]) {
        expect(await me(await relogin(who))).toMatchObject({ id: who.id, merchantId: b.id })
      }
    })
  })
})

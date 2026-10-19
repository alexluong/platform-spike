// Review probes for stack i (results/review-i.md): cross-pool attacks through the gateway, token
// shape, and what disabling an identity does to tokens already issued. Not conformance tests.
//   STACK=i HOST=cs-ws.lab.alexluong.com pnpm vitest run --config review-i/vitest.config.ts
// Probes that deactivate users need the review tool on cs-ws (go/cmd/i-review, see its header);
// they are skipped unless I_REVIEW=1.
import { execFileSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { describe, expect, test } from 'vitest'
import { ok } from '../src/client'
import type { Order } from '../src/types'
import { anon, createTenantUser, loginWithShop, newActiveMerchant, newCustomer, newTenantUser, sleep } from '../src/world'

const REDIRECT = 'http://localhost:3999/callback'
const b64url = (b: Buffer) => b.toString('base64url')

interface Target {
  issuer: string
  clientId: string
  projectId: string
  orgId: string
}
async function tenant(mid: string, org: 'staff' | 'customers'): Promise<Target> {
  const id = ok(await anon.get<{ issuer: string; clientId: string; projectId: string; orgs: Record<string, string> }>(`/api/merchants/${mid}/identity`), 200)
  return { issuer: id.issuer, clientId: id.clientId, projectId: id.projectId, orgId: id.orgs[org]! }
}

interface Started {
  authRequest: string
  verifier: string
  state: string
  t: Target
}
async function authorize(t: Target): Promise<Started> {
  const verifier = b64url(randomBytes(32))
  const state = b64url(randomBytes(12))
  const q = new URLSearchParams({
    client_id: t.clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: `openid profile email urn:zitadel:iam:org:project:id:${t.projectId}:aud urn:zitadel:iam:org:id:${t.orgId}`,
    code_challenge: b64url(createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
    state,
  })
  const res = await fetch(`${t.issuer}/oauth/v2/authorize?${q}`, { redirect: 'manual' })
  const loc = new URL(res.headers.get('location')!, t.issuer)
  return { authRequest: loc.searchParams.get('authRequest')!, verifier, state, t }
}
const postJSON = (url: string, body: unknown) =>
  fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

async function password(at: Target, s: Started, email: string, pw: string): Promise<Response> {
  return postJSON(`${at.issuer}/ui/v2/login/password`, { authRequest: s.authRequest, loginName: email, password: pw })
}
function codeOf(callbackUrl: string): string {
  return new URL(callbackUrl).searchParams.get('code')!
}
async function token(at: Target, code: string, verifier: string, clientId = at.clientId): Promise<Response> {
  return fetch(`${at.issuer}/oauth/v2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier }),
  })
}
async function loginTokens(t: Target, email: string, pw: string): Promise<{ access_token: string; id_token: string }> {
  for (let i = 0; ; i++) {
    const s = await authorize(t)
    const r = await password(t, s, email, pw)
    if (r.ok) {
      const tr = await token(t, codeOf((await r.json()).callbackUrl), s.verifier)
      if (tr.ok) return tr.json()
      if (i > 4) throw new Error(`token ${tr.status} ${await tr.text()}`)
    } else if (i > 4) throw new Error(`password ${r.status} ${await r.text()}`)
    await sleep(500)
  }
}

/** Shop leg up to the intent's success URL (not opened): {authRequest of the tenant, done URL}. */
async function shopUpToDone(t: Target, email: string, pw: string, s?: Started): Promise<{ s: Started; done: URL }> {
  s ??= await authorize(t)
  const { authUrl } = await (await postJSON(`${t.issuer}/ui/v2/login/idp`, { authRequest: s.authRequest })).json()
  const up = new URL(authUrl)
  const pl = new URL((await fetch(authUrl, { redirect: 'manual' })).headers.get('location')!, up.origin)
  const pr = await postJSON(`${up.origin}/ui/v2/login/password`, { authRequest: pl.searchParams.get('authRequest'), loginName: email, password: pw })
  if (!pr.ok) throw new Error(`Shop login ${pr.status} ${await pr.text()}`)
  const cb = (await pr.json()).callbackUrl
  const done = new URL((await fetch(cb, { redirect: 'manual' })).headers.get('location')!, t.issuer)
  return { s, done }
}

const claims = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString())
const instanceOf = (issuer: string) => new URL(issuer).hostname.split('.')[0] + '.zitadel.internal'
const meStatus = async (tok: string) => (await anon.as(tok, 'probe').get('/api/me')).status

function reviewTool(...args: string[]): string {
  return execFileSync('ssh', ['cs-ws', 'docker', 'run', '--rm', '--network', 'ps-i_i-net', '-v', 'ps-i_i-keys:/keys:ro', '-v', '/tmp/i-review:/i-review', 'alpine', '/i-review', ...args], {
    encoding: 'utf8',
  })
}

describe('review i: cross-pool', { timeout: 180_000 }, () => {
  test('codes, auth requests, intents and tokens stay in their instance', async () => {
    const [m1, m2] = await Promise.all([newActiveMerchant(), newActiveMerchant()])
    const [t1, t2] = await Promise.all([tenant(m1.id, 'staff'), tenant(m2.id, 'staff')])
    const u = await createTenantUser(m1.id, 'user')
    await sleep(1000)

    // 1. M1's auth request at M2's login stand-in → refused.
    const s1 = await authorize(t1)
    expect((await password(t2, s1, u.email, u.password)).status).toBe(400)

    // 2. M1's code at M2's token endpoint (with M2's client and with M1's client id) → refused;
    //    the code still works at M1 afterwards.
    let r = await password(t1, s1, u.email, u.password)
    for (let i = 0; !r.ok && i < 5; i++) {
      await sleep(500)
      r = await password(t1, s1, u.email, u.password)
    }
    expect(r.status).toBe(200)
    const code = codeOf((await r.json()).callbackUrl)
    expect((await token(t2, code, s1.verifier)).status).toBeGreaterThanOrEqual(400)
    expect((await token(t2, code, s1.verifier, t1.clientId)).status).toBeGreaterThanOrEqual(400)
    const tr = await token(t1, code, s1.verifier)
    expect(tr.status, 'code still redeemable at M1').toBe(200)
    const { access_token: at1, id_token: idt1 } = await tr.json()

    // 3. M1's access token at M2's userinfo → 401; at M2's API → 403/404.
    expect((await fetch(`${t2.issuer}/oidc/v1/userinfo`, { headers: { Authorization: `Bearer ${at1}` } })).status).toBe(401)
    expect([403, 404]).toContain((await anon.as(at1).get(`/api/merchants/${m2.id}`)).status)

    // 4. ID token as a bearer → 401 (P7).
    expect(await meStatus(idt1)).toBe(401)

    // 5. Token shape: lifetime and claims (what disabling a user leaves alive).
    const c = claims(at1)
    console.log('tenant access token', { lifetime_s: c.exp - c.iat, amr: c.amr, client_id: c.client_id, aud: c.aud })
  })

  test('Sign in with Shop: intents stay at their merchant; a staff auth request cannot take the Shop path', async () => {
    const [m1, m2] = await Promise.all([newActiveMerchant(), newActiveMerchant()])
    const buyer = await newCustomer('shop-probe')
    const [c1, c2, st1] = await Promise.all([tenant(m1.id, 'customers'), tenant(m2.id, 'customers'), tenant(m1.id, 'staff')])

    // M1's intent (id + token) replayed at M2's success URL → refused.
    const { done } = await shopUpToDone(c1, buyer.email, buyer.password)
    const s2 = await authorize(c2)
    const at2 = new URL(`${c2.issuer}/ui/v2/login/idp/done`)
    at2.search = done.search
    at2.searchParams.set('authRequest', s2.authRequest)
    const rr = await fetch(at2)
    console.log('M1 intent at M2', rr.status, (await rr.text()).slice(0, 160))
    expect(rr.status).toBeGreaterThanOrEqual(400)

    // A staff-scoped auth request at M1 taking the Shop path.
    const ss = await authorize(st1)
    const { done: d2 } = await shopUpToDone(c1, buyer.email, buyer.password, ss)
    const fin = await fetch(d2)
    const body = await fin.text()
    console.log('staff auth request via Shop', fin.status, body.slice(0, 200))
    if (fin.ok) {
      const tr = await token(st1, codeOf(JSON.parse(body).callbackUrl), ss.verifier)
      const tok = tr.ok ? (await tr.json()).access_token : undefined
      const me = tok ? ok(await anon.as(tok).get<{ kind: string }>('/api/me'), 200) : undefined
      console.log('  → token', tr.status, 'me', me)
      expect(me?.kind ?? 'customer', 'never staff').toBe('customer')
    }
  })

  test('login CSRF: an intent finishes any auth request of the same merchant (not bound to the one it was started for)', async () => {
    const m = await newActiveMerchant()
    const attacker = await newCustomer('shop-attacker')
    const c = await tenant(m.id, 'customers')
    const victim = await authorize(c) // the victim's pending login
    const { done } = await shopUpToDone(c, attacker.email, attacker.password) // attacker's own intent
    done.searchParams.set('authRequest', victim.authRequest)
    const r = await fetch(done)
    console.log('attacker intent + victim auth request', r.status)
    if (r.ok) {
      const tr = await token(c, codeOf((await r.json()).callbackUrl), victim.verifier)
      console.log('  victim redeems → logged in as the attacker:', tr.status)
    }
  })
})

describe.skipIf(process.env.I_REVIEW !== '1')('review i: disabling identities', { timeout: 240_000 }, () => {
  test('deactivating a Shop account or a tenant user leaves issued tokens working (12 h)', async () => {
    const m = await newActiveMerchant()
    const s = await m.store()
    const p = await m.product(s.id, 1000)
    const buyer = await newCustomer('shop-disable')
    const linked = await loginWithShop(m.id, buyer)
    const staff = await newTenantUser(m.id, 'user')
    const plat = instanceOf(claims(buyer.token).iss)
    const ten = instanceOf(claims(linked).iss)

    reviewTool('deactivate', plat, claims(buyer.token).sub)
    reviewTool('deactivate', ten, claims(staff.token).sub)
    await sleep(3000)
    try {
      const shopMe = await meStatus(buyer.token)
      const linkedMe = await meStatus(linked)
      const order = await anon.as(linked).post<Order>(`/api/stores/${s.id}/orders`, { items: [{ productId: p.id, qty: 1 }] })
      const staffMe = await meStatus(staff.token)
      let fresh = 'ok'
      try {
        await loginWithShop(m.id, buyer)
      } catch (e) {
        fresh = `refused: ${String(e).slice(0, 120)}`
      }
      console.log({ shopMe, linkedMe, linkedOrder: order.status, staffMe, freshShopLogin: fresh })
      expect(fresh).toMatch(/^refused/)
    } finally {
      reviewTool('reactivate', plat, claims(buyer.token).sub)
      reviewTool('reactivate', ten, claims(staff.token).sub)
    }
  })
})

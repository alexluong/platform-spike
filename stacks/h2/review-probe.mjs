// review-h2: live cross-pool probes against ps-h2 (results/review-h2.md). Every line prints
// what was tried and the status; "ok" means the attack failed (or the legit path still works).
//   node stacks/h2/review-probe.mjs            APP_URL (default http://cs-ws.lab.alexluong.com:8098), TEST_SECRET
import { createHash, randomBytes } from 'node:crypto'

const base = process.env.APP_URL ?? 'http://cs-ws.lab.alexluong.com:8098'
const secret = process.env.TEST_SECRET ?? 'test-secret'
const redirectUri = 'http://127.0.0.1/callback'
const b64 = (b) => b.toString('base64url')
const onApp = (u) => { const x = new URL(u, base); const b = new URL(base); x.protocol = b.protocol; x.host = b.host; return x }
const get = (u, h = {}) => fetch(onApp(u), { redirect: 'manual', headers: h })
const form = (u, body, h = {}) => fetch(onApp(u), { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', ...h }, body: new URLSearchParams(body) })
const api = async (method, path, body, token, extra = {}) => {
  const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra }, body: body ? JSON.stringify(body) : undefined })
  const t = await r.text()
  return { status: r.status, body: t ? (() => { try { return JSON.parse(t) } catch { return t } })() : null }
}
const must = async (...a) => { const r = await api(...a); if (r.status >= 300) throw new Error(`${a[0]} ${a[1]}: ${r.status} ${JSON.stringify(r.body)}`); return r.body }
const uniq = (l) => `${l}-${Date.now().toString(36)}${randomBytes(3).toString('hex')}@probe.example`
const loc = (r) => new URL(r.headers.get('location') ?? '', base)

const results = []
function check(name, got, okIf) {
  const ok = okIf(got)
  results.push({ ok, name, got })
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: ${typeof got === 'object' ? JSON.stringify(got) : got}`)
}

async function authorize(issuer, clientId, scope = 'openid') {
  const verifier = b64(randomBytes(32))
  const q = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope, state: 's1',
    code_challenge: b64(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256' })
  const r = await get(`${issuer}/authorize?${q}`)
  if (r.status !== 302) throw new Error(`authorize ${issuer} ${clientId}: ${r.status} ${await r.text()}`)
  return { id: loc(r).searchParams.get('id'), verifier, issuer, clientId }
}
async function loginCode(issuer, clientId, email, password, scope) {
  const a = await authorize(issuer, clientId, scope)
  const r = await form(`${issuer}/login`, { id: a.id, email, password })
  if (r.status !== 302) return { ...a, status: r.status }
  return { ...a, status: 302, code: new URL(r.headers.get('location')).searchParams.get('code') }
}
const exchange = (issuer, a) => form(`${issuer}/oauth/token`, { grant_type: 'authorization_code', code: a.code, redirect_uri: redirectUri, client_id: a.clientId, code_verifier: a.verifier })
async function tokens(issuer, clientId, email, password, scope) {
  const a = await loginCode(issuer, clientId, email, password, scope)
  const r = await exchange(issuer, a)
  if (!r.ok) throw new Error(`token ${r.status} ${await r.text()}`)
  return r.json()
}
async function testUser(kind, extra = {}) {
  const email = uniq(kind), password = `Pw-${randomBytes(6).toString('hex')}`
  const u = await must('POST', '/api/_test/users', { email, password, kind, ...extra }, null, { 'x-test-secret': secret })
  return { ...u, email, password }
}
async function tenantUser(mid, kind) {
  const email = uniq(`t${kind}`), password = `Pw-${randomBytes(6).toString('hex')}`
  const u = await must('POST', `/api/_test/merchants/${mid}/users`, { email, password, kind }, null, { 'x-test-secret': secret })
  return { ...u, email, password }
}
const issuerOf = async (mid) => (await must('GET', `/api/merchants/${mid}/identity`)).issuer

// Sign in with Shop, step by step, so the probes can swap pieces between merchants.
async function shopStart(issuer) {
  const a = await authorize(issuer, 'storefront')
  const s = await get(`${issuer}/login/shop?id=${a.id}`)
  if (s.status !== 302) throw new Error(`login/shop ${s.status} ${await s.text()}`)
  const cookie = (s.headers.get('set-cookie') ?? '').split(';')[0]
  return { a, cookie, shopAuthorize: loc(s) }
}
async function shopLeg(shopAuthorize, email, password) {
  const sa = await get(shopAuthorize)
  if (sa.status !== 302) return { status: sa.status, body: await sa.text() }
  const sl = loc(sa)
  const lr = await form(sl.origin + sl.pathname, { id: sl.searchParams.get('id'), email, password })
  if (lr.status !== 302) return { status: lr.status, body: await lr.text() }
  return { status: 302, callback: loc(lr) }
}

const admin = await testUser('platform', { platformRole: 'platform_admin' })
admin.token = (await tokens(`${base}/oidc/workforce`, 'platform-cli', admin.email, admin.password)).access_token
const mk = async () => must('POST', '/api/platform/merchants', { name: 'probe', ownerUserId: (await testUser('user')).id }, admin.token)
const [m1, m2] = [await mk(), await mk()]
const [i1, i2] = [await issuerOf(m1.id), await issuerOf(m2.id)]
const shopIss = `${base}/oidc/shop`
const platIss = `${base}/oidc/platform`
const c1 = await tenantUser(m1.id, 'customer')
const s1 = await tenantUser(m1.id, 'user')
const buyer = await testUser('customer')

// --- codes across pools ---
{
  const a = await loginCode(i1, 'storefront', c1.email, c1.password)
  check('M1 code at M2 token endpoint', (await exchange(i2, a)).status, (s) => s === 400)
  check('M1 code at shop token endpoint', (await exchange(shopIss, a)).status, (s) => s === 400)
  check('M1 code still redeemable at M1 after cross-pool attempts', (await exchange(i1, a)).status, (s) => s === 200)
}
// --- refresh tokens across pools ---
{
  const t = await tokens(i1, 'storefront', c1.email, c1.password, 'openid offline_access')
  check('refresh token issued (offline_access)', !!t.refresh_token, (x) => x)
  const rf = (iss, rt = t.refresh_token) => form(`${iss}/oauth/token`, { grant_type: 'refresh_token', refresh_token: rt, client_id: 'storefront' })
  check('M1 refresh at M2', (await rf(i2)).status, (s) => s === 400)
  check('M1 refresh at shop (platform-cli)', (await form(`${shopIss}/oauth/token`, { grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: 'platform-cli' })).status, (s) => s >= 400)
  // revoke at M2 must not touch M1's family
  await form(`${i2}/revoke`, { token: t.refresh_token, token_type_hint: 'refresh_token', client_id: 'storefront' })
  const ok = await rf(i1)
  check('M1 refresh at M1 after cross-pool attempts + M2 /revoke', ok.status, (s) => s === 200)
  const at = (await ok.json()).access_token
  // userinfo across pools
  check('M1 access token at M2 /userinfo', (await get(`${i2}/userinfo`, { authorization: `Bearer ${at}` })).status, (s) => s === 401 || s === 403)
  check('M1 access token at M1 /userinfo', (await get(`${i1}/userinfo`, { authorization: `Bearer ${at}` })).status, (s) => s === 200)
  check('M1 customer token on M2 order endpoint (app)', (await api('GET', `/api/merchants/${m2.id}`, null, at)).status, (s) => s === 403 || s === 404)
}
// --- clients across pools ---
{
  check('platform-cli at a tenant pool /authorize', (await get(`${i1}/authorize?client_id=platform-cli&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid&code_challenge=${'x'.repeat(43)}&code_challenge_method=S256`)).status, (s) => s !== 302)
  check('tenant staff via storefront client (wrong group)', (await loginCode(i1, 'storefront', s1.email, s1.password)).status, (s) => s === 401)
  check('tenant customer via merchant-admin client (wrong group)', (await loginCode(i1, 'merchant-admin', c1.email, c1.password)).status, (s) => s === 401)
  check('M1 staff at M2 (merchant-admin)', (await loginCode(i2, 'merchant-admin', s1.email, s1.password)).status, (s) => s === 401)
  check('platform account at workforce pool', (await loginCode(`${base}/oidc/workforce`, 'platform-cli', buyer.email, buyer.password)).status, (s) => s === 401)
  // machine client of the platform pool at other pools
  const owner = await testUser('user')
  const m3 = await must('POST', '/api/platform/merchants', { name: 'probe', ownerUserId: owner.id }, admin.token)
  const ot = (await tokens(platIss, 'platform-cli', owner.email, owner.password)).access_token
  const ag = await must('POST', '/api/agents', { name: 'probe-agent', merchantId: m3.id }, ot)
  const basic = 'Basic ' + Buffer.from(`${ag.clientId}:${ag.clientSecret}`).toString('base64')
  for (const [n, iss] of [['tenant', await issuerOf(m3.id)], ['shop', shopIss], ['workforce', `${base}/oidc/workforce`]]) {
    check(`agent client_credentials at ${n} pool`, (await form(`${iss}/oauth/token`, { grant_type: 'client_credentials' }, { authorization: basic })).status, (s) => s === 400 || s === 401)
  }
  check('agent client_credentials at platform pool', (await form(`${platIss}/oauth/token`, { grant_type: 'client_credentials' }, { authorization: basic })).status, (s) => s === 200)
}
// --- issuer-shaped paths ---
for (const p of ['/oidc/PLATFORM/.well-known/openid-configuration', '/oidc/platform%2F.well-known/openid-configuration', '/oidc/%70latform/.well-known/openid-configuration',
  '/oidc/pl_doesnotexist/.well-known/openid-configuration',
  `/oidc/${new URL(i1).pathname.split('/')[2].toUpperCase()}/.well-known/openid-configuration`, '/oidc/platform./.well-known/openid-configuration', '/oidc/ platform/.well-known/openid-configuration']) {
  const r = await fetch(base + p, { redirect: 'manual' })
  check(`path ${p}`, r.status, (s) => s === 404 || s === 400)
}
// Unclean paths (//, ./, ../) get the mux's 307 to the cleaned path, which is then routed normally
// (fetch normalizes ../ itself; curl --path-as-is shows the 307).
for (const p of ['/oidc//platform/.well-known/openid-configuration']) {
  const r = await fetch(base + p, { redirect: 'manual' })
  check(`path ${p} → 307 to the clean path`, `${r.status} ${loc(r).pathname}`, (s) => s === '307 /oidc/platform/.well-known/openid-configuration')
}
{
  const a = await authorize(i1, 'storefront')
  for (const p of [`/authorize/callback?id=${a.id}`, `/authorize/callback/?id=${a.id}`, `/authorize//callback?id=${a.id}`, `//authorize/callback?id=${a.id}`]) {
    // follow the mux's clean-path redirect: wherever it lands must not hand out a code
    const r = await fetch(onApp(`${i1}${p}`), { redirect: 'follow' }).catch((e) => ({ status: 'err', url: String(e) }))
    check(`callback closed ${p.split('?')[0]} (redirects followed)`, r.status, (s) => s === 404 || s === 400)
  }
}
// --- Sign in with Shop across merchants ---
{
  // (a) the shop pool won't send M1's federation client to M2's callback
  const st1 = await shopStart(i1)
  const fed1 = st1.shopAuthorize.searchParams.get('client_id')
  const st2 = await shopStart(i2)
  const swapped = new URL(st2.shopAuthorize)
  swapped.searchParams.set('client_id', fed1)
  check('shop authorize: M1 fed client with M2 callback', (await get(swapped)).status, (s) => s !== 302 || !loc(s).pathname.endsWith('/login'))
  // (b) M1's upstream code presented at M2's callback with M2's own state + cookie
  const leg1 = await shopLeg(st1.shopAuthorize, buyer.email, buyer.password)
  const cb = new URL(`${i2}/federation/shop/callback`)
  cb.searchParams.set('code', leg1.callback.searchParams.get('code'))
  cb.searchParams.set('state', st2.shopAuthorize.searchParams.get('state'))
  const r = await get(cb, { cookie: st2.cookie })
  check('M1 shop code at M2 callback (M2 state+cookie)', `${r.status} ${await r.text()}`, (s) => !s.startsWith('302'))
  // (c) M1's state + cookie at M2's callback
  const st3 = await shopStart(i1)
  const leg3 = await shopLeg(st3.shopAuthorize, buyer.email, buyer.password)
  const cb3 = new URL(leg3.callback)
  cb3.pathname = new URL(i2).pathname + '/federation/shop/callback'
  check('M1 callback (state+code+cookie) replayed at M2', (await get(cb3, { cookie: st3.cookie })).status, (s) => s === 400)
  check('M1 callback still completes at M1 afterwards', (await get(leg3.callback, { cookie: st3.cookie })).status, (s) => s === 302)
  // (d) no cookie / wrong cookie
  const st4 = await shopStart(i1)
  const leg4 = await shopLeg(st4.shopAuthorize, buyer.email, buyer.password)
  check('callback without binding cookie', (await get(leg4.callback)).status, (s) => s === 400)
  check('callback with another round trip\'s cookie', (await get(leg4.callback, { cookie: st1.cookie })).status, (s) => s === 400)
  check('callback with the right cookie after failed tries', (await get(leg4.callback, { cookie: st4.cookie })).status, (s) => s === 302)
  // (e) the shop token the federation client gets is not an API token
  // (f) a staff auth request can't take the Shop path
  const sa = await authorize(i1, 'merchant-admin')
  check('login/shop with a staff auth request', (await get(`${i1}/login/shop?id=${sa.id}`)).status, (s) => s === 400)
  // (g) M1's auth request id at M2's login/shop
  const ca = await authorize(i1, 'storefront')
  check('M1 auth request id at M2 login/shop', (await get(`${i2}/login/shop?id=${ca.id}`)).status, (s) => s === 400)
  check('login/shop at the shop pool itself', (await get(`${shopIss}/login/shop?id=${ca.id}`)).status, (s) => s === 404)
  // (h) M1 auth request id at M2 login
  check('M1 auth request id at M2 /login', (await form(`${i2}/login`, { id: ca.id, email: c1.email, password: c1.password })).status, (s) => s === 400)
}

console.log(`\n${results.filter((r) => r.ok).length}/${results.length} ok`)
process.exit(results.every((r) => r.ok) ? 0 : 1)

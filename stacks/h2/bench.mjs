// Stack h2 measurements (SPEC §12, §16.7): provisioning time, login latency per pool, warming pools.
//   node stacks/h2/bench.mjs provision <n> [concurrency]   create n merchants, time each create
//   node stacks/h2/bench.mjs warm [limit]                  each merchant: a tenant customer + one login
//   node stacks/h2/bench.mjs logins <k>                    k sequential logins per pool kind, p50/p95
// APP_URL (default http://cs-ws.lab.alexluong.com:8098), TEST_SECRET (default test-secret).
import { createHash, randomBytes } from 'node:crypto'

const base = process.env.APP_URL ?? 'http://cs-ws.lab.alexluong.com:8098'
const secret = process.env.TEST_SECRET ?? 'test-secret'
const redirectUri = 'http://127.0.0.1/callback'
const b64 = (b) => b.toString('base64url')
const onApp = (u) => { const x = new URL(u); const b = new URL(base); x.protocol = b.protocol; x.host = b.host; return x }
const get = (u, h = {}) => fetch(u, { redirect: 'manual', headers: h })
const form = (u, body, h = {}) => fetch(u, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', ...h }, body: new URLSearchParams(body) })
const json = async (method, path, body, token, extra = {}) => {
  const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra }, body: body ? JSON.stringify(body) : undefined })
  const t = await r.text()
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${t}`)
  return t ? JSON.parse(t) : null
}
const uniq = (l) => `${l}-${Date.now().toString(36)}${randomBytes(3).toString('hex')}@bench.example`

async function authorize(issuer, clientId) {
  const verifier = b64(randomBytes(32))
  const q = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid', state: 's',
    code_challenge: b64(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256' })
  const r = await get(onApp(`${issuer}/authorize?${q}`))
  if (r.status !== 302) throw new Error(`authorize ${r.status} ${await r.text()}`)
  return { id: new URL(r.headers.get('location'), base).searchParams.get('id'), verifier, issuer, clientId }
}
async function finish(a, r) {
  if (r.status !== 302) throw new Error(`login ${r.status} ${await r.text()}`)
  const code = new URL(r.headers.get('location')).searchParams.get('code')
  const t = await form(onApp(`${a.issuer}/oauth/token`), { grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: a.clientId, code_verifier: a.verifier })
  if (!t.ok) throw new Error(`token ${t.status}`)
  return (await t.json()).access_token
}
async function pwLogin(issuer, clientId, email, password) {
  const a = await authorize(issuer, clientId)
  return finish(a, await form(onApp(`${issuer}/login`), { id: a.id, email, password }))
}
async function shopLogin(issuer, email, password) {
  const a = await authorize(issuer, 'storefront')
  const s = await get(onApp(`${issuer}/login/shop?id=${a.id}`))
  const cookie = (s.headers.get('set-cookie') ?? '').split(';')[0]
  const sa = await get(onApp(new URL(s.headers.get('location'), base)))
  const sl = new URL(sa.headers.get('location'), base)
  const lr = await form(onApp(sl.origin + sl.pathname), { id: sl.searchParams.get('id'), email, password })
  if (lr.status !== 302) throw new Error(`shop login ${lr.status}`)
  return finish(a, await get(onApp(new URL(lr.headers.get('location'), base)), { cookie }))
}
const issuerOf = async (mid) => (await json('GET', `/api/merchants/${mid}/identity`)).issuer
async function testUser(kind, extra = {}) {
  const email = uniq(kind), password = `Pw-${randomBytes(6).toString('hex')}`
  const u = await json('POST', '/api/_test/users', { email, password, kind, ...extra }, null, { 'x-test-secret': secret })
  return { ...u, email, password }
}
async function admin() {
  const a = await testUser('platform', { platformRole: 'platform_admin' })
  a.token = await pwLogin(`${base}/oidc/workforce`, 'platform-cli', a.email, a.password)
  return a
}
const stats = (xs) => {
  const s = [...xs].sort((a, b) => a - b), q = (p) => s[Math.min(s.length - 1, Math.floor(p * s.length))]
  return { n: s.length, p50: +q(0.5).toFixed(1), p95: +q(0.95).toFixed(1), max: +s[s.length - 1].toFixed(1), mean: +(s.reduce((a, b) => a + b, 0) / s.length).toFixed(1) }
}
async function timed(f) { const t = performance.now(); await f(); return performance.now() - t }

async function provision(n, conc) {
  const a = await admin()
  const owners = []
  for (let i = 0; i < n; i++) owners.push(await testUser('user'))
  const times = []
  let next = 0
  await Promise.all(Array.from({ length: conc }, async () => {
    while (next < n) {
      const o = owners[next++]
      times.push(await timed(() => json('POST', '/api/platform/merchants', { name: 'bench', ownerUserId: o.id }, a.token)))
    }
  }))
  console.log(JSON.stringify({ provision: stats(times), concurrency: conc }))
}

async function warm(limit) {
  const a = await admin()
  const { items } = await json('GET', '/api/platform/merchants', null, a.token)
  const ms = items.filter((m) => m.status === 'active').slice(0, limit)
  let done = 0
  await Promise.all(Array.from({ length: 4 }, async () => {
    while (ms.length) {
      const m = ms.pop()
      const email = uniq('warm'), password = 'Pw-warm-1'
      await json('POST', `/api/_test/merchants/${m.id}/users`, { email, password, kind: 'customer' }, null, { 'x-test-secret': secret })
      await pwLogin(await issuerOf(m.id), 'storefront', email, password)
      done++
    }
  }))
  console.log(JSON.stringify({ warmed: done }))
}

async function logins(k) {
  const a = await admin()
  const staff = a, owner = await testUser('user'), buyer = await testUser('customer')
  const m = await json('POST', '/api/platform/merchants', { name: 'bench', ownerUserId: owner.id }, a.token)
  const iss = await issuerOf(m.id)
  const mk = async (kind) => {
    const email = uniq(kind), password = 'Pw-tenant-1'
    await json('POST', `/api/_test/merchants/${m.id}/users`, { email, password, kind }, null, { 'x-test-secret': secret })
    return { email, password }
  }
  const tstaff = await mk('user'), tcust = await mk('customer')
  const cases = {
    workforce: () => pwLogin(`${base}/oidc/workforce`, 'platform-cli', staff.email, staff.password),
    platform: () => pwLogin(`${base}/oidc/platform`, 'platform-cli', owner.email, owner.password),
    shop: () => pwLogin(`${base}/oidc/shop`, 'platform-cli', buyer.email, buyer.password),
    'tenant staff': () => pwLogin(iss, 'merchant-admin', tstaff.email, tstaff.password),
    'tenant customer': () => pwLogin(iss, 'storefront', tcust.email, tcust.password),
    'sign in with Shop': () => shopLogin(iss, buyer.email, buyer.password),
  }
  const out = {}
  for (const [name, f] of Object.entries(cases)) {
    await f() // warm
    const xs = []
    for (let i = 0; i < k; i++) xs.push(await timed(f))
    out[name] = stats(xs)
  }
  console.log(JSON.stringify(out, null, 1))
}

const [cmd, x, y] = process.argv.slice(2)
if (cmd === 'provision') await provision(Number(x ?? 100), Number(y ?? 1))
else if (cmd === 'warm') await warm(Number(x ?? 1e9))
else if (cmd === 'logins') await logins(Number(x ?? 30))
else console.error('usage: provision <n> [conc] | warm [limit] | logins <k>')

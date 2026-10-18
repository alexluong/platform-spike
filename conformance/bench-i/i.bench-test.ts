import { appendFileSync } from 'node:fs'
import { test } from 'vitest'
import { anon, loginTenant, loginWithShop, newCustomer, newTenantUser, newUser, platformAdmin, relogin, uniq, waitActive, newActiveMerchant } from '../src/world'
import type { Merchant } from '../src/types'

const bench = process.env.BENCH ?? ''
const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b)
  return Math.round(s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]!)
}
const out = process.env.BENCH_OUT ?? '/tmp/bench-i.jsonl'
const summary = (name: string, xs: number[]) =>
  appendFileSync(out, JSON.stringify({ at: new Date().toISOString(), name, n: xs.length, p50: pct(xs, 50), p95: pct(xs, 95), max: Math.round(Math.max(...xs)) }) + '\n')

test.runIf(bench === 'provision')('provisioning time', async () => {
  const N = Number(process.env.N ?? 100)
  const C = Number(process.env.C ?? 1)
  const admin = await platformAdmin()
  const createMs: number[] = []
  const activeMs: number[] = []
  let next = 0
  await Promise.all(
    Array.from({ length: C }, async () => {
      while (next < N) {
        next++
        const owner = await newUser('user', { label: 'bench-owner' })
        const t0 = performance.now()
        const r = await admin.api.post<Merchant>('/api/platform/merchants', { name: uniq('bench'), ownerUserId: owner.id })
        if (r.status !== 201) throw new Error(`create: ${r.status} ${r.text}`)
        createMs.push(performance.now() - t0)
        // poll every 100 ms until active
        for (;;) {
          const g = await owner.api.get<Merchant>(`/api/merchants/${r.body!.id}`)
          if (g.body?.status === 'active') break
          if (performance.now() - t0 > 120_000) throw new Error('not active after 120 s')
          await new Promise((res) => setTimeout(res, 100))
        }
        activeMs.push(performance.now() - t0)
      }
    }),
  )
  summary(`create request (C=${C})`, createMs)
  summary(`create → active (C=${C})`, activeMs)
})

test.runIf(bench === 'login')('login latency per pool', async () => {
  const K = Number(process.env.K ?? 20)
  const m = await newActiveMerchant()
  const [admin, buyer, staff, customer] = await Promise.all([platformAdmin(), newCustomer('bench-shop'), newTenantUser(m.id, 'user'), newTenantUser(m.id, 'customer')])
  await loginWithShop(m.id, buyer) // first time creates the linked identity
  const cases: [string, () => Promise<string>][] = [
    ['workforce (platform staff)', () => relogin(admin)],
    ['platform (account/owner)', () => relogin(m.owner)],
    ['shop (buyer, platform instance)', () => relogin(buyer)],
    ['tenant staff', () => loginTenant(m.id, 'user', staff.email, staff.password)],
    ['tenant customer', () => loginTenant(m.id, 'customer', customer.email, customer.password)],
    ['Sign in with Shop (both legs)', () => loginWithShop(m.id, buyer)],
  ]
  for (const [name, f] of cases) {
    const xs: number[] = []
    for (let i = 0; i < K; i++) {
      const t0 = performance.now()
      const tok = await f()
      xs.push(performance.now() - t0)
      if (i === 0) {
        const me = await anon.as(tok, 'bench').get('/api/me')
        if (me.status !== 200) throw new Error(`${name}: /api/me ${me.status}`)
      }
    }
    summary(name, xs)
  }
  // API request latency with a tenant token (verification against that pool's cached keys)
  const tok = await loginTenant(m.id, 'user', staff.email, staff.password)
  const api: number[] = []
  for (let i = 0; i < 50; i++) {
    const t0 = performance.now()
    await anon.as(tok, 'bench').get('/api/me')
    api.push(performance.now() - t0)
  }
  summary('GET /api/me with a tenant token', api)
})

// Provisioning failure story: Zitadel down while a merchant is created. Expected: 201
// provisioning, stays provisioning, the outbox relay retries, active soon after Zitadel is back.
test.runIf(bench === 'failure')('provisioning with Zitadel down', async () => {
  const { execSync } = await import('node:child_process')
  const dc = (cmd: string) => execSync(`docker compose -p ps-i --profile i ${cmd}`, { cwd: '..', stdio: 'pipe', env: { ...process.env, DOCKER_HOST: 'ssh://cs-ws' } })
  const admin = await platformAdmin()
  const owner = await newUser('user', { label: 'fail-owner' })
  ;(await admin.api.get('/api/platform/merchants')).status // warm the workforce keys
  await owner.api.get('/api/me') // warm the platform keys
  dc('stop i-zitadel')
  const t0 = performance.now()
  try {
    const r = await admin.api.post<Merchant>('/api/platform/merchants', { name: uniq('fail'), ownerUserId: owner.id })
    const id = r.body!.id
    const states: string[] = [`create ${r.status} ${r.body?.status}`]
    await new Promise((res) => setTimeout(res, 20_000))
    const mid = await owner.api.get<Merchant>(`/api/merchants/${id}`)
    states.push(`after 20 s with Zitadel down: ${mid.status} ${mid.body?.status}`)
    const store = await owner.api.post(`/api/merchants/${id}/stores`, { name: 'while provisioning' })
    states.push(`store create while provisioning: ${store.status}`)
    const up = performance.now()
    dc('start i-zitadel')
    for (;;) {
      const g = await owner.api.get<Merchant>(`/api/merchants/${id}`)
      if (g.body?.status === 'active') break
      if (performance.now() - up > 300_000) throw new Error('not active 300 s after Zitadel restart')
      await new Promise((res) => setTimeout(res, 500))
    }
    states.push(`active ${Math.round(performance.now() - up)} ms after 'start i-zitadel' (total ${Math.round(performance.now() - t0)} ms)`)
    appendFileSync(out, JSON.stringify({ at: new Date().toISOString(), name: 'failure story', states }) + '\n')
  } finally {
    dc('start i-zitadel')
  }
})

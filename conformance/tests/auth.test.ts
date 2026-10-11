// SPEC §2 principal kinds, §9 auth errors, /api/me, /healthz, test-support guard, §10 tokens.
import { describe, expect, test } from 'vitest'
import { expectError, expectStatus, expectUnauthenticated, ok } from '../src/client'
import { env } from '../src/env'
import type { Me } from '../src/types'
import { anon, grantedAgent, installedApp, merchantWithStore, newCustomer, newMerchant, newSupport, newUser, platformAdmin, uniq } from '../src/world'

describe('health', () => {
  test('GET /healthz → 200 without auth', async () => {
    expectStatus(await anon.get('/healthz'), 200)
  })
})

describe('unauthenticated', () => {
  const protectedEndpoints: [string, string, unknown?][] = [
    ['GET', '/api/me'],
    ['GET', '/api/me/orders'],
    ['GET', '/api/me/permissions?merchantId=does-not-exist'],
    ['GET', '/api/platform/merchants'],
    ['POST', '/api/platform/merchants', { name: 'x', ownerUserId: 'x' }],
    ['GET', '/api/merchants/does-not-exist'],
    ['GET', '/api/stores/does-not-exist/orders'],
    ['POST', '/api/stores/does-not-exist/orders', { items: [] }],
    ['POST', '/api/agents', { name: 'x' }],
  ]

  test.each(protectedEndpoints)('%s %s without a token → 401 unauthenticated (before any 404)', async (method, path, body) => {
    expectUnauthenticated(await anon.request(method, path, body))
  })

  const badTokens: [string, string][] = [
    ['garbage', 'not-a-token'],
    ['alg=none JWT', 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImtpbmQiOiJwbGF0Zm9ybSJ9.'],
    ['malformed JWT', 'eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl'],
  ]

  test.each(badTokens)('GET /api/me with %s token → 401', async (_name, token) => {
    expectUnauthenticated(await anon.as(token, 'bad-token').get('/api/me'))
  })

  test('non-Bearer Authorization header → 401', async () => {
    expectUnauthenticated(await anon.get('/api/me', { authorization: 'Basic dXNlcjpwYXNz' }))
  })

  test('public product listing needs no token', async () => {
    const { s } = await merchantWithStore()
    const body = ok(await anon.get(`/api/stores/${s.id}/products`), 200)
    expect(Array.isArray(body.items)).toBe(true)
  })
})

describe('test support guard', () => {
  test('POST /api/_test/users without X-Test-Secret → 401|403', async () => {
    const res = await anon.post('/api/_test/users', { email: `${uniq('nosecret')}@example.com`, password: 'Cf-x-Aa1!xyz', kind: 'user' })
    expectStatus(res, 401, 403)
  })
  test('POST /api/_test/users with a wrong secret → 401|403', async () => {
    const res = await anon.post(
      '/api/_test/users',
      { email: `${uniq('badsecret')}@example.com`, password: 'Cf-x-Aa1!xyz', kind: 'user' },
      { 'x-test-secret': `${env.testSecret}-wrong` },
    )
    expectStatus(res, 401, 403)
  })
  test('POST /api/_test/users with the secret → 201 {id, email}', async () => {
    const email = `${uniq('withsecret')}@example.com`
    const res = await anon.post('/api/_test/users', { email, password: 'Cf-1f2e3d4c-Aa1!', kind: 'customer' }, { 'x-test-secret': env.testSecret })
    const body = ok(res, 201)
    expect(typeof body.id).toBe('string')
    expect(body.email.toLowerCase()).toBe(email.toLowerCase())
  })
})

describe('GET /api/me per kind', () => {
  test('platform admin → kind platform', async () => {
    const a = await platformAdmin()
    const me = ok(await a.api.get<Me>('/api/me'), 200)
    expect(me).toMatchObject({ id: a.id, kind: 'platform' })
  })

  test('support → kind platform', async () => {
    const s = await newSupport()
    expect(ok(await s.api.get<Me>('/api/me'), 200)).toMatchObject({ id: s.id, kind: 'platform' })
  })

  test('customer → kind customer, no merchantId', async () => {
    const c = await newCustomer()
    const me = ok(await c.api.get<Me>('/api/me'), 200)
    expect(me).toMatchObject({ id: c.id, kind: 'customer' })
    expect(me.merchantId ?? null).toBeNull()
  })

  test('user with no merchant → kind user, no merchantId', async () => {
    const u = await newUser('user')
    const me = ok(await u.api.get<Me>('/api/me'), 200)
    expect(me).toMatchObject({ id: u.id, kind: 'user' })
    expect(me.merchantId ?? null).toBeNull()
  })

  test('merchant owner → kind user with merchantId (token issued before membership still works)', async () => {
    const m = await newMerchant()
    expect(ok(await m.owner.api.get<Me>('/api/me'), 200)).toMatchObject({ id: m.owner.id, kind: 'user', merchantId: m.id })
  })

  test('added member → merchantId of that merchant', async () => {
    const m = await newMerchant()
    const u = await m.member()
    expect(ok(await u.api.get<Me>('/api/me'), 200)).toMatchObject({ id: u.id, kind: 'user', merchantId: m.id })
  })

  test('app token → kind app', async () => {
    const { m, s } = await merchantWithStore()
    const app = await installedApp(m.owner, s.id, ['product.view'])
    const me = ok(await app.api.get<Me>('/api/me'), 200)
    expect(me.kind).toBe('app')
    expect(typeof me.id).toBe('string')
  })

  test('agent token → kind agent with the merchantId of its registering user', async () => {
    const { m, s } = await merchantWithStore()
    const agent = await grantedAgent(m.owner, s.id, ['store.view'])
    const me = ok(await agent.api.get<Me>('/api/me'), 200)
    expect(me).toMatchObject({ kind: 'agent', merchantId: m.id })
  })
})

describe('error shape', () => {
  test('nonexistent order → 403|404 with an {error:{code}} body', async () => {
    const m = await newMerchant()
    expectError(await m.owner.api.get('/api/orders/does-not-exist-0000'), [403, 404])
  })
})

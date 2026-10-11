import { describe, expect, it } from 'vitest'
import { authOptions, internalOnlyClientPrivileges } from './better-auth.js'

describe('OAuth client privileges', () => {
  const allow = internalOnlyClientPrivileges('k'.repeat(64))
  const h = (v?: string) => new Headers(v === undefined ? {} : { 'x-platform-internal': v })
  it('a session alone is not enough (any signed-in user would pass with `() => true`)', async () => {
    expect(await allow({ headers: h(), action: 'create' })).toBe(false)
    expect(await allow({ headers: h('wrong'), action: 'create' })).toBe(false)
  })
  it('the internal key allows create (and its client_credentials scopes) only', async () => {
    expect(await allow({ headers: h('k'.repeat(64)), action: 'create' })).toBe(true)
    expect(await allow({ headers: h('k'.repeat(64)), action: 'configure-client-credentials-scopes' })).toBe(true)
    for (const action of ['read', 'list', 'update', 'rotate', 'delete']) expect(await allow({ headers: h('k'.repeat(64)), action })).toBe(false)
  })
})

describe('auth options', () => {
  const base = { pool: {} as never, baseUrl: 'http://x', secret: 's'.repeat(32), apiResource: 'urn:x', internalKey: 'k' }
  it('rate limiting follows config; the IP header is passed when set', () => {
    expect(authOptions({ ...base, rateLimit: true }).rateLimit.enabled).toBe(true)
    expect(authOptions({ ...base, rateLimit: false }).rateLimit.enabled).toBe(false)
    expect(authOptions({ ...base, rateLimit: true, ipHeader: 'x-forwarded-for' }).advanced).toMatchObject({ ipAddress: { ipAddressHeaders: ['x-forwarded-for'] } })
  })
})

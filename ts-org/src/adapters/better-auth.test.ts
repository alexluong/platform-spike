import { describe, expect, it } from 'vitest'
import { TX_CONTROL, authOptions, internalOnlyClientPrivileges, orgOptions } from './better-auth.js'

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

describe('organization plugin (SPEC §15)', () => {
  const base = { pool: {} as never, baseUrl: 'http://x', secret: 's'.repeat(32), apiResource: 'urn:x', internalKey: 'k', rateLimit: false }
  /** Fake Better Auth adapter over in-memory member/organization rows. */
  const fakeDb = (members: Record<string, string>, orgs: Record<string, string>) => ({
    async findOne({ model, where }: { model: string; where: { field: string; value: string }[] }) {
      const v = where[0]!.value
      if (model === 'member') return members[v] ? { organizationId: members[v] } : null
      if (model === 'organization') return orgs[v] ? { id: v, status: orgs[v] } : null
      return null
    },
  })
  const hook = authOptions(base).databaseHooks.session.create.before
  const ctx = (members: Record<string, string>, orgs: Record<string, string>) => ({ context: { adapter: fakeDb(members, orgs) } })

  it('no session for a member of a suspended organization (login policy, §15.3)', async () => {
    await expect(hook({ userId: 'u1' }, ctx({ u1: 'm1' }, { m1: 'suspended' }))).rejects.toMatchObject({ statusCode: 403 })
  })
  it('members of active organizations, and users in none (staff, customers), sign in', async () => {
    await expect(hook({ userId: 'u1' }, ctx({ u1: 'm1' }, { m1: 'active' }))).resolves.toBeUndefined()
    await expect(hook({ userId: 'u2' }, ctx({}, {}))).resolves.toBeUndefined()
  })
  it("nobody creates organizations through Better Auth's own routes; limits don't cap a merchant at 100", () => {
    expect(orgOptions.allowUserToCreateOrganization).toBe(false)
    expect(orgOptions.membershipLimit).toBeGreaterThan(100)
    expect(orgOptions.schema.organization.additionalFields.status).toMatchObject({ input: false, defaultValue: 'active' })
  })
  it("transaction control never runs on the app's transaction connection", () => {
    for (const q of ['begin', 'BEGIN', ' start transaction', 'commit', 'rollback', 'savepoint sp1', 'release sp1', 'end']) expect(TX_CONTROL.test(q)).toBe(true)
    for (const q of ['select * from "member"', 'insert into "organization" ("id") values ($1)', 'update "invitation" set "status" = $1']) expect(TX_CONTROL.test(q)).toBe(false)
  })
})

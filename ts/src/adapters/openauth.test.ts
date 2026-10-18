import { issuer } from '@openauthjs/openauth/issuer'
import type { Provider } from '@openauthjs/openauth/provider/provider'
import { MemoryStorage } from '@openauthjs/openauth/storage/memory'
import { describe, expect, it } from 'vitest'
import { checkAuthorize, subjects } from './openauth.js'

// The raw OpenAuth 0.4.3 issuer, to pin down the two behaviours the adapter works around.
function rawIssuer(allow = true) {
  const machine: Provider<{ id: string }> = { type: 'client', init() {}, client: async ({ clientID }) => ({ id: clientID }) }
  return issuer({
    subjects,
    storage: MemoryStorage(),
    providers: { client: machine },
    allow: async () => allow,
    success: async (ctx, v) => ctx.subject('client', { clientId: v.id }),
  })
}
const claims = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString())

describe('OpenAuth issuer (unwrapped)', () => {
  it('takes `iss` from X-Forwarded-Host: a caller picks the issuer of its own token', async () => {
    const res = await rawIssuer().fetch(
      new Request('http://app.internal/token', {
        method: 'POST',
        headers: { 'x-forwarded-host': 'evil.example', 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'client_credentials', provider: 'client', client_id: 'c1', client_secret: 's' }),
      }),
    )
    const { access_token } = (await res.json()) as { access_token: string }
    expect(claims(access_token)).toMatchObject({ iss: 'http://evil.example', aud: 'c1', sub: expect.stringMatching(/^client:/), mode: 'access' })
  })

  it('redirects to the redirect_uri that allow() rejected (open redirect)', async () => {
    const res = await rawIssuer(false).fetch(
      new Request('http://app.internal/authorize?client_id=x&response_type=code&redirect_uri=https://evil.example/cb'),
    )
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toMatch(/^https:\/\/evil\.example\/cb\?error=unauthorized_client/)
  })
})

describe('checkAuthorize (gate in front of /authorize)', () => {
  const cfg = { firstPartyClient: 'platform-cli', redirectUris: ['http://127.0.0.1/callback'] }
  const ok = { client_id: 'platform-cli', redirect_uri: 'http://127.0.0.1/callback', response_type: 'code', code_challenge: 'abc', code_challenge_method: 'S256' }
  const check = (over: Record<string, string>) => checkAuthorize(new URLSearchParams({ ...ok, ...over }), cfg)
  it('accepts the first-party code + PKCE flow', () => expect(check({})).toBeUndefined())
  it('rejects other clients, unregistered redirects, implicit flow, missing PKCE', () => {
    expect(check({ client_id: 'other' })).toBeDefined()
    expect(check({ redirect_uri: 'https://evil.example/' })).toBeDefined()
    expect(check({ redirect_uri: 'http://127.0.0.1/callback/../x' })).toBeDefined()
    expect(check({ response_type: 'token' })).toBeDefined()
    expect(check({ code_challenge_method: 'plain' })).toBeDefined()
    expect(check({ code_challenge: '' })).toBeDefined()
  })
})

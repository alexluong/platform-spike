// Stack g: stack c's app with OpenAuth (in the app) instead of Better Auth. SPEC §10, §11.
// Users: OpenAuth's password provider through the real OAuth flow, headless: GET /authorize (code +
// PKCE, first-party client) sets the encrypted `authorization` cookie, POST /password/authorize
// with the form answers a redirect carrying the code, POST /token exchanges it.
// Apps/agents: POST /token grant_type=client_credentials with `provider=client` (OpenAuth routes
// client_credentials to a provider by name). Only the app port (8093) is needed.
import { createHash, randomBytes } from 'node:crypto'
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

const baseUrl = process.env.APP_URL ?? `http://${env.host}:8093`
/** stacks/g/compose.yaml AUTH_CLIENT_ID / AUTH_REDIRECT_URIS */
const clientId = 'platform-cli'
const redirectUri = 'http://127.0.0.1/callback'

async function fail(what: string, res: Response): Promise<never> {
  throw new Error(`stack g ${what}: HTTP ${res.status} ${await res.text().catch(() => '')}`)
}

const b64url = (b: Buffer) => b.toString('base64url')

const driver: StackDriver = {
  baseUrl,
  async loginUser(email, password) {
    const verifier = b64url(randomBytes(32))
    const state = b64url(randomBytes(12))
    const q = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      provider: 'password',
      state,
      code_challenge: b64url(createHash('sha256').update(verifier).digest()),
      code_challenge_method: 'S256',
    })
    const start = await fetch(`${baseUrl}/authorize?${q}`, { redirect: 'manual' })
    if (start.status !== 302) return fail('authorize', start)
    const cookie = start.headers
      .getSetCookie()
      .map((c) => c.split(';')[0])
      .join('; ')
    if (!cookie) throw new Error('stack g authorize: no authorization cookie')

    const form = await fetch(`${baseUrl}/password/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ email, password }),
    })
    if (form.status !== 302) return fail('password', form)
    const back = new URL(form.headers.get('location') ?? '', baseUrl)
    const code = back.searchParams.get('code')
    if (!code || back.searchParams.get('state') !== state) throw new Error(`stack g password: unexpected redirect ${back}`)

    const tok = await fetch(`${baseUrl}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier }),
    })
    if (!tok.ok) return fail('token', tok)
    const body = (await tok.json()) as { access_token?: string }
    if (!body.access_token) throw new Error('stack g token: no access_token')
    return body.access_token
  },
  async loginClient(cid, secret) {
    const res = await fetch(`${baseUrl}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', provider: 'client', client_id: cid, client_secret: secret }),
    })
    if (!res.ok) return fail('client_credentials', res)
    const body = (await res.json()) as { access_token?: string }
    if (!body.access_token) throw new Error('stack g client_credentials: no access_token')
    return body.access_token
  },
}
export default driver

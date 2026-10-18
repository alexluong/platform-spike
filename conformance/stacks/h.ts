// Stack h: stack a's Go app with the OpenID provider inside it (zitadel/oidc pkg/op), users and
// clients in the app's Postgres. SPEC §10, §11. Only the app port (8094) is needed.
//
// loginUser: authorization code + PKCE (S256) with the first-party public client, headless:
//   1. GET  /oidc/authorize?…           → 302 to /login?id=<auth request>
//   2. POST /login (id, email, password) → 302 to the redirect URI with ?code=
//      (what a login page would post; the app's login step answers with the code itself:
//      the library's /authorize/callback?id= is closed, it gave the code to any holder of the id)
//   3. POST /oidc/oauth/token (code + verifier) → JWT access token for the API
// loginClient: client_credentials at /oidc/oauth/token (HTTP Basic).
import { createHash, randomBytes } from 'node:crypto'
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

const baseUrl = process.env.APP_URL ?? `http://${env.host}:8094`
/** stacks/h/compose.yaml LOGIN_CLIENT_ID / DRIVER_REDIRECT_URI */
const clientId = 'platform-cli'
const redirectUri = 'http://127.0.0.1/callback'

async function fail(what: string, res: Response): Promise<never> {
  throw new Error(`stack h ${what}: HTTP ${res.status} ${await res.text().catch(() => '')}`)
}

const b64url = (b: Buffer) => b.toString('base64url')
const get = (url: string | URL) => fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(env.requestTimeoutMs) })
const post = (url: string, body: URLSearchParams, headers: Record<string, string> = {}) =>
  fetch(url, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body,
    signal: AbortSignal.timeout(env.requestTimeoutMs),
  })

/** Follows one redirect: the Location, resolved against the app (the issuer's host is the app's). */
function location(res: Response): URL {
  return new URL(res.headers.get('location') ?? '', baseUrl)
}

const driver: StackDriver = {
  baseUrl,
  async loginUser(email, password) {
    const verifier = b64url(randomBytes(32))
    const state = b64url(randomBytes(12))
    const q = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid',
      state,
      code_challenge: b64url(createHash('sha256').update(verifier).digest()),
      code_challenge_method: 'S256',
    })
    const start = await get(`${baseUrl}/oidc/authorize?${q}`)
    if (start.status !== 302) return fail('authorize', start)
    const id = location(start).searchParams.get('id')
    if (!id) throw new Error(`stack h authorize: no auth request id in ${location(start)}`)

    const login = await post(`${baseUrl}/login`, new URLSearchParams({ id, email, password }))
    if (login.status !== 302) return fail('login', login)

    const back = new URL(login.headers.get('location') ?? '')
    const code = back.searchParams.get('code')
    if (!code || back.searchParams.get('state') !== state) throw new Error(`stack h login: unexpected redirect ${back}`)

    const tok = await post(
      `${baseUrl}/oidc/oauth/token`,
      new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier }),
    )
    if (!tok.ok) return fail('token', tok)
    const body = (await tok.json()) as { access_token?: string }
    if (!body.access_token) throw new Error('stack h token: no access_token')
    return body.access_token
  },
  async loginClient(cid, secret) {
    const basic = Buffer.from(`${encodeURIComponent(cid)}:${encodeURIComponent(secret)}`).toString('base64')
    const res = await post(`${baseUrl}/oidc/oauth/token`, new URLSearchParams({ grant_type: 'client_credentials' }), {
      authorization: `Basic ${basic}`,
    })
    if (!res.ok) return fail('client_credentials', res)
    const body = (await res.json()) as { access_token?: string }
    if (!body.access_token) throw new Error('stack h client_credentials: no access_token')
    return body.access_token
  },
}
export default driver

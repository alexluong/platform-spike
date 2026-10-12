// Stack a2: Go app (from a) + Zitadel with one organization per merchant + SpiceDB. SPEC §10, §15.
// STARTING POINT: a copy of stacks/a.ts with the ports changed (app 8088, Zitadel 8089). The stack's
// builder adjusts it to the real login path (e.g. org-scoped login, org scopes in the token request).
// features: ['idp-tenancy'] opts into tests/idp-tenancy.test.ts (SPEC §15.2, §15.3).
//
// loginUser: OIDC authorization code + PKCE, driven headless the way Zitadel's own
// Login v2 UI does it: /oauth/v2/authorize redirects to the (never served) login UI
// with an auth request id; the driver, holding the IAM_LOGIN_CLIENT token, creates a
// session with a password check (Session API v2) and finalizes the auth request
// (OIDC service v2), then exchanges the code at the token endpoint.
// loginClient: client_credentials at the token endpoint (machine users).
import { createHash, randomBytes } from 'node:crypto'
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App (SPEC table: port 8088). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8088`
/**
 * Zitadel, published by stacks/a2/compose.yaml on 8089. Zitadel resolves its instance
 * from the Host header, so by default the driver uses the issuer the app reports
 * (http://$STACK_A2_HOST:8089, default cs-ws.lab.alexluong.com). Override with A2_ZITADEL_URL.
 */
export const zitadelPort = 8089
export const zitadelUrlOverride = process.env.A2_ZITADEL_URL

interface DriverConfig {
  issuer: string
  clientId: string
  projectId: string
  redirectUri: string
  loginClientToken: string
}

let configPromise: Promise<DriverConfig> | undefined

/** IdP client ids and the login-client token, from the app's TEST_MODE endpoint (written by the stack bootstrap). */
function config(): Promise<DriverConfig> {
  configPromise ??= (async () => {
    const res = await fetch(`${baseUrl}/api/_test/driver-config`, {
      headers: { 'X-Test-Secret': env.testSecret },
      signal: AbortSignal.timeout(env.requestTimeoutMs),
    })
    if (!res.ok) throw new Error(`driver-config: ${res.status} ${await res.text()}`)
    return (await res.json()) as DriverConfig
  })()
  configPromise.catch(() => {
    configPromise = undefined
  })
  return configPromise
}

const b64url = (b: Buffer) => b.toString('base64url')

async function call(path: string, init: RequestInit & { token?: string; json?: unknown } = {}): Promise<Response> {
  const headers = new Headers(init.headers)
  if (init.token) headers.set('Authorization', `Bearer ${init.token}`)
  if (init.json !== undefined) headers.set('Content-Type', 'application/json')
  const base = zitadelUrlOverride ?? (await config()).issuer
  return fetch(`${base}${path}`, {
    ...init,
    headers,
    body: init.json !== undefined ? JSON.stringify(init.json) : init.body,
    signal: AbortSignal.timeout(env.requestTimeoutMs),
  })
}

async function jsonOrThrow<T>(res: Response, what: string): Promise<T> {
  const text = await res.text()
  if (!res.ok) throw new Error(`zitadel ${what}: ${res.status} ${text}`)
  return JSON.parse(text) as T
}

function scope(cfg: DriverConfig, base: string): string {
  // The project audience scope puts the project id in `aud`; the app requires it.
  return `${base} urn:zitadel:iam:org:project:id:${cfg.projectId}:aud`
}

const driver: StackDriver = {
  baseUrl,
  features: ['idp-tenancy'],

  async loginUser(email, password) {
    const cfg = await config()
    const verifier = b64url(randomBytes(32))
    const challenge = b64url(createHash('sha256').update(verifier).digest())
    const state = b64url(randomBytes(12))

    // 1. Authorization request → redirect to the login UI carrying the auth request id.
    const q = new URLSearchParams({
      client_id: cfg.clientId,
      redirect_uri: cfg.redirectUri,
      response_type: 'code',
      scope: scope(cfg, 'openid profile email'),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    })
    const auth = await call(`/oauth/v2/authorize?${q}`, { redirect: 'manual' })
    const location = auth.headers.get('location')
    if (auth.status < 300 || auth.status >= 400 || !location) {
      throw new Error(`zitadel authorize: expected redirect, got ${auth.status} ${await auth.text()}`)
    }
    const authRequestId = new URL(location, zitadelUrlOverride ?? cfg.issuer).searchParams.get('authRequest')
    if (!authRequestId) throw new Error(`zitadel authorize: no authRequest in ${location}`)

    // 2. Session with user + password checks (what the login UI does).
    const session = await jsonOrThrow<{ sessionId: string; sessionToken: string }>(
      await call('/v2/sessions', {
        method: 'POST',
        token: cfg.loginClientToken,
        json: { checks: { user: { loginName: email }, password: { password } } },
      }),
      'create session',
    )

    // 3. Finalize the auth request with the session → callback URL with the code.
    const cb = await jsonOrThrow<{ callbackUrl: string }>(
      await call(`/v2/oidc/auth_requests/${authRequestId}`, {
        method: 'POST',
        token: cfg.loginClientToken,
        json: { session: { sessionId: session.sessionId, sessionToken: session.sessionToken } },
      }),
      'finalize auth request',
    )
    const callback = new URL(cb.callbackUrl)
    const code = callback.searchParams.get('code')
    if (!code || callback.searchParams.get('state') !== state) throw new Error(`zitadel callback: bad ${cb.callbackUrl}`)

    // 4. Code + PKCE verifier → tokens.
    const tok = await jsonOrThrow<{ access_token: string }>(
      await call('/oauth/v2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: cfg.redirectUri,
          client_id: cfg.clientId,
          code_verifier: verifier,
        }),
      }),
      'token (authorization_code)',
    )
    return tok.access_token
  },

  async loginClient(clientId, clientSecret) {
    const cfg = await config()
    const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64')
    // Zitadel is eventually consistent: a secret added a moment ago can read as
    // "Secret.NotExisting" (or the machine user as "client not found") until its projection catches up, so retry briefly.
    for (let attempt = 0; ; attempt++) {
      const res = await call('/oauth/v2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` },
        body: new URLSearchParams({ grant_type: 'client_credentials', scope: scope(cfg, 'openid') }),
      })
      if (res.status === 400 && attempt < 20) {
        const text = await res.clone().text()
        if (text.includes('NotExisting') || text.includes('NotFound') || text.includes('client not found')) {
          await new Promise((r) => setTimeout(r, 250))
          continue
        }
      }
      const tok = await jsonOrThrow<{ access_token: string }>(res, 'token (client_credentials)')
      return tok.access_token
    }
  },
}
export default driver

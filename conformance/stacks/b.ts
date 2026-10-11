// Stack b: Go app + Ory Kratos + Hydra (OIDC) + OpenFGA. SPEC §10, §11.
//
// loginUser: OAuth2 authorization code + PKCE at Hydra, with the login UI replaced by the driver:
//   1. GET  Hydra /oauth2/auth → 302 to the (never served) login UI with a login_challenge (+ CSRF cookie)
//   2. Kratos native (API) login flow: GET /self-service/login/api, POST /self-service/login?flow=
//      with the password → session (identity id)
//   3. PUT  Hydra admin /admin/oauth2/auth/requests/login/accept {subject: identity id} → redirect_to
//   4. GET  redirect_to (cookies) → 302 to the consent UI with a consent_challenge
//   5. PUT  Hydra admin /admin/oauth2/auth/requests/consent/accept {grant_scope, grant_access_token_audience}
//   6. GET  redirect_to (cookies) → 302 to redirect_uri?code=…
//   7. POST Hydra /oauth2/token (code + PKCE verifier) → JWT access token
// loginClient: client_credentials at Hydra /oauth2/token with the API audience.
import { createHash, randomBytes } from 'node:crypto'
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App (SPEC table: port 8082). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8082`
/** Published by stacks/b/compose.yaml. Hydra's issuer is http://$STACK_B_HOST:4444 (HOST must match it). */
export const kratosPublicUrl = process.env.KRATOS_PUBLIC_URL ?? `http://${env.host}:4433`
export const hydraPublicUrl = process.env.HYDRA_PUBLIC_URL ?? `http://${env.host}:4444`
export const hydraAdminUrl = process.env.HYDRA_ADMIN_URL ?? `http://${env.host}:4445`

interface DriverConfig {
  issuer: string
  clientId: string
  redirectUri: string
  audience: string
}

let configPromise: Promise<DriverConfig> | undefined

/** Hydra client id, redirect URI and API audience, from the app's TEST_MODE endpoint (written by the stack bootstrap). */
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

/** Minimal cookie jar: Hydra ties the login and consent steps to CSRF cookies set on its public URL. */
class Jar {
  private cookies = new Map<string, string>()
  store(res: Response) {
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(';')
      const i = pair.indexOf('=')
      if (i > 0) this.cookies.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim())
    }
  }
  header(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ')
  }
}

async function http(url: string, init: RequestInit & { json?: unknown } = {}): Promise<Response> {
  const headers = new Headers(init.headers)
  if (init.json !== undefined) headers.set('Content-Type', 'application/json')
  headers.set('Accept', 'application/json')
  return fetch(url, {
    ...init,
    headers,
    body: init.json !== undefined ? JSON.stringify(init.json) : init.body,
    redirect: 'manual',
    signal: AbortSignal.timeout(env.requestTimeoutMs),
  })
}

async function jsonOrThrow<T>(res: Response, what: string): Promise<T> {
  const text = await res.text()
  if (!res.ok) throw new Error(`ory ${what}: ${res.status} ${text}`)
  return JSON.parse(text) as T
}

/** GET a Hydra URL with the jar's cookies and return the redirect target. */
async function follow(url: string, jar: Jar, what: string): Promise<URL> {
  const res = await http(url, { headers: { Cookie: jar.header() } })
  jar.store(res)
  const location = res.headers.get('location')
  if (res.status < 300 || res.status >= 400 || !location) {
    throw new Error(`hydra ${what}: expected redirect, got ${res.status} ${await res.text()}`)
  }
  return new URL(location, url)
}

/** Kratos native login: returns the identity id (what a login UI would hand to Hydra as the subject). */
async function kratosLogin(email: string, password: string): Promise<string> {
  const flow = await jsonOrThrow<{ id: string }>(await http(`${kratosPublicUrl}/self-service/login/api`), 'create login flow')
  const res = await http(`${kratosPublicUrl}/self-service/login?flow=${encodeURIComponent(flow.id)}`, {
    method: 'POST',
    json: { method: 'password', identifier: email, password },
  })
  const out = await jsonOrThrow<{ session_token: string; session: { identity: { id: string } } }>(res, 'login')
  return out.session.identity.id
}

const driver: StackDriver = {
  baseUrl,

  async loginUser(email, password) {
    const cfg = await config()
    const jar = new Jar()
    const verifier = b64url(randomBytes(32))
    const challenge = b64url(createHash('sha256').update(verifier).digest())
    const state = b64url(randomBytes(12))

    // 1. Authorization request → login UI with login_challenge.
    const q = new URLSearchParams({
      client_id: cfg.clientId,
      redirect_uri: cfg.redirectUri,
      response_type: 'code',
      scope: 'openid',
      audience: cfg.audience,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    })
    const toLogin = await follow(`${hydraPublicUrl}/oauth2/auth?${q}`, jar, 'authorize')
    const loginChallenge = toLogin.searchParams.get('login_challenge')
    if (!loginChallenge) throw new Error(`hydra authorize: no login_challenge in ${toLogin}`)

    // 2. Authenticate the user at Kratos (what the login UI does).
    const subject = await kratosLogin(email, password)

    // 3. Accept the login request with the Kratos identity as subject.
    const login = await jsonOrThrow<{ redirect_to: string }>(
      await http(`${hydraAdminUrl}/admin/oauth2/auth/requests/login/accept?login_challenge=${encodeURIComponent(loginChallenge)}`, {
        method: 'PUT',
        json: { subject, remember: false },
      }),
      'accept login',
    )

    // 4. Back to Hydra → consent UI with consent_challenge.
    const toConsent = await follow(login.redirect_to, jar, 'login verifier')
    const consentChallenge = toConsent.searchParams.get('consent_challenge')
    if (!consentChallenge) throw new Error(`hydra: no consent_challenge in ${toConsent}`)

    // 5. Accept consent: grant the scope and the API audience.
    const consent = await jsonOrThrow<{ redirect_to: string }>(
      await http(`${hydraAdminUrl}/admin/oauth2/auth/requests/consent/accept?consent_challenge=${encodeURIComponent(consentChallenge)}`, {
        method: 'PUT',
        json: { grant_scope: ['openid'], grant_access_token_audience: [cfg.audience], remember: false },
      }),
      'accept consent',
    )

    // 6. Back to Hydra → redirect_uri with the code.
    const callback = await follow(consent.redirect_to, jar, 'consent verifier')
    const code = callback.searchParams.get('code')
    if (!code || callback.searchParams.get('state') !== state) throw new Error(`hydra callback: bad ${callback}`)

    // 7. Code + PKCE verifier → tokens.
    const tok = await jsonOrThrow<{ access_token: string }>(
      await http(`${hydraPublicUrl}/oauth2/token`, {
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
    const tok = await jsonOrThrow<{ access_token: string }>(
      await http(`${hydraPublicUrl}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` },
        body: new URLSearchParams({ grant_type: 'client_credentials', audience: cfg.audience }),
      }),
      'token (client_credentials)',
    )
    return tok.access_token
  },
}
export default driver

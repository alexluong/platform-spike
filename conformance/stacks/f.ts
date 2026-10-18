// Stack f: Go app (stack a's) + Logto (OIDC) + SpiceDB. SPEC §10, §11.
//
// loginUser: OIDC authorization code + PKCE with a resource indicator, the sign-in page replaced by
// Logto's Experience API (what Logto's own sign-in UI calls), all on Logto's public endpoint:
//   1. GET  /oidc/auth?…&resource=<api> → 303 to the sign-in page (+ interaction cookies)
//   2. PUT  /api/experience {interactionEvent: SignIn}
//   3. POST /api/experience/verification/password {identifier: {type: email}, password} → verificationId
//   4. POST /api/experience/identification {verificationId}
//   5. POST /api/experience/submit → redirectTo (/oidc/auth/<uid>)
//   6. follow redirects (auto-consent for first-party apps) → redirect_uri?code=…
//   7. POST /oidc/token (code + PKCE verifier + resource) → JWT access token for the API
// loginClient: client_credentials at /oidc/token with the API resource.
import { createHash, randomBytes } from 'node:crypto'
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App (SPEC table: port 8091). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8091`

interface DriverConfig {
  endpoint: string // Logto's public edge (http://$STACK_F_HOST:8092), from the app's TEST_MODE endpoint
  clientId: string
  redirectUri: string
  resource: string
}

let configPromise: Promise<DriverConfig> | undefined

function config(): Promise<DriverConfig> {
  configPromise ??= (async () => {
    const res = await fetch(`${baseUrl}/api/_test/driver-config`, {
      headers: { 'X-Test-Secret': env.testSecret },
      signal: AbortSignal.timeout(env.requestTimeoutMs),
    })
    if (!res.ok) throw new Error(`driver-config: ${res.status} ${await res.text()}`)
    const cfg = (await res.json()) as DriverConfig
    if (process.env.LOGTO_URL) cfg.endpoint = process.env.LOGTO_URL
    return cfg
  })()
  configPromise.catch(() => {
    configPromise = undefined
  })
  return configPromise
}

const b64url = (b: Buffer) => b.toString('base64url')

/** Cookie jar: Logto ties the OIDC interaction to signed cookies (all on path /). */
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

async function http(url: string, jar: Jar, init: RequestInit & { json?: unknown } = {}): Promise<Response> {
  const headers = new Headers(init.headers)
  if (init.json !== undefined) headers.set('Content-Type', 'application/json')
  headers.set('Cookie', jar.header())
  const res = await fetch(url, {
    ...init,
    headers,
    body: init.json !== undefined ? JSON.stringify(init.json) : init.body,
    redirect: 'manual',
    signal: AbortSignal.timeout(env.requestTimeoutMs),
  })
  jar.store(res)
  return res
}

async function okOrThrow(res: Response, what: string): Promise<string> {
  const text = await res.text()
  if (!res.ok) throw new Error(`logto ${what}: ${res.status} ${text}`)
  return text
}

/**
 * The whole user login; returns Logto's token response. `clientId` and `resource` override the
 * driver app and the API resource (`null`: no resource, i.e. an opaque access token), for
 * negative token checks.
 */
export async function logtoLogin(
  email: string,
  password: string,
  opts: { clientId?: string; resource?: string | null } = {},
): Promise<{ access_token: string; id_token?: string }> {
  const base = await config()
  const cfg = { ...base, clientId: opts.clientId ?? base.clientId }
  const resource = opts.resource === undefined ? base.resource : opts.resource
  const jar = new Jar()
  const verifier = b64url(randomBytes(32))
  const challenge = b64url(createHash('sha256').update(verifier).digest())
  const state = b64url(randomBytes(12))

  // 1. Authorization request → sign-in page.
  const q = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    response_type: 'code',
    scope: 'openid',
    resource: resource ?? '',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    prompt: 'login',
  })
  if (resource === null) q.delete('resource')
  const auth = await http(`${cfg.endpoint}/oidc/auth?${q}`, jar)
  if (auth.status !== 303) throw new Error(`logto authorize: expected 303, got ${auth.status} ${await auth.text()}`)

  // 2–5. What the sign-in page does.
  const api = (path: string, json?: unknown, method = 'POST') => http(`${cfg.endpoint}/api/experience${path}`, jar, { method, json })
  await okOrThrow(await api('', { interactionEvent: 'SignIn' }, 'PUT'), 'start interaction')
  const { verificationId } = JSON.parse(
    await okOrThrow(await api('/verification/password', { identifier: { type: 'email', value: email }, password }), 'verify password'),
  ) as { verificationId: string }
  await okOrThrow(await api('/identification', { verificationId }), 'identify')
  const { redirectTo } = JSON.parse(await okOrThrow(await api('/submit'), 'submit')) as { redirectTo: string }

  // 6. Back to the provider until it redirects to the client with the code.
  let next = new URL(redirectTo, cfg.endpoint)
  for (let hop = 0; !next.href.startsWith(cfg.redirectUri); hop++) {
    if (hop > 6) throw new Error(`logto: too many redirects (at ${next})`)
    const res = await http(next.href, jar)
    const location = res.headers.get('location')
    if (res.status < 300 || res.status >= 400 || !location) {
      throw new Error(`logto ${next.pathname}: expected redirect, got ${res.status} ${await res.text()}`)
    }
    next = new URL(location, cfg.endpoint)
  }
  const code = next.searchParams.get('code')
  if (!code || next.searchParams.get('state') !== state) throw new Error(`logto callback: bad ${next}`)

  // 7. Code + PKCE verifier → JWT access token for the API resource.
  const tok = JSON.parse(
    await okOrThrow(
      await http(`${cfg.endpoint}/oidc/token`, jar, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: cfg.redirectUri,
          client_id: cfg.clientId,
          code_verifier: verifier,
          ...(resource === null ? {} : { resource }),
        }),
      }),
      'token (authorization_code)',
    ),
  ) as { access_token: string; id_token?: string }
  return tok
}

const driver: StackDriver = {
  baseUrl,

  async loginUser(email, password) {
    return (await logtoLogin(email, password)).access_token
  },

  async loginClient(clientId, clientSecret) {
    const cfg = await config()
    const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64')
    const res = await fetch(`${cfg.endpoint}/oidc/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` },
      body: new URLSearchParams({ grant_type: 'client_credentials', resource: cfg.resource }),
      signal: AbortSignal.timeout(env.requestTimeoutMs),
    })
    const tok = JSON.parse(await okOrThrow(res, 'token (client_credentials)')) as { access_token: string }
    return tok.access_token
  },
}
export default driver

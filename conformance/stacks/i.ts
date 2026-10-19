// Stack i: stack a's Go app + Zitadel with one instance per merchant on one deployment + SpiceDB.
// SPEC §10, §16. features: ['multi-pool'] opts into tests/multi-pool.test.ts (SPEC §16.6).
//
// Pools: workforce instance (platform staff), platform instance with orgs `accounts` (merchant
// owners, staff and partners) and `shop` (Shop buyers), one instance per merchant with org
// `customers` (SPEC v4.1: tenant pools hold customers only). The driver never talks to Zitadel directly: the app is the gateway. Every pool has
// its own host, http://<label>.<ID_DOMAIN>:8096 (default ID_DOMAIN cs.internal: gw DNS → cs-ws),
// which is also its issuer; the app maps the host to the instance (x-zitadel-instance-host).
// On those hosts /oauth/v2/* etc. reach Zitadel, and /ui/v2/login/* is the app's headless
// stand-in for Zitadel's Login UI v2 (JSON instead of HTML). The driver plays the browser:
//   authorize → 302 to /ui/v2/login/login?authRequest=… → POST password (or idp) → callback URL →
//   code + PKCE at the token endpoint.
// Which pool: platform-level logins ask the app's test-mode home realm (kinds holding the email)
// and take the targets from /api/_test/driver-config; tenant logins read
// GET /api/merchants/:mid/identity (issuer, client, orgs).
import { createHash, randomBytes } from 'node:crypto'
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App (SPEC §16 table: port 8096). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8096`

interface Target {
  issuer: string
  clientId: string
  projectId: string
  orgId: string
}
interface DriverConfig {
  redirectUri: string
  platform: Target
  user: Target
  customer: Target
}

let configPromise: Promise<DriverConfig> | undefined
function config(): Promise<DriverConfig> {
  configPromise ??= (async () => {
    const res = await get(`${baseUrl}/api/_test/driver-config`, { 'X-Test-Secret': env.testSecret })
    if (!res.ok) throw new Error(`driver-config: ${res.status} ${await res.text()}`)
    return (await res.json()) as DriverConfig
  })()
  configPromise.catch(() => {
    configPromise = undefined
  })
  return configPromise
}

const b64url = (b: Buffer) => b.toString('base64url')

function get(url: string, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(url, { headers, redirect: 'manual', signal: AbortSignal.timeout(env.requestTimeoutMs) })
}

function post(url: string, body: unknown): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(env.requestTimeoutMs),
  })
}

async function jsonOrThrow<T>(res: Response, what: string): Promise<T> {
  const text = await res.text()
  if (!res.ok) throw new Error(`${what}: ${res.status} ${text}`)
  return JSON.parse(text) as T
}

function redirectOf(res: Response, base: string, what: string): URL {
  const loc = res.headers.get('location')
  if (res.status < 300 || res.status >= 400 || !loc) throw new Error(`${what}: expected a redirect, got ${res.status}`)
  return new URL(loc, base)
}

interface Started {
  authRequest: string
  verifier: string
  state: string
  target: Target
}

/** Authorization request at a pool (scoped to one org) → the login UI's auth request id. */
async function authorize(target: Target, redirectUri: string): Promise<Started> {
  const verifier = b64url(randomBytes(32))
  const state = b64url(randomBytes(12))
  const q = new URLSearchParams({
    client_id: target.clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    // project audience (the app requires it) + the org: Zitadel refuses a session of another org
    scope: `openid profile email urn:zitadel:iam:org:project:id:${target.projectId}:aud urn:zitadel:iam:org:id:${target.orgId}`,
    code_challenge: b64url(createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
    state,
  })
  const res = await get(`${target.issuer}/oauth/v2/authorize?${q}`)
  const login = redirectOf(res, target.issuer, `authorize at ${target.issuer}`)
  const authRequest = login.searchParams.get('authRequest')
  if (!authRequest) throw new Error(`authorize: no authRequest in ${login}`)
  return { authRequest, verifier, state, target }
}

/** Callback URL → code → access token at the pool's token endpoint. */
async function redeem(s: Started, callbackUrl: string, redirectUri: string): Promise<string> {
  const cb = new URL(callbackUrl)
  const code = cb.searchParams.get('code')
  if (!code || cb.searchParams.get('state') !== s.state) throw new Error(`callback: bad ${callbackUrl}`)
  const res = await fetch(`${s.target.issuer}/oauth/v2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: s.target.clientId, code_verifier: s.verifier }),
    signal: AbortSignal.timeout(env.requestTimeoutMs),
  })
  return (await jsonOrThrow<{ access_token: string }>(res, `token at ${s.target.issuer}`)).access_token
}

/**
 * Zitadel reads the user from a projection when it issues the token: right after the user was
 * created the token request can fail with 404 User.NotFound, and the code is spent. A person
 * would just try again; so does the driver (whole flow, a few times).
 */
async function retryFresh<T>(f: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await f()
    } catch (e) {
      if (attempt >= 4 || !/User\.NotFound|AuthRequest\.NoCode/.test(String(e))) throw e
      await new Promise((r) => setTimeout(r, 300 * (attempt + 1)))
    }
  }
}

function passwordLogin(target: Target, redirectUri: string, email: string, password: string): Promise<string> {
  return retryFresh(() => passwordLoginOnce(target, redirectUri, email, password))
}

async function passwordLoginOnce(target: Target, redirectUri: string, email: string, password: string): Promise<string> {
  const s = await authorize(target, redirectUri)
  const { callbackUrl } = await jsonOrThrow<{ callbackUrl: string }>(
    await post(`${target.issuer}/ui/v2/login/password`, { authRequest: s.authRequest, loginName: email, password }),
    `login at ${target.issuer}`,
  )
  return redeem(s, callbackUrl, redirectUri)
}

interface PoolIdentity {
  issuer: string
  clientId: string
  projectId: string
  orgs: Record<string, string>
  status: string
}

async function tenant(merchantId: string): Promise<Target> {
  const id = await jsonOrThrow<PoolIdentity>(await get(`${baseUrl}/api/merchants/${encodeURIComponent(merchantId)}/identity`), 'identity')
  if (id.status !== 'active' || !id.orgs.customers) throw new Error(`merchant ${merchantId}: pool ${id.status}`)
  return { issuer: id.issuer.replace(/\/$/, ''), clientId: id.clientId, projectId: id.projectId, orgId: id.orgs.customers }
}

const driver: StackDriver = {
  baseUrl,
  features: ['multi-pool'],

  async loginUser(email, password) {
    const cfg = await config()
    const realm = await jsonOrThrow<{ kinds: string[] }>(
      await get(`${baseUrl}/api/_test/home-realm?${new URLSearchParams({ email })}`, { 'X-Test-Secret': env.testSecret }),
      'home realm',
    )
    if (realm.kinds.length === 0) throw new Error(`no platform-level account for ${email}`)
    let last: unknown
    for (const kind of realm.kinds) {
      try {
        return await passwordLogin(cfg[kind as keyof Omit<DriverConfig, 'redirectUri'>], cfg.redirectUri, email, password)
      } catch (e) {
        last = e
      }
    }
    throw last
  },

  async loginClient(clientId, clientSecret) {
    const cfg = await config()
    const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64')
    // Machine users live in the platform instance. Zitadel is eventually consistent: a fresh
    // secret can read as NotExisting for a moment.
    for (let attempt = 0; ; attempt++) {
      const res = await fetch(`${cfg.user.issuer}/oauth/v2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` },
        body: new URLSearchParams({ grant_type: 'client_credentials', scope: `openid urn:zitadel:iam:org:project:id:${cfg.user.projectId}:aud` }),
        signal: AbortSignal.timeout(env.requestTimeoutMs),
      })
      if ((res.status === 400 || res.status === 401) && attempt < 40) {
        const text = await res.clone().text()
        if (text.includes('NotExisting') || text.includes('NotFound') || text.includes('client not found')) {
          await new Promise((r) => setTimeout(r, 250))
          continue
        }
      }
      return (await jsonOrThrow<{ access_token: string }>(res, 'token (client_credentials)')).access_token
    }
  },

  async loginTenant(merchantId, email, password) {
    const cfg = await config()
    return passwordLogin(await tenant(merchantId), cfg.redirectUri, email, password)
  },

  loginWithShop(merchantId, shopEmail, shopPassword) {
    return retryFresh(() => shopLoginOnce(merchantId, shopEmail, shopPassword))
  },
}

async function shopLoginOnce(merchantId: string, shopEmail: string, shopPassword: string): Promise<string> {
  {
    const cfg = await config()
    const t = await tenant(merchantId)
    const s = await authorize(t, cfg.redirectUri)
    // 1. The merchant pool's login UI starts the Shop IdP intent → platform instance authorize URL.
    const { authUrl } = await jsonOrThrow<{ authUrl: string }>(await post(`${t.issuer}/ui/v2/login/idp`, { authRequest: s.authRequest }), 'start Sign in with Shop')
    const upstream = new URL(authUrl)
    const platformIssuer = upstream.origin
    // 2. Platform instance: authorize → its login UI → password as the Shop buyer → callback URL
    //    (the merchant instance's /idps/callback).
    const plogin = redirectOf(await get(authUrl), platformIssuer, 'Shop authorize')
    const pRequest = plogin.searchParams.get('authRequest')
    if (!pRequest) throw new Error(`Shop authorize: no authRequest in ${plogin}`)
    const { callbackUrl: idpCallback } = await jsonOrThrow<{ callbackUrl: string }>(
      await post(`${platformIssuer}/ui/v2/login/password`, { authRequest: pRequest, loginName: shopEmail, password: shopPassword }),
      'Shop login',
    )
    // 3. Back at the merchant instance: it redeems the upstream code, then sends the browser to
    //    the intent's success URL on its login UI, which finishes the merchant-pool login.
    const done = redirectOf(await get(idpCallback), t.issuer, 'IdP callback')
    if (done.pathname.endsWith('/idp/failed')) throw new Error(`Sign in with Shop failed: ${done}`)
    const { callbackUrl } = await jsonOrThrow<{ callbackUrl: string }>(await get(done.toString()), 'finish Sign in with Shop')
    return redeem(s, callbackUrl, cfg.redirectUri)
  }
}
export default driver

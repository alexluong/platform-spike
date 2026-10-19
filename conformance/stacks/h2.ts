// Stack h2: stack h's Go app with the in-app OpenID provider (zitadel/oidc pkg/op), pools as rows,
// one issuer per pool at /oidc/<pool>. SPEC §10, §16. Only the app port (8098) is needed.
//
// Every login is stack h's flow at a pool's issuer (authorize → POST <issuer>/login → code →
// token, PKCE S256):
// - loginUser: the core suite gives no pool, so the driver asks test support which platform-level
//   kind (platform → workforce, user → platform, customer → shop) holds the email
//   (GET /api/_test/home-realm). A real UI knows
//   its pool (staff console, merchant admin, Shop app).
// - loginTenant: the merchant's issuer from GET /api/merchants/:mid/identity; staff log in through
//   the `merchant-admin` client, customers through `storefront` (one pool, two user groups).
// - loginWithShop: storefront authorize at the tenant issuer → <issuer>/login/shop (the "Sign in
//   with Shop" button, sets a binding cookie) → 302 to the shop pool's authorize → POST the shop
//   login → 302 to <tenant issuer>/federation/shop/callback (with the cookie) → the app exchanges the
//   shop code over HTTP and answers with the tenant code → token at the tenant issuer.
// - loginClient: client_credentials at the platform pool (apps and agents live there).
import { createHash, randomBytes } from 'node:crypto'
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

const baseUrl = process.env.APP_URL ?? `http://${env.host}:8098`
/** stacks/h2/compose.yaml LOGIN_CLIENT_ID / STAFF_CLIENT_ID / CUSTOMER_CLIENT_ID / DRIVER_REDIRECT_URI */
const clients = { platform: 'platform-cli', user: 'merchant-admin', customer: 'storefront' } as const
const redirectUri = 'http://127.0.0.1/callback'

async function fail(what: string, res: Response): Promise<never> {
  throw new Error(`stack h2 ${what}: HTTP ${res.status} ${(await res.text().catch(() => '')).slice(0, 300)}`)
}

const b64url = (b: Buffer) => b.toString('base64url')
const get = (url: string | URL, headers: Record<string, string> = {}) =>
  fetch(url, { redirect: 'manual', headers, signal: AbortSignal.timeout(env.requestTimeoutMs) })
const post = (url: string, body: URLSearchParams, headers: Record<string, string> = {}) =>
  fetch(url, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body,
    signal: AbortSignal.timeout(env.requestTimeoutMs),
  })

/** The issuer is the app's host, so relative redirects resolve against the app. */
const location = (res: Response) => new URL(res.headers.get('location') ?? '', baseUrl)

/** Issuer URLs carry the configured public host; the driver may reach the app under another name. */
function onApp(url: string | URL): URL {
  const u = new URL(url)
  const b = new URL(baseUrl)
  u.protocol = b.protocol
  u.host = b.host
  return u
}

async function issuerOfMerchant(merchantId: string): Promise<string> {
  const res = await get(`${baseUrl}/api/merchants/${merchantId}/identity`)
  if (!res.ok) return fail('identity', res)
  return ((await res.json()) as { issuer: string }).issuer
}

let base: Promise<string> | undefined
/** PUBLIC_URL/oidc/ from test-mode driver config; a pool's issuer is base + pool id. */
function issuerBase(): Promise<string> {
  base ??= (async () => {
    const res = await get(`${baseUrl}/api/_test/driver-config`, { 'x-test-secret': env.testSecret })
    if (!res.ok) return fail('driver-config', res)
    return ((await res.json()) as { issuerBase: string }).issuerBase
  })()
  return base
}

/** platform-level kind → its pool (stack h2's pool ids). */
const poolOfKind: Record<string, string> = { platform: 'workforce', user: 'platform', customer: 'shop' }

async function issuerOfEmail(email: string): Promise<string> {
  const res = await get(`${baseUrl}/api/_test/home-realm?email=${encodeURIComponent(email)}`, { 'x-test-secret': env.testSecret })
  if (!res.ok) return fail('home-realm', res)
  const { kinds } = (await res.json()) as { kinds: string[] }
  const pool = poolOfKind[kinds[0] ?? '']
  if (!pool) throw new Error(`stack h2: no platform-level account for ${email}`)
  return `${await issuerBase()}${pool}`
}

/** authorize at `issuer` → the auth request id and what the token exchange needs. */
async function authorize(issuer: string, clientId: string) {
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
  const start = await get(onApp(`${issuer}/authorize?${q}`))
  if (start.status !== 302) return fail('authorize', start)
  const id = location(start).searchParams.get('id')
  if (!id) throw new Error(`stack h2 authorize: no auth request id in ${location(start)}`)
  return { id, verifier, state, clientId, issuer }
}

/** The login step answered with a 302 to the redirect URI: take the code, exchange it. */
async function finish(a: { verifier: string; state: string; clientId: string; issuer: string }, res: Response): Promise<string> {
  if (res.status !== 302) return fail('login', res)
  const back = new URL(res.headers.get('location') ?? '')
  const code = back.searchParams.get('code')
  if (!code || back.searchParams.get('state') !== a.state || !back.href.startsWith(redirectUri)) {
    throw new Error(`stack h2 login: unexpected redirect ${back}`)
  }
  const tok = await post(
    onApp(`${a.issuer}/oauth/token`).href,
    new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: a.clientId, code_verifier: a.verifier }),
  )
  if (!tok.ok) return fail('token', tok)
  const body = (await tok.json()) as { access_token?: string }
  if (!body.access_token) throw new Error('stack h2 token: no access_token')
  return body.access_token
}

async function passwordLogin(issuer: string, clientId: string, email: string, password: string): Promise<string> {
  const a = await authorize(issuer, clientId)
  return finish(a, await post(onApp(`${issuer}/login`).href, new URLSearchParams({ id: a.id, email, password })))
}

const driver: StackDriver = {
  baseUrl,
  features: ['multi-pool'],
  async loginUser(email, password) {
    return passwordLogin(await issuerOfEmail(email), clients.platform, email, password)
  },
  async loginClient(cid, secret) {
    const basic = Buffer.from(`${encodeURIComponent(cid)}:${encodeURIComponent(secret)}`).toString('base64')
    const res = await post(`${baseUrl}/oidc/platform/oauth/token`, new URLSearchParams({ grant_type: 'client_credentials' }), {
      authorization: `Basic ${basic}`,
    })
    if (!res.ok) return fail('client_credentials', res)
    const body = (await res.json()) as { access_token?: string }
    if (!body.access_token) throw new Error('stack h2 client_credentials: no access_token')
    return body.access_token
  },
  async loginTenant(merchantId, kind, email, password) {
    return passwordLogin(await issuerOfMerchant(merchantId), clients[kind], email, password)
  },
  async loginWithShop(merchantId, shopEmail, shopPassword) {
    const issuer = await issuerOfMerchant(merchantId)
    const a = await authorize(issuer, clients.customer)
    // "Sign in with Shop" on the tenant login page: binding cookie + redirect to the shop pool.
    const start = await get(onApp(`${issuer}/login/shop?id=${encodeURIComponent(a.id)}`))
    if (start.status !== 302) return fail('login/shop', start)
    const cookie = (start.headers.get('set-cookie') ?? '').split(';')[0]
    if (!cookie) throw new Error('stack h2 login/shop: no binding cookie')
    // The shop pool: authorize → its login step → 302 back to the tenant pool's callback.
    const shopAuth = await get(onApp(location(start)))
    if (shopAuth.status !== 302) return fail('shop authorize', shopAuth)
    const shopReq = location(shopAuth).searchParams.get('id')
    if (!shopReq) throw new Error(`stack h2 shop authorize: no auth request id in ${location(shopAuth)}`)
    const shopLogin = await post(onApp(location(shopAuth).origin + location(shopAuth).pathname).href, new URLSearchParams({ id: shopReq, email: shopEmail, password: shopPassword }))
    if (shopLogin.status !== 302) return fail('shop login', shopLogin)
    // Back at the tenant pool: it exchanges the shop code itself and answers with the tenant code.
    const callback = await get(onApp(location(shopLogin)), { cookie })
    return finish(a, callback)
  },
}
export default driver

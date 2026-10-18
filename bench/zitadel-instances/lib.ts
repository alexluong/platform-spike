// Shared helpers for the Zitadel instances probes and bench (round 4, TASK-62).
// Plain Node 24 (type stripping), no dependencies:  mise exec -- node bench/zitadel-instances/<script>.ts
// Env: ZBENCH_URL (default http://cs-ws.lab.alexluong.com:8099) = where requests go (TCP);
//      ZBENCH_AUD   = audience for System API JWTs (default = ZBENCH_URL; must be the default instance's issuer).
import { createHash, createSign, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const here = dirname(fileURLToPath(import.meta.url))
export const BASE = process.env.ZBENCH_URL ?? 'http://cs-ws.lab.alexluong.com:8099'
const AUD = process.env.ZBENCH_AUD ?? 'http://cs-ws.lab.alexluong.com:8099'
export const PASSWORD = 'Password1!-zbench'

const b64u = (b: Buffer | string) => Buffer.from(b).toString('base64url')
let sysKey: string | undefined
const sysToks: Record<string, { jwt: string; exp: number }> = {}

/** JWT-profile bearer for a System API user: iss = sub = the SystemAPIUsers key name, signed RS256.
 *  zbench = SYSTEM_OWNER; zlogin = IAM_LOGIN_CLIENT on all instances (compose.yaml). */
export function systemToken(user = 'zbench'): string {
  const now = Math.floor(Date.now() / 1000)
  const cached = sysToks[user]
  if (cached && cached.exp - 60 > now) return cached.jwt
  sysKey ??= readFileSync(join(here, '.keys/system.pem'), 'utf8')
  const head = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
  const exp = now + 3600
  const body = b64u(JSON.stringify({ iss: user, sub: user, aud: AUD, iat: now, exp }))
  const sig = createSign('RSA-SHA256').update(`${head}.${body}`).sign(sysKey)
  sysToks[user] = { jwt: `${head}.${body}.${b64u(sig)}`, exp }
  return sysToks[user].jwt
}

export interface Res<T = any> {
  status: number
  json: T
  text: string
  headers: Headers
  ms: number
}

export interface Opts {
  method?: string
  json?: unknown
  form?: Record<string, string>
  token?: string
  /** x-zitadel-instance-host */
  instance?: string
  /** x-zitadel-public-host */
  pub?: string
  /** Host header override (needs undici; Node fetch forbids Host): not used, kept for docs */
  headers?: Record<string, string>
  redirect?: 'manual' | 'follow'
  base?: string
}

/** One HTTP call to Zitadel; never throws on HTTP status. */
export async function z<T = any>(path: string, o: Opts = {}): Promise<Res<T>> {
  const h = new Headers(o.headers)
  if (o.token) h.set('authorization', `Bearer ${o.token}`)
  if (o.instance) h.set('x-zitadel-instance-host', o.instance)
  if (o.pub) h.set('x-zitadel-public-host', o.pub)
  let body: string | undefined
  if (o.json !== undefined) {
    h.set('content-type', 'application/json')
    body = JSON.stringify(o.json)
  } else if (o.form) {
    h.set('content-type', 'application/x-www-form-urlencoded')
    body = new URLSearchParams(o.form).toString()
  }
  h.set('accept', 'application/json')
  let t0 = performance.now()
  let r: Response
  for (let attempt = 0; ; attempt++) {
    t0 = performance.now()
    try {
      r = await fetch((o.base ?? BASE) + path, {
        method: o.method ?? (body ? 'POST' : 'GET'),
        headers: h,
        body,
        redirect: o.redirect ?? 'manual',
        signal: AbortSignal.timeout(60_000),
      })
      break
    } catch (e) {
      // Keep-alive resets (ECONNRESET) on a reused socket: retry; a real outage still throws.
      if (attempt >= 3) throw e
      await sleep(200)
    }
  }
  const text = await r.text()
  const ms = performance.now() - t0
  let json: any
  try {
    json = JSON.parse(text)
  } catch {
    json = undefined
  }
  return { status: r.status, json, text, headers: r.headers, ms }
}

export async function ok<T = any>(what: string, p: Promise<Res<T>>): Promise<Res<T>> {
  const r = await p
  if (r.status >= 300) throw new Error(`${what}: ${r.status} ${r.text.slice(0, 500)}`)
  return r
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** Retry while Zitadel's projections catch up (NotFound / precondition right after a write). */
export async function eventually<T>(what: string, f: () => Promise<Res<T>>, tries = 40): Promise<Res<T>> {
  let last: Res<T> | undefined
  for (let i = 0; i < tries; i++) {
    last = await f()
    if (last.status < 300) return last
    if (![400, 401, 403, 404, 412].includes(last.status)) break
    await sleep(250)
  }
  throw new Error(`${what}: ${last?.status} ${last?.text.slice(0, 500)}`)
}

export interface Instance {
  id: string
  name: string
  domain: string // internal instance domain, e.g. m-1.idp.internal
  pat: string // owner machine user PAT (IAM_OWNER)
  createMs: number
}

/** System API: create an instance with an owner machine user (PAT) and a custom (internal) domain. */
export async function createInstance(name: string, domain: string): Promise<Instance> {
  const r = await ok(
    `create instance ${name}`,
    z('/system/v1/instances/_create', {
      token: systemToken(),
      json: {
        instanceName: name,
        firstOrgName: 'staff',
        customDomain: domain,
        // `owner` is a proto oneof: the variant goes at top level.
        machine: {
          userName: 'owner',
          name: 'owner',
          personalAccessToken: { expirationDate: '2099-01-01T00:00:00Z' },
        },
        defaultLanguage: 'en',
      },
    }),
  )
  return { id: r.json.instanceId, name, domain, pat: r.json.pat, createMs: r.ms }
}

export function pkce() {
  const verifier = b64u(randomBytes(32))
  const challenge = b64u(createHash('sha256').update(verifier).digest())
  return { verifier, challenge, state: b64u(randomBytes(12)) }
}

export function decodeJwt(t: string): any {
  return JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString())
}

export function pct(xs: number[], p: number): number {
  if (!xs.length) return NaN
  const s = [...xs].sort((a, b) => a - b)
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]
}

export const round = (n: number) => Math.round(n * 10) / 10

/** Run f over items with at most n in flight. */
export async function pool<T, R>(items: T[], n: number, f: (x: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length)
  let next = 0
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (next < items.length) {
        const i = next++
        out[i] = await f(items[i], i)
      }
    }),
  )
  return out
}

export const REDIRECT = 'http://localhost:3999/callback'

export interface LoginCfg {
  projectId: string
  clientId: string
  orgId: string
  userId: string
  email: string
}

/**
 * Per-instance login setup through the instance header only: project, PKCE OIDC app (JWT access
 * tokens), one human user with a pre-verified email and a password. Uses the owner PAT (IAM_OWNER).
 */
export async function provisionLogin(inst: Instance, email = 'user@example.com', pub?: string): Promise<LoginCfg & { ms: number }> {
  const t0 = performance.now()
  const o = { token: inst.pat, instance: inst.domain, pub }
  const org = await eventually('orgs/me', () => z('/management/v1/orgs/me', o))
  const p = await ok('project', z('/management/v1/projects', { ...o, json: { name: 'app' } }))
  const app = await ok(
    'oidc app',
    z(`/management/v1/projects/${p.json.id}/apps/oidc`, {
      ...o,
      json: {
        name: 'web',
        redirectUris: [REDIRECT],
        responseTypes: ['OIDC_RESPONSE_TYPE_CODE'],
        grantTypes: ['OIDC_GRANT_TYPE_AUTHORIZATION_CODE'],
        appType: 'OIDC_APP_TYPE_USER_AGENT',
        authMethodType: 'OIDC_AUTH_METHOD_TYPE_NONE',
        accessTokenType: 'OIDC_TOKEN_TYPE_JWT',
        devMode: true,
        version: 'OIDC_VERSION_1_0',
        loginVersion: { loginV2: { baseUri: 'http://login.internal/ui/v2/login/' } },
      },
    }),
  )
  const u = await ok(
    'user',
    z('/v2/users/new', {
      ...o,
      json: {
        organizationId: org.json.org.id,
        username: email,
        human: {
          profile: { givenName: 'Test', familyName: 'User' },
          email: { email, isVerified: true },
          password: { password: PASSWORD, changeRequired: false },
        },
      },
    }),
  )
  return {
    projectId: p.json.id,
    clientId: app.json.clientId,
    orgId: org.json.org.id,
    userId: u.json.id,
    email,
    ms: performance.now() - t0,
  }
}

export interface LoginResult {
  accessToken: string
  idToken?: string
  ms: { authorize: number; session: number; finalize: number; token: number; total: number }
}

/**
 * Headless OIDC code + PKCE login, as Login UI v2 does it (stack a's driver): authorize →
 * Session API (user + password checks) → finalize the auth request → token. All through the
 * instance header; `pub` sets x-zitadel-public-host. `loginToken` = a token allowed to use the
 * Session/OIDC services (IAM_LOGIN_CLIENT).
 */
export async function login(inst: Instance, cfg: LoginCfg, opts: { pub?: string; loginToken?: string; password?: string } = {}): Promise<LoginResult> {
  const o = { instance: inst.domain, pub: opts.pub }
  // Default: the zlogin System API user (IAM_LOGIN_CLIENT on every instance), like one shared
  // Login UI v2. The instance owner PAT gets 403 AUTH-AWfge on finalize (IAM_OWNER lacks it).
  const tok = opts.loginToken ?? systemToken('zlogin')
  const { verifier, challenge, state } = pkce()
  const q = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: `openid profile email urn:zitadel:iam:org:project:id:${cfg.projectId}:aud`,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  })
  const t0 = performance.now()
  const a = await z(`/oauth/v2/authorize?${q}`, o)
  const loc = a.headers.get('location')
  if (a.status < 300 || a.status >= 400 || !loc) throw new Error(`authorize: ${a.status} ${a.text.slice(0, 300)}`)
  const authRequest = new URL(loc, 'http://x').searchParams.get('authRequest')
  if (!authRequest) throw new Error(`authorize: no authRequest in ${loc}`)
  const s = await ok(
    'session',
    z('/v2/sessions', { ...o, token: tok, json: { checks: { user: { loginName: cfg.email }, password: { password: opts.password ?? PASSWORD } } } }),
  )
  const f = await ok(
    'finalize',
    z(`/v2/oidc/auth_requests/${authRequest}`, {
      ...o,
      token: tok,
      json: { session: { sessionId: s.json.sessionId, sessionToken: s.json.sessionToken } },
    }),
  )
  const cb = new URL(f.json.callbackUrl)
  const code = cb.searchParams.get('code')
  if (!code || cb.searchParams.get('state') !== state) throw new Error(`callback: ${f.json.callbackUrl}`)
  const t = await ok(
    'token',
    z('/oauth/v2/token', {
      ...o,
      form: { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: cfg.clientId, code_verifier: verifier },
    }),
  )
  return {
    accessToken: t.json.access_token,
    idToken: t.json.id_token,
    ms: { authorize: a.ms, session: s.ms, finalize: f.ms, token: t.ms, total: performance.now() - t0 },
  }
}

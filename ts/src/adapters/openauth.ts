// Identity: OpenAuth (openauthjs, 0.4.3), its issuer mounted in the app's own Hono server.
//
// Users: OpenAuth's password provider, driven as an authorization-code + PKCE flow by one
// first-party public client (FIRST_PARTY_CLIENT). `success` maps the login's email to the app's user
// row and issues a `user` subject whose `sub` is our user id.
// Apps and agents: OpenAuth has no client registry. Its /token endpoint accepts
// grant_type=client_credentials only through a provider that implements `client()`, and none of the
// built-in providers do. So this adapter registers clients itself (table `openauth_clients`,
// SHA-256 of a 256-bit random secret) and plugs a `client` provider into the issuer that checks the
// secret; `success` then issues a `client` subject. Tokens are still minted and signed by OpenAuth.
import { createClient } from '@openauthjs/openauth/client'
import { issuer } from '@openauthjs/openauth/issuer'
import { PasswordProvider, ScryptHasher } from '@openauthjs/openauth/provider/password'
import type { Provider } from '@openauthjs/openauth/provider/provider'
import { encryptionKeys, signingKeys } from '@openauthjs/openauth/keys'
import { Storage } from '@openauthjs/openauth/storage/storage'
import { createSubjects } from '@openauthjs/openauth/subject'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type pg from 'pg'
import { z } from 'zod'
import { migrateKv, PostgresStorage, sweepKv } from './openauth-pg-storage.js'

/** What the app learns from a valid credential (same shape as the Better Auth adapter). */
export type Credential = { type: 'session'; userId: string } | { type: 'client'; clientId: string; scopes: string[] }

export interface OpenAuthConfig {
  pool: pg.Pool
  /** Public base URL of the app; pinned as the token issuer (`iss`). */
  baseUrl: string
  /** The client id the login flow must use; the `aud` of user tokens. */
  firstPartyClient: string
  /** Redirect URIs the first-party client may use (loopback for headless/native clients). */
  redirectUris: string[]
  /** The one scope the principal resolver requires of client tokens. OpenAuth tokens carry no
   *  scope claim; a verified `client` subject is given this scope by the adapter. */
  apiScope: string
  accessTtlSeconds: number
  refreshTtlSeconds: number
}

const CLIENTS_TABLE = 'openauth_clients'

export const subjects = createSubjects({
  user: z.object({ id: z.string() }),
  client: z.object({ clientId: z.string() }),
})

/** Gate in front of the issuer's /authorize. `allow()` is not enough: when it says no, the issuer's
 *  error handler still 302s to the rejected redirect_uri (an open redirect, cf. issue #299). And
 *  `allow()` never sees response_type or PKCE, so it can't refuse the implicit flow (tokens in a URL
 *  fragment) or a code flow without PKCE for a public client. */
export function checkAuthorize(q: URLSearchParams, cfg: Pick<OpenAuthConfig, 'firstPartyClient' | 'redirectUris'>): string | undefined {
  if (q.get('client_id') !== cfg.firstPartyClient) return 'unknown client_id'
  if (!cfg.redirectUris.includes(q.get('redirect_uri') ?? '')) return 'redirect_uri not registered'
  if (q.get('response_type') !== 'code') return 'only response_type=code'
  if (q.get('code_challenge_method') !== 'S256' || !q.get('code_challenge')) return 'PKCE (S256) required'
  return undefined
}

const sha256 = (s: string) => createHash('sha256').update(s).digest()

/** Our users table, read by `success` (email → user id). Injected so the adapter doesn't import the app schema. */
export type UserLookup = (email: string) => Promise<{ id: string } | undefined>

export async function makeOpenAuth(cfg: OpenAuthConfig, lookupUser: UserLookup) {
  const { pool } = cfg
  await migrateKv(pool)
  await pool.query(`create table if not exists ${CLIENTS_TABLE} (
    client_id text primary key,
    secret_sha256 bytea not null,
    name text not null,
    created_at timestamptz not null default now()
  )`)
  await sweepKv(pool)
  const sweep = setInterval(() => sweepKv(pool).catch((e) => console.error('openauth kv sweep', e)), 10 * 60_000)
  sweep.unref()

  const storage = PostgresStorage(pool)
  const hasher = ScryptHasher() // OpenAuth's default: scrypt N=16384 r=8 p=1
  // The password provider skips the hash check when the email has no password, so a wrong
  // password for a known email took ~40 ms and an unknown email ~9 ms (user enumeration by timing).
  // On a failed login for an unknown email, `login` verifies against this dummy hash.
  const dummyHash = await hasher.hash(randomBytes(16).toString('hex'))

  // The password provider wants a UI for login, register and change. Only login is reachable
  // (register/change are not mounted), and it answers JSON: no HTML pages are needed for a bearer API.
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
  const password = PasswordProvider({
    login: async (_req, form, error) => {
      if (!error) return json(200, { form: ['email', 'password'] })
      const email = form?.get('email')?.toString().toLowerCase()
      if (email && !(await Storage.get(storage, ['email', email, 'password']))) await hasher.verify(form?.get('password')?.toString() ?? '', dummyHash)
      return json(401, { error: error.type })
    },
    register: async () => json(404, { error: 'registration_disabled' }),
    change: async () => json(404, { error: 'password_change_disabled' }),
    sendCode: async () => {
      throw new Error('codes are not sent in this spike')
    },
    hasher,
  })

  /** client_credentials for registered machine clients. `client()` cannot reject a request by
   *  itself (the issuer mints a token from whatever it returns), so it returns `ok` and `success`
   *  answers 401 when the secret doesn't match. */
  const clientProvider: Provider<{ clientId: string; ok: boolean }> = {
    type: 'client',
    init() {}, // no routes: /token handles this provider
    async client({ clientID, clientSecret }) {
      const r = await pool.query<{ secret_sha256: Buffer }>(`select secret_sha256 from ${CLIENTS_TABLE} where client_id = $1`, [clientID])
      const want = r.rows[0]?.secret_sha256
      const ok = !!want && timingSafeEqual(want, sha256(clientSecret))
      return { clientId: clientID, ok }
    },
  }

  const issuerApp = issuer({
    subjects,
    storage,
    providers: { password, client: clientProvider },
    ttl: { access: cfg.accessTtlSeconds, refresh: cfg.refreshTtlSeconds },
    // Default `allow` accepts any client_id and any redirect on the issuer's own domain (and an open
    // redirect bug, issue #299). Only the first-party client with an exact redirect URI may log in.
    allow: async ({ clientID, redirectURI }) => clientID === cfg.firstPartyClient && cfg.redirectUris.includes(redirectURI),
    async success(ctx, value) {
      if (value.provider === 'password') {
        const u = await lookupUser(value.email)
        if (!u) return json(401, { error: 'unknown_user' })
        return ctx.subject('user', { id: u.id }, { subject: u.id })
      }
      if (value.provider === 'client') {
        if (!value.ok) return json(401, { error: 'invalid_client' })
        // OpenAuth always issues and stores a refresh token; `handler` deletes it (dropClientRefresh).
        return ctx.subject('client', { clientId: value.clientId }, { subject: value.clientId, ttl: { refresh: 60 } })
      }
      return json(400, { error: 'unsupported_provider' })
    },
  })

  /** Every request into the issuer gets the configured base URL. The issuer derives `iss` from the
   *  request URL and trusts X-Forwarded-Host/Proto/Port; left alone, any caller could pick the `iss`
   *  of the tokens it gets. */
  const base = new URL(cfg.baseUrl)
  async function handler(req: Request): Promise<Response> {
    const u = new URL(req.url)
    // Hono's routers (the app's and the issuer's) match the decodeURI'd path: "/%61uthorize" reached
    // the issuer's /authorize past a gate that compared the raw path. Gate and forward the decoded path.
    let path: string
    try {
      path = decodeURI(u.pathname)
    } catch {
      return json(400, { error: 'invalid_request' })
    }
    if (path === '/authorize') {
      const bad = checkAuthorize(u.searchParams, cfg)
      if (bad) return json(400, { error: 'invalid_request', error_description: bad })
    }
    const url = new URL(base.origin)
    url.pathname = path
    url.search = u.search
    const headers = new Headers(req.headers)
    for (const h of ['x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-port', 'host']) headers.delete(h)
    const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : await req.arrayBuffer()
    const res = await issuerApp.fetch(new Request(url, { method: req.method, headers, body, redirect: 'manual' }))
    if (path === '/token' && body && res.ok) return dropClientRefresh(body, res)
    return res
  }

  /** OpenAuth issues a refresh token with every client_credentials token, and its refresh grant
   *  re-checks neither the secret nor the client: each refresh returns a new refresh token, so a
   *  holder kept getting tokens forever, after the secret changed or the client was deleted.
   *  Machines hold their secret; delete the stored refresh token and don't hand it out. */
  async function dropClientRefresh(body: ArrayBuffer, res: Response): Promise<Response> {
    const form = new URLSearchParams(new TextDecoder().decode(body))
    if (form.get('grant_type') !== 'client_credentials') return res
    const { refresh_token, ...rest } = (await res.json()) as { refresh_token?: string }
    if (refresh_token) {
      const i = refresh_token.lastIndexOf(':')
      await Storage.remove(storage, ['oauth:refresh', refresh_token.slice(0, i), refresh_token.slice(i + 1)])
    }
    const headers = new Headers(res.headers)
    headers.delete('content-length')
    return new Response(JSON.stringify(rest), { status: 200, headers })
  }

  // Verification uses OpenAuth's own client. Its JWKS fetch goes to the issuer in-process (no
  // network hop). Note: the client caches the JWKS for the life of the process.
  const issuerUrl = base.origin
  const verifier = createClient({
    clientID: cfg.firstPartyClient,
    issuer: issuerUrl,
    fetch: (input, init) => handler(new Request(input, init)),
  })

  // Generate the signing and encryption keys now, under a lock. Each instance caches its key list for
  // the life of the process (issuer and verifier), and the client lib never refetches the JWKS on an
  // unknown kid. Two instances creating keys at once could each keep only its own: tokens (and the
  // encrypted `authorization` cookie) from one would then fail on the other until restart.
  const lock = await pool.connect()
  try {
    await lock.query(`select pg_advisory_lock(hashtext('openauth_keys'))`)
    await signingKeys(storage)
    await encryptionKeys(storage)
  } finally {
    await lock.query(`select pg_advisory_unlock(hashtext('openauth_keys'))`).catch(() => {})
    lock.release()
  }
  await handler(new Request(`${issuerUrl}/.well-known/jwks.json`))

  return {
    /** Validate `Authorization: Bearer …`: signature (issuer JWKS), `iss`, `exp`, `mode: access`,
     *  the subject schema (OpenAuth's `verify`), then `aud`, which `verify` leaves to the caller. */
    async authenticate(authorization: string | undefined): Promise<Credential | null> {
      const m = /^Bearer\s+(\S+)$/i.exec(authorization ?? '')
      if (!m) return null
      let v
      try {
        v = await verifier.verify(subjects, m[1]!)
      } catch {
        return null
      }
      if (v.err) return null
      if (v.subject.type === 'user') return v.aud === cfg.firstPartyClient ? { type: 'session', userId: v.subject.properties.id } : null
      if (v.subject.type === 'client') {
        const clientId = v.subject.properties.clientId
        return v.aud === clientId ? { type: 'client', clientId, scopes: [cfg.apiScope] } : null
      }
      return null
    },

    /** OpenAuth has no API to create a user: its password provider only knows the email-code
     *  registration form. The test endpoint writes the hash where the provider looks for it. */
    async createUser(email: string, pw: string): Promise<{ id: string; email: string }> {
      const key = ['email', email, 'password']
      if (await Storage.get(storage, key)) throw new Error('email taken')
      await Storage.set(storage, key, await hasher.hash(pw))
      return { id: `usr_${randomBytes(10).toString('base64url')}`, email }
    },

    /** Register a machine client (app or agent). `actorCredential` is unused: the registry is ours. */
    async createClient(name: string, _actorCredential: string): Promise<{ clientId: string; clientSecret: string }> {
      const clientId = `cli_${randomBytes(12).toString('base64url')}`
      const clientSecret = randomBytes(32).toString('base64url')
      await pool.query(`insert into ${CLIENTS_TABLE} (client_id, secret_sha256, name) values ($1, $2, $3)`, [clientId, sha256(clientSecret), name])
      return { clientId, clientSecret }
    },

    handler,
    /** Only these issuer routes are reachable over HTTP (no /password/register, /password/change). */
    exposedPaths: ['/authorize', '/password/authorize', '/token', '/.well-known/jwks.json', '/.well-known/oauth-authorization-server'],
  }
}
export type OpenAuthIdentity = Awaited<ReturnType<typeof makeOpenAuth>>

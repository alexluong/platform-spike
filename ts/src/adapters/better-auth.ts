// Identity: Better Auth, in the app. Users sign in with email/password and use the session token
// as a bearer (bearer plugin). Apps and agents are OAuth clients of Better Auth's OAuth provider
// and get JWT access tokens via client_credentials; we verify those against the JWKS.
import { betterAuth, type BetterAuthOptions } from 'better-auth'
import { getMigrations } from 'better-auth/db/migration'
import { verifyJwsAccessToken } from 'better-auth/oauth2'
import { bearer, jwt } from 'better-auth/plugins'
import { oauthProvider } from '@better-auth/oauth-provider'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import type pg from 'pg'

/** What the app learns from a valid credential (before mapping to app records). */
export type Credential = { type: 'session'; userId: string } | { type: 'client'; clientId: string; scopes: string[] }

export interface IdentityConfig {
  pool: pg.Pool
  baseUrl: string // issuer base, e.g. http://localhost:8083
  secret: string
  /** RFC 8707 resource identifier for this API; the `aud` of client tokens. */
  apiResource: string
  /** Better Auth's rate limiter (sign-in: 3 per 10 s per IP). Off only for the test stack, which signs
   *  in hundreds of users from one IP. */
  rateLimit: boolean
  /** Header carrying the client IP, set by a trusted proxy (e.g. x-forwarded-for). Without it the
   *  limiter can't tell clients apart and puts every request in one shared bucket. */
  ipHeader?: string
  /** Shared secret for the app's own client-registration calls (see internalOnlyClientPrivileges). */
  internalKey: string
}

const INTERNAL_HEADER = 'x-platform-internal'

/** OAuth client admin is for the app's own server-side calls only. Better Auth checks this hook on
 *  every client mutation, for any caller with a session, so `async () => true` would let any signed-in
 *  user (customers too) create, read, rotate or delete clients the moment one of those routes is
 *  mounted. Only requests carrying the per-process key, and only the actions we use, pass. */
export function internalOnlyClientPrivileges(internalKey: string) {
  const want = Buffer.from(internalKey)
  return async ({ headers, action }: { headers: Headers; action: string }) => {
    if (action !== 'create' && action !== 'configure-client-credentials-scopes') return false
    const got = Buffer.from(headers.get(INTERNAL_HEADER) ?? '')
    return got.length === want.length && timingSafeEqual(got, want)
  }
}

/** A fresh random key per process (clients are only created in-process). */
export const newInternalKey = () => randomBytes(32).toString('hex')

export const API_SCOPE = 'api'

export function authOptions(cfg: IdentityConfig) {
  return {
    baseURL: cfg.baseUrl,
    basePath: '/api/auth',
    secret: cfg.secret,
    database: cfg.pool,
    emailAndPassword: { enabled: true, minPasswordLength: 8 },
    telemetry: { enabled: false },
    rateLimit: { enabled: cfg.rateLimit },
    advanced: {
      // Bearer-only API: /api reads only the Authorization header, and the only Better Auth routes
      // mounted are sign-in, token, jwks and discovery, so no cookie ever authenticates anything and
      // login CSRF has nothing to ride on. Node's fetch sends Sec-Fetch-Mode without an Origin, which
      // Better Auth 1.7 rejects (MISSING_OR_NULL_ORIGIN). callbackURL validation stays on.
      // Revisit (trustedOrigins + this check on) before any browser uses cookie sessions.
      disableCSRFCheck: true,
      ...(cfg.ipHeader ? { ipAddress: { ipAddressHeaders: [cfg.ipHeader] } } : {}),
    },
    plugins: [
      bearer(),
      jwt(),
      oauthProvider({
        loginPage: '/login', // unused: no authorization-code flow in this spike
        consentPage: '/consent',
        scopes: [API_SCOPE],
        grantTypes: ['client_credentials'],
        clientPrivileges: internalOnlyClientPrivileges(cfg.internalKey),
        resources: [{ identifier: cfg.apiResource, allowedScopes: [API_SCOPE] }],
        clientRegistrationDefaultResources: [cfg.apiResource],
      }),
    ],
  } satisfies BetterAuthOptions
}

/** Create/upgrade Better Auth's tables. Runs before the instance exists: the OAuth provider seeds
 *  its resource row at init, which needs the tables. */
export async function migrateBetterAuth(cfg: IdentityConfig) {
  const { runMigrations } = await getMigrations(authOptions(cfg))
  await runMigrations()
}

export function makeBetterAuth(cfg: IdentityConfig) {
  const auth = betterAuth(authOptions(cfg))

  const issuer = `${cfg.baseUrl}/api/auth`
  const jwksCacheKey = {}
  const jwksFetch = async () => {
    const r = await auth.handler(new Request(`${issuer}/jwks`))
    return (await r.json()) as never
  }

  return {
    auth,

    /** Validate `Authorization: Bearer …`. Session tokens are checked against Better Auth's
     *  session table; JWT client tokens against the JWKS (iss, aud, exp, scope). */
    async authenticate(authorization: string | undefined): Promise<Credential | null> {
      const m = /^Bearer\s+(\S+)$/i.exec(authorization ?? '')
      if (!m) return null
      const token = m[1]!
      if (token.split('.').length === 3) {
        try {
          const p = await verifyJwsAccessToken(token, { jwksFetch, jwksCacheKey, verifyOptions: { issuer, audience: cfg.apiResource } })
          const scopes = typeof p.scope === 'string' ? p.scope.split(' ') : []
          const clientId = typeof p.azp === 'string' ? p.azp : typeof p.client_id === 'string' ? p.client_id : undefined
          // client_credentials tokens carry sub = client_id; anything else would be user-delegated (unused here)
          if (!clientId || (p.sub && p.sub !== clientId)) return null
          return { type: 'client', clientId, scopes }
        } catch {
          return null
        }
      }
      try {
        const s = await auth.api.getSession({ headers: new Headers({ authorization: `Bearer ${token}` }) })
        return s ? { type: 'session', userId: s.user.id } : null
      } catch {
        return null
      }
    },

    async createUser(email: string, password: string): Promise<{ id: string; email: string }> {
      const r = await auth.api.signUpEmail({ body: { email, password, name: email } })
      return { id: r.user.id, email: r.user.email }
    },

    /** Register an OAuth client (client_credentials, scope api) for an app or agent. Better Auth's
     *  admin endpoint wants a session, so the calling user's credential is passed through (the client
     *  is recorded as owned by that user); the internal key is what authorizes the call. */
    async createClient(name: string, actorCredential: string): Promise<{ clientId: string; clientSecret: string }> {
      const c = (await auth.api.adminCreateOAuthClient({
        headers: new Headers({ authorization: actorCredential, [INTERNAL_HEADER]: cfg.internalKey }),
        body: {
          client_name: name,
          grant_types: ['client_credentials'],
          client_credentials_scopes: [API_SCOPE],
          token_endpoint_auth_method: 'client_secret_post',
        },
      })) as { client_id: string; client_secret?: string }
      if (!c.client_secret) throw new Error('no client secret returned')
      return { clientId: c.client_id, clientSecret: c.client_secret }
    },

    /** Only these Better Auth routes are reachable over HTTP. */
    exposedPaths: ['/api/auth/sign-in/email', '/api/auth/oauth2/token', '/api/auth/jwks', '/api/auth/.well-known/openid-configuration'],
  }
}
export type Identity = ReturnType<typeof makeBetterAuth>

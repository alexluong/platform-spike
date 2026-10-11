// Identity: Better Auth, in the app. Users sign in with email/password and use the session token
// as a bearer (bearer plugin). Apps and agents are OAuth clients of Better Auth's OAuth provider
// and get JWT access tokens via client_credentials; we verify those against the JWKS.
import { betterAuth } from 'better-auth'
import { getMigrations } from 'better-auth/db/migration'
import { verifyJwsAccessToken } from 'better-auth/oauth2'
import { bearer, jwt } from 'better-auth/plugins'
import { oauthProvider } from '@better-auth/oauth-provider'
import type pg from 'pg'

/** What the app learns from a valid credential (before mapping to app records). */
export type Credential = { type: 'session'; userId: string } | { type: 'client'; clientId: string; scopes: string[] }

export interface IdentityConfig {
  pool: pg.Pool
  baseUrl: string // issuer base, e.g. http://localhost:8083
  secret: string
  /** RFC 8707 resource identifier for this API; the `aud` of client tokens. */
  apiResource: string
}

export const API_SCOPE = 'api'

export function makeBetterAuth(cfg: IdentityConfig) {
  const auth = betterAuth({
    baseURL: cfg.baseUrl,
    basePath: '/api/auth',
    secret: cfg.secret,
    database: cfg.pool,
    emailAndPassword: { enabled: true, minPasswordLength: 8 },
    telemetry: { enabled: false },
    plugins: [
      bearer(),
      jwt(),
      oauthProvider({
        loginPage: '/login', // unused: no authorization-code flow in this spike
        consentPage: '/consent',
        scopes: [API_SCOPE],
        grantTypes: ['client_credentials'],
        // Only the app's own server-side calls create clients (the HTTP routes are not mounted).
        clientPrivileges: async () => true,
        resources: [{ identifier: cfg.apiResource, allowedScopes: [API_SCOPE] }],
        clientRegistrationDefaultResources: [cfg.apiResource],
      }),
    ],
  })

  const issuer = `${cfg.baseUrl}/api/auth`
  const jwksCacheKey = {}
  const jwksFetch = async () => {
    const r = await auth.handler(new Request(`${issuer}/jwks`))
    return (await r.json()) as never
  }

  return {
    auth,

    async migrate() {
      const { runMigrations } = await getMigrations(auth.options)
      await runMigrations()
    },

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
          if (!clientId || p.sub) return null // user-delegated tokens are not used in this spike
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
     *  admin endpoint wants a session, so the calling user's credential is passed through. */
    async createClient(name: string, actorCredential: string): Promise<{ clientId: string; clientSecret: string }> {
      const c = (await auth.api.adminCreateOAuthClient({
        headers: new Headers({ authorization: actorCredential }),
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

// Identity: Better Auth, in the app, with the organization plugin owning the merchant's identity
// side (SPEC §15.1): one organization per merchant, membership, invitations, and the login policy for
// suspended merchants (§15.3). Users sign in with email/password and use the session token as a
// bearer (bearer plugin). Apps and agents are OAuth clients of Better Auth's OAuth provider and get
// JWT access tokens via client_credentials; we verify those against the JWKS.
//
// Cross-system writes (§15.1): Better Auth's core and the organization plugin resolve their DB
// adapter through an AsyncLocalStorage (`getCurrentAdapter`). `tenancyFor(client)` puts an adapter
// bound to the app's transaction connection there, so organization/member/invitation writes run
// inside the app's transaction: one commit, no dual write. The OAuth provider does NOT read that
// storage (it writes through `ctx.context.adapter`), so client creation stays outside (see createClient).
import { AsyncLocalStorage } from 'node:async_hooks'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { getCurrentDBAdapterAsyncLocalStorage } from '@better-auth/core/context'
import { kyselyAdapter } from '@better-auth/kysely-adapter'
import { oauthProvider } from '@better-auth/oauth-provider'
import { betterAuth, type BetterAuthOptions } from 'better-auth'
import { APIError, createAuthMiddleware, isAPIError } from 'better-auth/api'
import { getMigrations } from 'better-auth/db/migration'
import { verifyJwsAccessToken } from 'better-auth/oauth2'
import { bearer, jwt } from 'better-auth/plugins'
import { getOrgAdapter, organization } from 'better-auth/plugins/organization'
import { Kysely, PostgresDialect } from 'kysely'
import type pg from 'pg'
import { AppError, conflict, forbidden, notFound } from '../kernel/errors.js'
import type { InvitationRecord, MerchantStatus, Tenancy } from '../kernel/tenancy.js'

/** What the app learns from a valid credential (before mapping to app records). */
export type Credential = { type: 'session'; userId: string } | { type: 'client'; clientId: string; scopes: string[] }

export interface IdentityConfig {
  pool: pg.Pool
  baseUrl: string // issuer base, e.g. http://localhost:8086
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

/** The role every member has in Better Auth. Roles are the app's (role_assignments, §3); the IdP's
 *  role column is unused so no role lives in two places. */
export const IDP_MEMBER_ROLE = 'member'

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

/** Minimal view of Better Auth's DB adapter used by the login-policy hooks. */
type FindOne = { findOne<T>(q: { model: string; where: { field: string; value: string }[] }): Promise<T | null> }

/** Is `userId` a member of a suspended organization? (login policy, §15.3) */
async function userSuspended(db: FindOne, userId: string) {
  const m = await db.findOne<{ organizationId: string }>({ model: 'member', where: [{ field: 'userId', value: userId }] })
  return m ? orgSuspended(db, m.organizationId) : false
}
async function orgSuspended(db: FindOne, organizationId: string) {
  const o = await db.findOne<{ status?: string | null }>({ model: 'organization', where: [{ field: 'id', value: organizationId }] })
  return o?.status === 'suspended'
}

export const orgOptions = {
  // Nobody creates organizations or invites through Better Auth's own routes (none are mounted);
  // the app does it through the organization adapter, after its own authorization (§3 member.manage).
  allowUserToCreateOrganization: false,
  // Defaults are 100: a merchant's 101st member couldn't accept an invitation.
  membershipLimit: 1_000_000,
  invitationLimit: 1_000_000,
  invitationExpiresIn: 7 * 24 * 3600,
  schema: {
    organization: {
      additionalFields: {
        // the merchant's status: the IdP's login policy and the app's §7 checks both read it
        status: { type: 'string', required: false, defaultValue: 'active', input: false },
      },
    },
  },
} as const

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
    // Login policy, users (§15.3): no session for a member of a suspended merchant. Runs for every
    // way a session gets created, after the password check (a wrong password stays 401).
    databaseHooks: {
      session: {
        create: {
          before: async (session: { userId: string }, ctx: { context: { adapter: unknown } } | null) => {
            if (!ctx) return
            if (await userSuspended(ctx.context.adapter as FindOne, session.userId)) {
              throw new APIError('FORBIDDEN', { message: 'merchant suspended', code: 'MERCHANT_SUSPENDED' })
            }
          },
        },
      },
    },
    // Login policy, agents (§15.3): no client_credentials token for a client whose owning
    // organization (oauthClient.referenceId, set by attachClient) is suspended. Apps have no
    // organization and are unaffected.
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        if (ctx.path !== '/oauth2/token') return
        const body = (ctx.body ?? {}) as Record<string, unknown>
        if (body.grant_type !== 'client_credentials' || typeof body.client_id !== 'string') return
        const db = ctx.context.adapter as unknown as FindOne
        const client = await db.findOne<{ referenceId?: string | null }>({ model: 'oauthClient', where: [{ field: 'clientId', value: body.client_id }] })
        if (client?.referenceId && (await orgSuspended(db, client.referenceId))) {
          throw new APIError('BAD_REQUEST', { error: 'invalid_client', error_description: 'the owning organization is suspended' })
        }
      }),
    },
    plugins: [
      bearer(),
      jwt(),
      organization(orgOptions),
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

/** Statements that would open or end a transaction: never allowed on the app's tx connection. */
const TX_CONTROL = /^\s*(begin|start\s+transaction|commit|rollback|end|savepoint|release)\b/i

export function makeBetterAuth(cfg: IdentityConfig) {
  const auth = betterAuth(authOptions(cfg))

  const issuer = `${cfg.baseUrl}/api/auth`
  const jwksCacheKey = {}
  const jwksFetch = async () => {
    const r = await auth.handler(new Request(`${issuer}/jwks`))
    return (await r.json()) as never
  }

  // A Better Auth DB adapter whose "pool" hands out the app's current transaction connection.
  const txClient = new AsyncLocalStorage<pg.PoolClient>()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const txKysely = new Kysely<any>({
    dialect: new PostgresDialect({
      pool: {
        async connect() {
          const c = txClient.getStore()
          if (!c) throw new Error('Better Auth tx adapter used outside a transaction')
          return {
            query: ((sql: string, params?: unknown[]) => {
              if (TX_CONTROL.test(sql)) throw new Error(`refusing "${sql}" on the app's transaction connection`)
              return c.query(sql, params as never[])
            }) as never,
            release() {},
          }
        },
        async end() {},
        options: {},
      },
    }),
  })
  const txAdapter = kyselyAdapter(txKysely, { type: 'postgres' })(auth.options)
  const orgs = getOrgAdapter({ adapter: txAdapter } as never, orgOptions)

  /** Run Better Auth code with every adapter lookup resolving to the app's transaction. */
  async function inTx<T>(client: pg.PoolClient, pending: (() => Promise<void>)[], fn: () => Promise<T>): Promise<T> {
    const als = await getCurrentDBAdapterAsyncLocalStorage()
    return txClient.run(client, () => als.run({ adapter: txAdapter, pendingHooks: pending, isTransactionActive: true } as never, fn))
  }

  const invitationOut = (i: { id: string; organizationId: string; email: string; status: string; expiresAt: Date | string }): InvitationRecord => ({
    id: i.id,
    organizationId: i.organizationId,
    email: i.email,
    status: i.status,
    expiresAt: new Date(i.expiresAt),
  })

  const isUniqueViolation = (e: unknown): boolean => {
    for (let x: unknown = e; x && typeof x === 'object'; x = (x as { cause?: unknown }).cause) {
      if ((x as { code?: unknown }).code === '23505') return true
    }
    return false
  }

  /** The tenancy port bound to one transaction connection. `afterCommit` runs Better Auth's
   *  after-commit hooks (queued while the transaction was open); drop them on rollback. */
  function tenancyFor(client: pg.PoolClient): { port: Tenancy; afterCommit(): Promise<void> } {
    const pending: (() => Promise<void>)[] = []
    const run = <T>(fn: () => Promise<T>) => inTx(client, pending, fn)
    const port: Tenancy = {
      createOrganization: ({ id, name }) =>
        run(async () => {
          await orgs.createOrganization({ organization: { id, name, slug: id, createdAt: new Date(), status: 'active' } as never })
        }),

      setStatus: (organizationId, status: MerchantStatus) =>
        run(async () => !!(await orgs.updateOrganization(organizationId, { status } as never))),

      addMember: (organizationId, userId) =>
        run(async () => {
          try {
            await orgs.createMember({ organizationId, userId, role: IDP_MEMBER_ROLE })
          } catch (e) {
            if (isUniqueViolation(e)) throw conflict('already_member', 'user already belongs to a merchant')
            throw e
          }
        }),

      removeMember: (organizationId, userId) =>
        run(async () => {
          const m = await orgs.checkMembership({ userId, organizationId })
          if (!m) return false
          await orgs.deleteMember({ memberId: m.id, organizationId, userId })
          return true
        }),

      invite: (organizationId, email, inviterId) =>
        run(async () => {
          const i = await orgs.createInvitation({
            invitation: { organizationId, email: email.toLowerCase(), role: IDP_MEMBER_ROLE, teamIds: [] } as never,
            user: { id: inviterId } as never,
          })
          return invitationOut(i as never)
        }),

      listInvitations: (organizationId) => run(async () => (await orgs.listInvitations({ organizationId })).map((i) => invitationOut(i as never))),

      findInvitation: (id) =>
        run(async () => {
          const i = await orgs.findInvitationById(id)
          return i ? invitationOut(i as never) : null
        }),

      cancelInvitation: (id) => run(async () => !!(await orgs.updateInvitation({ invitationId: id, status: 'canceled', fromStatus: 'pending' } as never))),

      acceptInvitation: (id, callerCredential) =>
        run(async () => {
          try {
            const r = await auth.api.acceptInvitation({ headers: new Headers({ authorization: callerCredential }), body: { invitationId: id } })
            return { organizationId: (r as { member: { organizationId: string } }).member.organizationId }
          } catch (e) {
            if (isUniqueViolation(e)) throw conflict('already_member', 'user already belongs to a merchant')
            if (isAPIError(e)) {
              const code = (e.body as { code?: string } | undefined)?.code
              if (code === 'INVITATION_NOT_FOUND') throw notFound('invitation')
              if (code === 'YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION') throw forbidden('forbidden', 'not the recipient of this invitation')
              throw new AppError(e.statusCode >= 400 && e.statusCode < 500 ? e.statusCode : 500, 'idp_error', e.message)
            }
            throw e
          }
        }),

      attachClient: (clientId, organizationId) =>
        run(async () => {
          await txAdapter.update({ model: 'oauthClient', where: [{ field: 'clientId', value: clientId }], update: { referenceId: organizationId } })
        }),
    }
    return {
      port,
      async afterCommit() {
        for (const h of pending.splice(0)) await h()
      },
    }
  }

  return {
    auth,
    tenancyFor,

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
     *  is recorded as owned by that user); the internal key is what authorizes the call.
     *  Runs on Better Auth's own pool and commits on its own: the OAuth provider writes through
     *  `ctx.context.adapter`, not the transaction-aware adapter lookup. Failure window: if the app's
     *  transaction then rolls back, the client stays, owned by no app/agent row and no organization;
     *  its tokens map to no principal (401). */
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

    /** Only these Better Auth routes are reachable over HTTP (none of the organization plugin's). */
    exposedPaths: ['/api/auth/sign-in/email', '/api/auth/oauth2/token', '/api/auth/jwks', '/api/auth/.well-known/openid-configuration'],
  }
}
export type Identity = ReturnType<typeof makeBetterAuth>

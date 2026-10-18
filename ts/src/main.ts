// Composition root: config → adapters → modules → executor → HTTP. Wired by hand.
import { serve } from '@hono/node-server'
import { sql } from 'drizzle-orm'
import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { z } from 'zod'
import { eq } from 'drizzle-orm'
import { makeBetterAuth, migrateBetterAuth, newInternalKey, API_SCOPE } from './adapters/better-auth.js'
import { makeOpenAuth } from './adapters/openauth.js'
import { makeCerbosAuthorizer } from './adapters/cerbos.js'
import { makeDb, migrateApp } from './db/client.js'
import { appUsers } from './db/schema.js'
import { buildHttp } from './http/routes.js'
import { buildRegistry } from './kernel/action.js'
import { invalid } from './kernel/errors.js'
import { makeExecutor } from './kernel/executor.js'
import { makeAccessResolver } from './modules/access.js'
import { agentActions } from './modules/agents.js'
import { appActions } from './modules/apps.js'
import { catalogActions } from './modules/catalog.js'
import { deliveryActions } from './modules/delivery.js'
import { meActions } from './modules/me.js'
import { merchantActions } from './modules/merchants.js'
import { orderActions } from './modules/orders.js'
import { paymentActions } from './modules/payments.js'
import { platformActions } from './modules/platform.js'
import { makePrincipalResolver } from './modules/principals.js'
import { roleActions } from './modules/roles.js'
import { storeActions } from './modules/stores.js'

const config = z
  .object({
    PORT: z.coerce.number().default(8083),
    DATABASE_URL: z.string(),
    CERBOS_ADDRESS: z.string().default('localhost:3593'),
    AUTH_BASE_URL: z.string().default('http://localhost:8083'),
    /** Identity adapter: Better Auth (stack c) or OpenAuth (stack g). */
    IDENTITY: z.enum(['better-auth', 'openauth']).default('better-auth'),
    AUTH_SECRET: z.string().min(32).optional(),
    /** OpenAuth: the first-party login client and its redirect URIs (comma-separated). */
    AUTH_CLIENT_ID: z.string().default('platform-cli'),
    AUTH_REDIRECT_URIS: z.string().default('http://127.0.0.1/callback'),
    AUTH_ACCESS_TTL: z.coerce.number().int().positive().default(900),
    AUTH_REFRESH_TTL: z.coerce.number().int().positive().default(86_400),
    API_RESOURCE: z.string().default('urn:platform-spike:api'),
    AUTH_RATE_LIMIT: z.enum(['on', 'off']).default('on'),
    AUTH_IP_HEADER: z.string().optional(),
    TEST_MODE: z.string().optional(),
    TEST_SECRET: z.string().optional(),
  })
  .parse(process.env)

// Three pools, so no request can deadlock the app. The executor holds a connection from `pool` for
// the whole transaction, and inside it calls can() (the PIP reads the DB) and, for app/agent
// registration, Better Auth. If those shared `pool`, N concurrent requests holding N connections
// would each wait forever for an (N+1)th. PIP and Better Auth only borrow per query, never across an
// await on another pool, so their pools always drain. The timeout turns any future cycle into errors.
const poolOpts = { connectionString: config.DATABASE_URL, connectionTimeoutMillis: 10_000 }
const pool = new pg.Pool({ ...poolOpts, max: 20 })
const pipPool = new pg.Pool({ ...poolOpts, max: 10 })
const authPool = new pg.Pool({ ...poolOpts, max: 10 })
const db = makeDb(pool)

// Identity adapter (migrates its own tables), then the app's migrations.
async function makeIdentity() {
  if (config.IDENTITY === 'openauth') {
    const authDb = makeDb(authPool)
    return makeOpenAuth(
      {
        pool: authPool,
        baseUrl: config.AUTH_BASE_URL,
        firstPartyClient: config.AUTH_CLIENT_ID,
        redirectUris: config.AUTH_REDIRECT_URIS.split(',').map((x) => x.trim()),
        apiScope: API_SCOPE,
        accessTtlSeconds: config.AUTH_ACCESS_TTL,
        refreshTtlSeconds: config.AUTH_REFRESH_TTL,
      },
      async (email) => (await authDb.select({ id: appUsers.id }).from(appUsers).where(eq(appUsers.email, email)))[0],
    )
  }
  if (!config.AUTH_SECRET) throw new Error('AUTH_SECRET (32+ chars) is required for Better Auth')
  const identityConfig = {
    pool: authPool,
    baseUrl: config.AUTH_BASE_URL,
    secret: config.AUTH_SECRET,
    apiResource: config.API_RESOURCE,
    rateLimit: config.AUTH_RATE_LIMIT === 'on',
    ipHeader: config.AUTH_IP_HEADER,
    internalKey: newInternalKey(),
  }
  await migrateBetterAuth(identityConfig)
  const ba = makeBetterAuth(identityConfig)
  return { ...ba, handler: (req: Request) => ba.auth.handler(req) }
}
const identity = await makeIdentity()
await migrateApp(db, fileURLToPath(new URL('../drizzle', import.meta.url)))

// Adapters
const pip = makeAccessResolver(makeDb(pipPool))
const authz = makeCerbosAuthorizer({ address: config.CERBOS_ADDRESS, pip })
const resolvePrincipal = makePrincipalResolver(db, API_SCOPE)

// Modules → registry → executor
const registry = buildRegistry(
  platformActions(),
  merchantActions(),
  roleActions(),
  storeActions({ authz }),
  catalogActions(),
  orderActions(),
  paymentActions(),
  deliveryActions(),
  appActions({ clients: identity }),
  agentActions({ clients: identity }),
  meActions(),
)
const executor = makeExecutor({ db, authz, registry })

const testMode = config.TEST_MODE === '1' && !!config.TEST_SECRET
const testUserInput = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  kind: z.enum(['platform', 'user', 'customer']),
  platformRole: z.enum(['platform_admin', 'support']).optional(),
})

const app = buildHttp({
  executor,
  async authenticate(header) {
    const cred = await identity.authenticate(header)
    return cred ? resolvePrincipal(cred, header!) : null
  },
  authHandler: identity.handler,
  authPaths: identity.exposedPaths,
  async health() {
    try {
      await db.execute(sql`select 1`)
    } catch {
      return false
    }
    return authz.healthy()
  },
  testUsers: testMode
    ? {
        secret: config.TEST_SECRET!,
        async create(raw) {
          const r = testUserInput.safeParse(raw)
          if (!r.success) throw invalid('invalid_input', r.error.message)
          const i = r.data
          if (i.kind === 'platform' && !i.platformRole) throw invalid('invalid_input', 'platformRole required for platform users')
          const u = await identity.createUser(i.email.toLowerCase(), i.password)
          await db.insert(appUsers).values({ id: u.id, email: u.email, kind: i.kind, platformRole: i.kind === 'platform' ? i.platformRole : null })
          return u
        },
      }
    : undefined,
})

serve({ fetch: app.fetch, port: config.PORT }, (info) => console.log(`app (${config.IDENTITY}) on :${info.port} (${registry.size} actions)`))

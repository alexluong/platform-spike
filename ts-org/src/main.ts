// Composition root: config → adapters → modules → executor → HTTP. Wired by hand.
import { serve } from '@hono/node-server'
import { sql } from 'drizzle-orm'
import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { z } from 'zod'
import { makeBetterAuth, migrateBetterAuth, newInternalKey, API_SCOPE } from './adapters/better-auth.js'
import { makeCerbosAuthorizer } from './adapters/cerbos.js'
import { makeSpiceDbAuthorizer } from './adapters/spicedb/authorizer.js'
import { connect as connectSpiceDb } from './adapters/spicedb/client.js'
import { makeSpiceDbSync } from './adapters/spicedb/sync.js'
import { makeDb, migrateApp, withTransaction } from './db/client.js'
import { appUsers, outbox } from './db/schema.js'
import { buildHttp } from './http/routes.js'
import { buildRegistry } from './kernel/action.js'
import { invalid } from './kernel/errors.js'
import type { Authorizer } from './kernel/authz.js'
import { makeExecutor, type Transact } from './kernel/executor.js'
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
import { makeRelay, type Relay } from './outbox/relay.js'

const config = z
  .object({
    PORT: z.coerce.number().default(8086),
    DATABASE_URL: z.string(),
    // stack d: cerbos; stack e: spicedb (same app, other authz adapter)
    AUTHZ: z.enum(['cerbos', 'spicedb']).default('cerbos'),
    CERBOS_ADDRESS: z.string().default('localhost:3593'),
    SPICEDB_ENDPOINT: z.string().default('localhost:50051'),
    SPICEDB_KEY: z.string().default(''),
    AUTH_BASE_URL: z.string().default('http://localhost:8086'),
    AUTH_SECRET: z.string().min(32),
    API_RESOURCE: z.string().default('urn:platform-spike:api'),
    AUTH_RATE_LIMIT: z.enum(['on', 'off']).default('on'),
    AUTH_IP_HEADER: z.string().optional(),
    TEST_MODE: z.string().optional(),
    TEST_SECRET: z.string().optional(),
  })
  .parse(process.env)

// Three pools, so no request can deadlock the app. The executor holds a connection from `pool` for
// the whole transaction, and inside it calls can() (the PIP reads the DB) and, for app/agent
// registration, Better Auth's OAuth provider. If those shared `pool`, N concurrent requests holding N
// connections would each wait forever for an (N+1)th. PIP and Better Auth only borrow per query,
// never across an await on another pool, so their pools always drain. The timeout turns any future
// cycle into errors. Better Auth's organization writes take no connection at all: they run on the
// request's own transaction connection (identity.tenancyFor).
const poolOpts = { connectionString: config.DATABASE_URL, connectionTimeoutMillis: 10_000 }
const pool = new pg.Pool({ ...poolOpts, max: 20 })
const pipPool = new pg.Pool({ ...poolOpts, max: 10 })
const authPool = new pg.Pool({ ...poolOpts, max: 10 })
const db = makeDb(pool)

// Migrations (idempotent): Better Auth's tables, then ours.
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
await migrateApp(db, fileURLToPath(new URL('../drizzle', import.meta.url)))

// Adapters
const identity = makeBetterAuth(identityConfig)
const pipDb = makeDb(pipPool)
const pip = makeAccessResolver(pipDb)
// Cerbos is stateless (the PIP feeds it per check). SpiceDB stores relationships: the relay applies
// the outbox to it, and checks read the relay's latest ZedToken through the PIP's pool.
let authz: Authorizer & { healthy(): Promise<boolean> }
let relay: Relay | undefined
if (config.AUTHZ === 'spicedb') {
  const client = connectSpiceDb(config.SPICEDB_ENDPOINT, config.SPICEDB_KEY)
  const spicedb = makeSpiceDbAuthorizer({ client, db: pipDb, pip })
  await retry('spicedb schema', () => spicedb.writeSchema())
  authz = spicedb
  relay = makeRelay({ pool, sync: makeSpiceDbSync(client) })
  // System roles live in code: (re)sync them at every start, through the outbox like any change.
  await db.insert(outbox).values({ action: 'system.start', actor: 'system', payload: { events: [{ type: 'system_roles.sync' }] } })
  if (!(await relay.settle(30_000))) throw new Error('outbox relay: could not apply the system roles to SpiceDB')
  relay.start(1000)
} else {
  authz = makeCerbosAuthorizer({ address: config.CERBOS_ADDRESS, pip })
}
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
// The request's transaction: Drizzle and Better Auth's organization adapter on one connection, so a
// merchant/member/invitation change and the app's rows (assignments, outbox) commit together.
// With a relay, a transaction that wrote anything settles the outbox after commit (its own rows
// included) before the response: the next request sees the change (read-your-writes).
const transact: Transact = async (fn) => {
  let after: (() => Promise<void>) | undefined
  let wrote = false
  const out = await withTransaction(pool, async (tx, client) => {
    const t = identity.tenancyFor(client)
    after = t.afterCommit
    const r = await fn(tx, t.port)
    if (relay) wrote = (await client.query<{ w: boolean }>('SELECT pg_current_xact_id_if_assigned() IS NOT NULL AS w')).rows[0]!.w
    return r
  })
  await after?.()
  if (wrote) await settle()
  return out
}
async function settle() {
  if (relay && !(await relay.settle(5_000))) console.error('outbox relay: own rows not applied within 5 s; the background relay keeps retrying')
}
const executor = makeExecutor({ db, transact, authz, registry })

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
  authHandler: (req) => identity.auth.handler(req),
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
          await db.transaction(async (tx) => {
            await tx.insert(appUsers).values({ id: u.id, email: u.email, kind: i.kind, platformRole: i.kind === 'platform' ? i.platformRole : null })
            // platform roles are relationships in SpiceDB (Cerbos reads app_users per check)
            if (relay && i.kind === 'platform')
              await tx.insert(outbox).values({ action: 'test.users.create', actor: 'system', payload: { events: [{ type: 'platform_role.granted', userId: u.id }] } })
          })
          if (relay && i.kind === 'platform') await settle()
          return u
        },
      }
    : undefined,
})

serve({ fetch: app.fetch, port: config.PORT }, (info) => console.log(`app (${config.AUTHZ}) on :${info.port} (${registry.size} actions)`))

async function retry(what: string, fn: () => Promise<unknown>, tries = 60) {
  for (let n = 1; ; n++) {
    try {
      return await fn()
    } catch (err) {
      if (n >= tries) throw err
      console.warn(`${what}: ${err instanceof Error ? err.message : err} (retrying)`)
      await new Promise((r) => setTimeout(r, 1000))
    }
  }
}

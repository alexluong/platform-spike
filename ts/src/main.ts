// Composition root: config → adapters → modules → executor → HTTP. Wired by hand.
import { serve } from '@hono/node-server'
import { sql } from 'drizzle-orm'
import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { z } from 'zod'
import { makeBetterAuth, API_SCOPE } from './adapters/better-auth.js'
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
    AUTH_SECRET: z.string().min(32),
    API_RESOURCE: z.string().default('urn:platform-spike:api'),
    TEST_MODE: z.string().optional(),
    TEST_SECRET: z.string().optional(),
  })
  .parse(process.env)

const pool = new pg.Pool({ connectionString: config.DATABASE_URL, max: 20 })
const db = makeDb(pool)

// Adapters
const identity = makeBetterAuth({ pool, baseUrl: config.AUTH_BASE_URL, secret: config.AUTH_SECRET, apiResource: config.API_RESOURCE })
const pip = makeAccessResolver(db)
const authz = makeCerbosAuthorizer({ address: config.CERBOS_ADDRESS, pip })
const resolvePrincipal = makePrincipalResolver(db, API_SCOPE)

// Migrations (idempotent): Better Auth's tables, then ours.
await identity.migrate()
await migrateApp(db, fileURLToPath(new URL('../drizzle', import.meta.url)))

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
          await db.insert(appUsers).values({ id: u.id, email: u.email, kind: i.kind, platformRole: i.kind === 'platform' ? i.platformRole : null })
          return u
        },
      }
    : undefined,
})

serve({ fetch: app.fetch, port: config.PORT }, (info) => console.log(`stack c app on :${info.port} (${registry.size} actions)`))

// HTTP adapter: thin handlers that turn a request into (actionId, principal, input).
import { Hono, type Context } from 'hono'
import type { ContentfulStatusCode } from 'hono/utils/http-status'
import { AppError } from '../kernel/errors.js'
import type { Executor } from '../kernel/executor.js'
import type { Principal } from '../kernel/principal.js'

export interface HttpDeps {
  executor: Executor
  authenticate(authorization: string | undefined): Promise<Principal | null>
  /** Better Auth's handler, for the allow-listed paths only. */
  authHandler: (req: Request) => Promise<Response>
  authPaths: readonly string[]
  health(): Promise<boolean>
  testUsers?: {
    secret: string
    create(input: { email: string; password: string; kind: string; platformRole?: string }): Promise<{ id: string; email: string }>
  }
}

type Env = { Variables: { principal: Principal | null } }

export function buildHttp(deps: HttpDeps) {
  const app = new Hono<Env>()

  app.onError((err, c) => {
    if (err instanceof AppError) {
      return c.json({ error: { code: err.code, message: err.message } }, err.status as ContentfulStatusCode)
    }
    console.error(err)
    return c.json({ error: { code: 'internal', message: 'internal error' } }, 500)
  })
  app.notFound((c) => c.json({ error: { code: 'not_found' } }, 404))

  app.get('/healthz', async (c) => ((await deps.health()) ? c.json({ ok: true }) : c.json({ ok: false }, 503)))

  for (const p of deps.authPaths) app.all(p, (c) => deps.authHandler(c.req.raw))

  if (deps.testUsers) {
    const t = deps.testUsers
    app.post('/api/_test/users', async (c) => {
      if (c.req.header('x-test-secret') !== t.secret) return c.json({ error: { code: 'forbidden' } }, 403)
      const body = await jsonBody(c)
      return c.json(await t.create(body as never), 201)
    })
  }

  app.use('/api/*', async (c, next) => {
    c.set('principal', await deps.authenticate(c.req.header('authorization')))
    await next()
  })

  /** Route helper: `status` is the success code; input = JSON body + query + path params. */
  const act =
    (actionId: string, status: 200 | 201 | 204 = 200) =>
    async (c: Context<Env>) => {
      const body = c.req.method === 'GET' || c.req.method === 'DELETE' ? {} : await jsonBody(c)
      const input = { ...body, ...c.req.query(), ...params(c) }
      const out = await deps.executor.execute(actionId, c.get('principal'), input)
      if (status === 204) return c.body(null, 204)
      return c.json(out as object, status)
    }

  // Platform
  app.post('/api/platform/merchants', act('platform.merchant.create', 201))
  app.get('/api/platform/merchants', act('platform.merchant.view'))
  app.post('/api/platform/merchants/:merchantId/suspend', act('platform.merchant.suspend'))
  app.post('/api/platform/merchants/:merchantId/reinstate', act('platform.merchant.reinstate'))
  app.post('/api/platform/apps', act('platform.app.register', 201))
  app.post('/api/platform/break-glass', act('platform.break_glass', 201))
  app.get('/api/platform/audit', act('platform.audit.view'))

  // Merchant
  app.get('/api/merchants/:merchantId', act('merchant.view'))
  app.post('/api/merchants/:merchantId/members', act('member.add', 201))
  app.delete('/api/merchants/:merchantId/members/:userId', act('member.remove', 204))
  app.get('/api/merchants/:merchantId/roles', act('role.list'))
  app.post('/api/merchants/:merchantId/roles', act('role.create', 201))
  app.patch('/api/merchants/:merchantId/roles/:roleId', act('role.update'))
  app.delete('/api/merchants/:merchantId/roles/:roleId', act('role.delete', 204))
  app.post('/api/merchants/:merchantId/role-assignments', act('role.assign', 201))
  app.delete('/api/merchants/:merchantId/role-assignments/:assignmentId', act('role.unassign', 204))
  app.post('/api/merchants/:merchantId/invitations', act('invitation.create', 201))
  app.get('/api/merchants/:merchantId/invitations', act('invitation.list'))
  app.delete('/api/merchants/:merchantId/invitations/:invitationId', act('invitation.cancel', 204))
  app.post('/api/invitations/:invitationId/accept', act('invitation.accept'))
  app.post('/api/merchants/:merchantId/stores', act('store.create', 201))
  app.get('/api/merchants/:merchantId/stores', act('store.list'))

  // Store modules
  app.get('/api/stores/:storeId', act('store.view'))
  app.post('/api/stores/:storeId/products', act('product.create', 201))
  app.patch('/api/products/:productId', act('product.update'))
  app.get('/api/stores/:storeId/products', act('product.list_public'))
  app.post('/api/stores/:storeId/orders', act('order.place', 201))
  app.get('/api/stores/:storeId/orders', act('order.list'))
  app.get('/api/orders/:orderId', act('order.view'))
  app.get('/api/me/orders', act('order.view_own'))
  app.post('/api/orders/:orderId/cancel', act('order.cancel'))
  app.post('/api/orders/:orderId/refund', act('order.refund'))
  app.post('/api/orders/:orderId/payments/capture', act('payment.capture', 201))
  app.get('/api/orders/:orderId/payments', act('payment.view'))
  app.post('/api/orders/:orderId/shipments', act('shipment.create', 201))
  app.post('/api/shipments/:shipmentId/status', act('shipment.update'))
  app.get('/api/orders/:orderId/shipments', act('shipment.view'))
  app.post('/api/stores/:storeId/apps', act('app.install', 201))
  app.delete('/api/stores/:storeId/apps/:installId', act('app.uninstall', 204))
  app.get('/api/stores/:storeId/apps', act('app.view'))
  app.post('/api/agents', act('agent.register', 201))
  app.post('/api/stores/:storeId/agent-grants', act('agent.grant', 201))
  app.delete('/api/stores/:storeId/agent-grants/:grantId', act('agent.revoke', 204))

  // Me
  app.get('/api/me', act('me.view'))
  app.get('/api/me/permissions', act('me.permissions'))

  return app
}

async function jsonBody(c: Context): Promise<Record<string, unknown>> {
  const b = await c.req.json().catch(() => ({}))
  return b && typeof b === 'object' && !Array.isArray(b) ? (b as Record<string, unknown>) : {}
}

const params = (c: Context) => c.req.param() as Record<string, string>

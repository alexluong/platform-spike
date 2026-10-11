// Fixtures: every test builds its own world through the real API (no reset exists; SPEC §9).
// Names and emails are unique per run and per worker, so files and tests run in parallel safely.
import { randomBytes } from 'node:crypto'
import { Api, ok } from './client'
import { env } from './env'
import { getDriver } from './stack'
import type {
  BreakGlass,
  ClientCreds,
  Grant,
  Install,
  Merchant,
  Order,
  Payment,
  Product,
  Role,
  Scope,
  Shipment,
  Store,
  Assignment,
} from './types'

const runId = `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`
let seq = 0
export function uniq(prefix = 'x'): string {
  return `${prefix}-${runId}-${process.pid}-${++seq}`
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export const driver = getDriver()
/** Unauthenticated client. */
export const anon = new Api(driver.baseUrl)

// ---------- principals ----------

export interface Actor {
  id: string
  email: string
  password: string
  kind: 'platform' | 'user' | 'customer'
  token: string
  api: Api
}

export interface ClientActor {
  creds: ClientCreds
  token: string
  api: Api
}

export type PlatformRole = 'platform_admin' | 'support'

/** Create an identity via `/api/_test/users` and log it in through the stack's real login path. */
export async function newUser(kind: Actor['kind'], opts: { platformRole?: PlatformRole; label?: string } = {}): Promise<Actor> {
  const label = opts.label ?? kind
  const email = `${uniq(label)}@example.com`.toLowerCase()
  const password = `Cf-${randomBytes(8).toString('hex')}-Aa1!`
  const body: Record<string, unknown> = { email, password, kind }
  if (opts.platformRole) body.platformRole = opts.platformRole
  const u = ok(await anon.post<{ id: string; email: string }>('/api/_test/users', body, { 'x-test-secret': env.testSecret }), 201)
  const token = await driver.loginUser(email, password)
  return { id: String(u.id), email, password, kind, token, api: anon.as(token, label) }
}

let adminP: Promise<Actor> | undefined
/** One platform admin per test file (platform admins are global; sharing is safe). */
export function platformAdmin(): Promise<Actor> {
  adminP ??= newUser('platform', { platformRole: 'platform_admin', label: 'padmin' })
  return adminP
}

export function newSupport(): Promise<Actor> {
  return newUser('platform', { platformRole: 'support', label: 'support' })
}

export function newCustomer(label = 'customer'): Promise<Actor> {
  return newUser('customer', { label })
}

export async function clientActor(creds: ClientCreds, label: string): Promise<ClientActor> {
  const token = await driver.loginClient(creds.clientId, creds.clientSecret)
  return { creds, token, api: anon.as(token, label) }
}

// ---------- apps & agents ----------

export async function registerApp(scopes: string[]): Promise<ClientCreds> {
  const admin = await platformAdmin()
  return ok(await admin.api.post<ClientCreds>('/api/platform/apps', { name: uniq('app'), scopes }), 201)
}

export async function installApp(by: Actor, storeId: string, appId: string, scopes: string[]): Promise<Install> {
  return ok(await by.api.post<Install>(`/api/stores/${storeId}/apps`, { appId, scopes }), 201)
}

/** Register an app with `scopes`, install it on `storeId` with the same scopes, and log it in. */
export async function installedApp(by: Actor, storeId: string, scopes: string[]): Promise<ClientActor & { install: Install }> {
  const creds = await registerApp(scopes)
  const install = await installApp(by, storeId, creds.id, scopes)
  return { ...(await clientActor(creds, 'app')), install }
}

export async function registerAgent(by: Actor): Promise<ClientCreds> {
  return ok(await by.api.post<ClientCreds>('/api/agents', { name: uniq('agent') }), 201)
}

export async function grantAgent(by: Actor, storeId: string, agentId: string, permissions: string[], expiresInSeconds = 600): Promise<Grant> {
  return ok(await by.api.post<Grant>(`/api/stores/${storeId}/agent-grants`, { agentId, permissions, expiresInSeconds }), 201)
}

/** Agent registered by `by`, granted `permissions` on `storeId`, logged in. */
export async function grantedAgent(by: Actor, storeId: string, permissions: string[], expiresInSeconds = 600): Promise<ClientActor & { grant: Grant }> {
  const creds = await registerAgent(by)
  const grant = await grantAgent(by, storeId, creds.id, permissions, expiresInSeconds)
  return { ...(await clientActor(creds, 'agent')), grant }
}

export async function openBreakGlass(by: Actor, merchantId: string, minutes = 10): Promise<BreakGlass> {
  return ok(await by.api.post<BreakGlass>('/api/platform/break-glass', { merchantId, reason: 'conformance test', minutes }), 201)
}

// ---------- merchant world ----------

export const merchantScope = (m: { id: string }): Scope => ({ type: 'merchant', id: m.id })
export const storeScope = (s: { id: string }): Scope => ({ type: 'store', id: s.id })

export class MerchantWorld {
  private customerP?: Promise<Actor>
  constructor(
    readonly id: string,
    readonly name: string,
    readonly owner: Actor,
  ) {}

  get scope(): Scope {
    return merchantScope(this)
  }

  async store(by: Actor = this.owner): Promise<Store> {
    return ok(await by.api.post<Store>(`/api/merchants/${this.id}/stores`, { name: uniq('store') }), 201)
  }

  /** New user, added as a member with no roles. */
  async member(label = 'member'): Promise<Actor> {
    const u = await newUser('user', { label })
    ok(await this.owner.api.post(`/api/merchants/${this.id}/members`, { userId: u.id }), 201)
    return u
  }

  async role(permissions: string[], refundLimitCents?: number, by: Actor = this.owner): Promise<Role> {
    const body: Record<string, unknown> = { name: uniq('role'), permissions }
    if (refundLimitCents !== undefined) body.refundLimitCents = refundLimitCents
    return ok(await by.api.post<Role>(`/api/merchants/${this.id}/roles`, body), 201)
  }

  async assign(user: { id: string }, roleId: string, scope: Scope = this.scope, by: Actor = this.owner): Promise<Assignment> {
    return ok(await by.api.post<Assignment>(`/api/merchants/${this.id}/role-assignments`, { userId: user.id, roleId, scope }), 201)
  }

  /** New member holding `roleId` (system or custom) at `scope`. */
  async memberWithRole(roleId: string, scope: Scope = this.scope, label = roleId): Promise<Actor & { assignment: Assignment }> {
    const u = await this.member(label)
    const assignment = await this.assign(u, roleId, scope)
    return { ...u, assignment }
  }

  /** New member holding a fresh custom role with `permissions` at `scope`. */
  async memberWithPerms(
    permissions: string[],
    scope: Scope = this.scope,
    opts: { refundLimitCents?: number; label?: string } = {},
  ): Promise<Actor & { role: Role; assignment: Assignment }> {
    const role = await this.role(permissions, opts.refundLimitCents)
    const u = await this.memberWithRole(role.id, scope, opts.label ?? 'custom')
    return { ...u, role }
  }

  async product(storeId: string, priceCents = 1000, by: Actor = this.owner): Promise<Product> {
    return ok(await by.api.post<Product>(`/api/stores/${storeId}/products`, { title: uniq('product'), priceCents }), 201)
  }

  /** A shared customer for this merchant world (customers are global identities; SPEC §2). */
  customer(): Promise<Actor> {
    this.customerP ??= newCustomer()
    return this.customerP
  }

  /** Pending order for one product priced `totalCents`. */
  async order(storeId: string, totalCents = 1000, customer?: Actor): Promise<Order> {
    const c = customer ?? (await this.customer())
    const p = await this.product(storeId, totalCents)
    return ok(await c.api.post<Order>(`/api/stores/${storeId}/orders`, { items: [{ productId: p.id, qty: 1 }] }), 201)
  }

  async getOrder(orderId: string): Promise<Order> {
    return ok(await this.owner.api.get<Order>(`/api/orders/${orderId}`), 200)
  }

  async capture(orderId: string): Promise<Payment> {
    return ok(await this.owner.api.post<Payment>(`/api/orders/${orderId}/payments/capture`), 201)
  }

  async paidOrder(storeId: string, totalCents = 1000, customer?: Actor): Promise<Order> {
    const o = await this.order(storeId, totalCents, customer)
    await this.capture(o.id)
    return this.getOrder(o.id)
  }

  async ship(orderId: string): Promise<Shipment> {
    return ok(await this.owner.api.post<Shipment>(`/api/orders/${orderId}/shipments`, { carrier: 'ups' }), 201)
  }

  async setShipmentStatus(shipmentId: string, status: Shipment['status']): Promise<Shipment> {
    return ok(await this.owner.api.post<Shipment>(`/api/shipments/${shipmentId}/status`, { status }))
  }

  async suspend(): Promise<void> {
    const admin = await platformAdmin()
    ok(await admin.api.post(`/api/platform/merchants/${this.id}/suspend`), 200)
  }

  async reinstate(): Promise<void> {
    const admin = await platformAdmin()
    ok(await admin.api.post(`/api/platform/merchants/${this.id}/reinstate`), 200)
  }
}

/** Fresh merchant (created by the platform admin) with a fresh owner. */
export async function newMerchant(): Promise<MerchantWorld> {
  const [admin, owner] = await Promise.all([platformAdmin(), newUser('user', { label: 'owner' })])
  const m = ok(await admin.api.post<Merchant>('/api/platform/merchants', { name: uniq('merchant'), ownerUserId: owner.id }), 201)
  return new MerchantWorld(String(m.id), m.name, owner)
}

/** Merchant + one store, the most common starting point. */
export async function merchantWithStore(): Promise<{ m: MerchantWorld; s: Store }> {
  const m = await newMerchant()
  const s = await m.store()
  return { m, s }
}

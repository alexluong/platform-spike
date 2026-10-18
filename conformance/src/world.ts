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
  Invitation,
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
  Identity,
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

export const newEmail = (label: string) => `${uniq(label)}@example.com`.toLowerCase()
export const newPassword = () => `Cf-${randomBytes(8).toString('hex')}-Aa1!`

/** Create an identity via `/api/_test/users` and log it in through the stack's real login path. */
export async function newUser(
  kind: Actor['kind'],
  opts: { platformRole?: PlatformRole; label?: string; email?: string; password?: string } = {},
): Promise<Actor> {
  const label = opts.label ?? kind
  const email = opts.email ?? newEmail(label)
  const password = opts.password ?? newPassword()
  const body: Record<string, unknown> = { email, password, kind }
  if (opts.platformRole) body.platformRole = opts.platformRole
  const u = ok(await anon.post<{ id: string; email: string }>('/api/_test/users', body, { 'x-test-secret': env.testSecret }), 201)
  const token = await driver.loginUser(email, password)
  return { id: String(u.id), email, password, kind, token, api: anon.as(token, label) }
}

/** Log `who` in again with its password (fresh token; the driver throws when the IdP refuses). */
export function relogin(who: Pick<Actor, 'email' | 'password'>): Promise<string> {
  return driver.loginUser(who.email, who.password)
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

  /** Invite `email` (SPEC §15.2; `idp-tenancy` stacks only). */
  async invite(email: string, by: Actor = this.owner): Promise<Invitation> {
    return ok(await by.api.post<Invitation>(`/api/merchants/${this.id}/invitations`, { email }), 201)
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

// ---------- round 4: multi-pool (SPEC §16; `multi-pool` stacks only) ----------

export const multiPool = driver.features?.includes('multi-pool') ?? false

/** A merchant's tenant-pool identity (SPEC §16.4): `user` = its staff, `customer` = its customer. */
export interface TenantActor extends Actor {
  kind: 'user' | 'customer'
  merchantId: string
}

function needDriver<K extends 'loginTenant' | 'loginWithShop'>(method: K): NonNullable<(typeof driver)[K]> {
  const fn = driver[method]
  if (!fn) throw new Error(`driver declares multi-pool but has no ${method} (SPEC §16.4)`)
  return fn.bind(driver) as NonNullable<(typeof driver)[K]>
}

/** Tenant-pool login through the driver (rejects when the pool refuses). */
export function loginTenant(merchantId: string, kind: TenantActor['kind'], email: string, password: string): Promise<string> {
  return needDriver('loginTenant')(merchantId, kind, email, password)
}

export function reloginTenant(who: Pick<TenantActor, 'merchantId' | 'kind' | 'email' | 'password'>): Promise<string> {
  return loginTenant(who.merchantId, who.kind, who.email, who.password)
}

/** "Sign in with Shop" at `merchantId` (SPEC §16.5): a token issued by the merchant's tenant pool. */
export function loginWithShop(merchantId: string, buyer: Pick<Actor, 'email' | 'password'>): Promise<string> {
  return needDriver('loginWithShop')(merchantId, buyer.email, buyer.password)
}

/** `POST /api/_test/merchants/:mid/users` only (no login). */
export async function createTenantUser(
  merchantId: string,
  kind: TenantActor['kind'],
  opts: { email?: string; password?: string; label?: string } = {},
): Promise<{ id: string; email: string; password: string }> {
  const email = opts.email ?? newEmail(opts.label ?? `t-${kind}`)
  const password = opts.password ?? newPassword()
  const u = ok(
    await anon.post<{ id: string; email: string }>(`/api/_test/merchants/${merchantId}/users`, { email, password, kind }, { 'x-test-secret': env.testSecret }),
    201,
  )
  return { id: String(u.id), email, password }
}

/** Identity in `merchantId`'s tenant pool, logged in there (SPEC §16.4). Staff start as members with no roles. */
export async function newTenantUser(
  merchantId: string,
  kind: TenantActor['kind'],
  opts: { email?: string; password?: string; label?: string } = {},
): Promise<TenantActor> {
  const label = opts.label ?? (kind === 'user' ? 'tstaff' : 'tcustomer')
  const u = await createTenantUser(merchantId, kind, { ...opts, label })
  const token = await loginTenant(merchantId, kind, u.email, u.password)
  return { ...u, kind, merchantId, token, api: anon.as(token, label) }
}

/** `GET /api/merchants/:mid/identity` (no auth) → the tenant issuer (SPEC §16.3). */
export async function tenantIssuer(merchantId: string): Promise<string> {
  const body = ok(await anon.get<Identity>(`/api/merchants/${merchantId}/identity`), 200)
  if (typeof body?.issuer !== 'string' || body.issuer.length === 0) throw new Error(`GET /api/merchants/${merchantId}/identity: no issuer in ${JSON.stringify(body)}`)
  return normIssuer(body.issuer)
}

/** Issuers compare without a trailing slash (`https://x/` and `https://x` are the same issuer). */
export const normIssuer = (iss: string) => iss.replace(/\/+$/, '')

/**
 * Poll `GET /api/merchants/:mid` as the owner until `status: "active"` (SPEC §16.3: within 60 s).
 * Returns the milliseconds it took.
 */
export async function waitActive(m: { id: string; owner: Actor }, timeoutMs = 60_000): Promise<number> {
  const start = Date.now()
  let last = ''
  for (;;) {
    const r = await m.owner.api.get<Merchant>(`/api/merchants/${m.id}`)
    if (r.status === 200 && r.body?.status === 'active') return Date.now() - start
    last = `${r.status} ${r.text.slice(0, 200)}`
    if (Date.now() - start > timeoutMs) throw new Error(`merchant ${m.id} not active after ${timeoutMs} ms (last GET /api/merchants/${m.id}: ${last})`)
    await sleep(500)
  }
}

/** Fresh merchant whose tenant pool is ready (status `active`). */
export async function newActiveMerchant(): Promise<MerchantWorld> {
  const m = await newMerchant()
  await waitActive(m)
  return m
}

/** The `iss` claim (normalized) when `token` is a JWT; `undefined` for opaque tokens. Not verified. */
export function jwtIssuer(token: string): string | undefined {
  const parts = token.split('.')
  if (parts.length !== 3) return undefined
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as { iss?: unknown }
    return typeof payload.iss === 'string' ? normIssuer(payload.iss) : undefined
  } catch {
    return undefined
  }
}

// App tables (source of truth for roles, assignments, installs, grants). Better Auth owns its own
// tables (user, session, account, jwks, oauth*, and with the organization plugin organization, member,
// invitation) and migrates them itself. Merchants and members are Better Auth's organizations and
// members (SPEC §15.1): read-only mirrors in idp-tables.ts; the FKs to "organization" are in a
// hand-written migration (drizzle/0001_idp_links.sql) so drizzle-kit never tries to create that table.
import { sql } from 'drizzle-orm'
import { index, integer, jsonb, pgTable, text, timestamp, uniqueIndex, bigserial } from 'drizzle-orm/pg-core'

/** Money columns are Postgres `integer`: inputs above this would fail the insert (500). */
export const MAX_CENTS = 2_147_483_647

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' })

/** App-side record for an identity in Better Auth (`id` = Better Auth user id). */
export const appUsers = pgTable('app_users', {
  id: text('id').primaryKey(),
  email: text('email').notNull(),
  kind: text('kind').$type<'platform' | 'user' | 'customer'>().notNull(),
  platformRole: text('platform_role').$type<'platform_admin' | 'support'>(),
  createdAt: ts('created_at').notNull().defaultNow(),
})

/** Custom roles only; system roles live in code. */
export const roles = pgTable(
  'roles',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    name: text('name').notNull(),
    permissions: jsonb('permissions').$type<string[]>().notNull(),
    refundLimitCents: integer('refund_limit_cents'),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('roles_merchant').on(t.merchantId)],
)

export const roleAssignments = pgTable(
  'role_assignments',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    userId: text('user_id').notNull(),
    /** system role id ("owner") or custom role id; custom rows cascade via app code */
    roleId: text('role_id').notNull(),
    scopeType: text('scope_type').$type<'merchant' | 'store'>().notNull(),
    scopeId: text('scope_id').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('ra_user').on(t.userId), index('ra_role').on(t.roleId), index('ra_merchant').on(t.merchantId)],
)

export const stores = pgTable(
  'stores',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    name: text('name').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('stores_merchant').on(t.merchantId)],
)

export const products = pgTable(
  'products',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    storeId: text('store_id')
      .notNull()
      .references(() => stores.id),
    title: text('title').notNull(),
    priceCents: integer('price_cents').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('products_store').on(t.storeId)],
)

export type OrderItem = { productId: string; qty: number; unitPriceCents: number }
export type OrderStatus = 'pending' | 'paid' | 'fulfilling' | 'delivered' | 'cancelled'

export const orders = pgTable(
  'orders',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    storeId: text('store_id')
      .notNull()
      .references(() => stores.id),
    customerId: text('customer_id').notNull(),
    items: jsonb('items').$type<OrderItem[]>().notNull(),
    totalCents: integer('total_cents').notNull(),
    status: text('status').$type<OrderStatus>().notNull(),
    refundedCents: integer('refunded_cents').notNull().default(0),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('orders_store').on(t.storeId), index('orders_customer').on(t.customerId)],
)

export const payments = pgTable(
  'payments',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    orderId: text('order_id')
      .notNull()
      .references(() => orders.id),
    status: text('status').$type<'captured' | 'refunded'>().notNull(),
    amountCents: integer('amount_cents').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('payments_order').on(t.orderId)],
)

export type ShipmentStatus = 'label_created' | 'in_transit' | 'delivered'
export const shipments = pgTable(
  'shipments',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    storeId: text('store_id').notNull(),
    orderId: text('order_id')
      .notNull()
      .references(() => orders.id),
    carrier: text('carrier').notNull(),
    status: text('status').$type<ShipmentStatus>().notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('shipments_order').on(t.orderId)],
)

export const apps = pgTable(
  'apps',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    requestedScopes: jsonb('requested_scopes').$type<string[]>().notNull(),
    clientId: text('client_id').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [uniqueIndex('apps_client').on(t.clientId)],
)

export const appInstalls = pgTable(
  'app_installs',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    storeId: text('store_id')
      .notNull()
      .references(() => stores.id),
    appId: text('app_id')
      .notNull()
      .references(() => apps.id),
    scopes: jsonb('scopes').$type<string[]>().notNull(),
    installedBy: text('installed_by').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('installs_app').on(t.appId), index('installs_store').on(t.storeId)],
)

export const agents = pgTable(
  'agents',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    createdBy: text('created_by').notNull(),
    name: text('name').notNull(),
    clientId: text('client_id').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [uniqueIndex('agents_client').on(t.clientId)],
)

export const agentGrants = pgTable(
  'agent_grants',
  {
    id: text('id').primaryKey(),
    merchantId: text('merchant_id').notNull(),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id),
    storeId: text('store_id')
      .notNull()
      .references(() => stores.id),
    grantedBy: text('granted_by').notNull(),
    permissions: jsonb('permissions').$type<string[]>().notNull(),
    expiresAt: ts('expires_at').notNull(),
    revokedAt: ts('revoked_at'),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('grants_agent').on(t.agentId)],
)

export const breakGlass = pgTable(
  'break_glass',
  {
    id: text('id').primaryKey(),
    actor: text('actor').notNull(),
    merchantId: text('merchant_id').notNull(),
    reason: text('reason').notNull(),
    expiresAt: ts('expires_at').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('bg_actor').on(t.actor)],
)

export const audit = pgTable(
  'audit',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    actor: text('actor').notNull(),
    action: text('action').notNull(),
    merchantId: text('merchant_id'),
    at: ts('at').notNull().defaultNow(),
  },
  (t) => [index('audit_merchant').on(t.merchantId)],
)

/** Events written in the same transaction as the change (SPEC §1.1). Stack d (Cerbos, stateless)
 *  has no consumer; stack e's relay (outbox/relay.ts) applies them to SpiceDB and records delivery
 *  in the last three columns. */
export const outbox = pgTable(
  'outbox',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    action: text('action').notNull(),
    actor: text('actor').notNull(),
    payload: jsonb('payload').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
    processedAt: ts('processed_at'),
    attempts: integer('attempts').notNull().default(0),
    lastError: text('last_error'),
  },
  (t) => [index('outbox_pending').on(t.id).where(sql`processed_at IS NULL`)],
)

/** The engine's consistency token after the relay's latest write (SpiceDB ZedToken), one row. In the
 *  DB rather than in process memory so read-your-writes holds across app instances (SPEC §1). */
export const authzConsistency = pgTable('authz_consistency', {
  id: integer('id').primaryKey(),
  token: text('token').notNull(),
  updatedAt: ts('updated_at').notNull().defaultNow(),
})

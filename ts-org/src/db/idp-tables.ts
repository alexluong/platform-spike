// Read-only Drizzle mirrors of Better Auth's organization-plugin tables (SPEC §15.1: the IdP owns
// merchants' identity side). Better Auth creates and writes these tables; the app only reads them in
// SQL (tenant scoping, the PIP, the last-owner lock) and writes them through the IdP port
// (kernel/tenancy.ts), so there is one writer. Column names are Better Auth's (camelCase, quoted).
// Not part of drizzle.config.ts's schema: drizzle-kit must never generate DDL for them.
import { pgTable, text, timestamp } from 'drizzle-orm/pg-core'

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' })

/** organization = merchant. `status` is an additionalField of the plugin (login policy reads it). */
export const organization = pgTable('organization', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  slug: text('slug').notNull(),
  status: text('status').$type<'active' | 'suspended'>(),
  createdAt: ts('createdAt').notNull(),
})

/** member = a user in a merchant. One per user (unique index in drizzle/0001_idp_links.sql). `role`
 *  is always "member": roles live in the app (role_assignments), never in the IdP. */
export const member = pgTable('member', {
  id: text('id').primaryKey(),
  organizationId: text('organizationId').notNull(),
  userId: text('userId').notNull(),
  role: text('role').notNull(),
  createdAt: ts('createdAt').notNull(),
})

export const invitation = pgTable('invitation', {
  id: text('id').primaryKey(),
  organizationId: text('organizationId').notNull(),
  email: text('email').notNull(),
  role: text('role'),
  status: text('status').notNull(),
  expiresAt: ts('expiresAt').notNull(),
  inviterId: text('inviterId').notNull(),
})

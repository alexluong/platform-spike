// Permission catalog (SPEC §4) and system roles (SPEC §3). The platform owns these; merchants
// compose custom roles from GRANTABLE only.

export const GRANTABLE = [
  'merchant.view',
  'merchant.update',
  'member.manage',
  'role.manage',
  'store.create',
  'store.view',
  'product.create',
  'product.update',
  'product.view',
  'order.view',
  'order.cancel',
  'order.refund',
  'payment.capture',
  'payment.view',
  'shipment.create',
  'shipment.update',
  'shipment.view',
  'app.install',
  'app.uninstall',
  'app.view',
  'agent.grant',
] as const
export type Permission = (typeof GRANTABLE)[number]

export const PLATFORM_ACTIONS = [
  'platform.merchant.create',
  'platform.merchant.view',
  'platform.merchant.suspend',
  'platform.break_glass',
  'platform.audit.view',
] as const

export const CATALOG = [...PLATFORM_ACTIONS, ...GRANTABLE] as const
export type CatalogAction = (typeof CATALOG)[number]

/** Actions whose check runs against a store (SPEC §4 "scope"). role.manage may run at either. */
export const STORE_ACTIONS: readonly Permission[] = [
  'role.manage',
  'store.view',
  'product.create',
  'product.update',
  'product.view',
  'order.view',
  'order.cancel',
  'order.refund',
  'payment.capture',
  'payment.view',
  'shipment.create',
  'shipment.update',
  'shipment.view',
  'app.install',
  'app.uninstall',
  'app.view',
  'agent.grant',
]

/** Apps never get these, even if requested (SPEC §5). */
export const NEVER_FOR_APPS: readonly Permission[] = ['role.manage', 'member.manage', 'agent.grant', 'app.install', 'app.uninstall']

export const isGrantable = (a: string): a is Permission => (GRANTABLE as readonly string[]).includes(a)

export interface SystemRole {
  id: string
  name: string
  permissions: readonly Permission[]
}

export const SYSTEM_ROLES: readonly SystemRole[] = [
  { id: 'owner', name: 'Owner', permissions: GRANTABLE },
  { id: 'admin', name: 'Admin', permissions: GRANTABLE },
  {
    id: 'developer',
    name: 'Developer',
    permissions: ['merchant.view', 'store.view', 'product.view', 'order.view', 'app.install', 'app.uninstall', 'app.view'],
  },
  {
    id: 'staff',
    name: 'Staff',
    permissions: [
      'merchant.view',
      'store.view',
      'product.view',
      'product.create',
      'product.update',
      'order.view',
      'order.cancel',
      'shipment.view',
      'shipment.create',
      'shipment.update',
    ],
  },
]

export const systemRole = (id: string) => SYSTEM_ROLES.find((r) => r.id === id)

/** Refund limit sentinel meaning "no limit" (also what the guardrail asks for when a role has no limit). */
export const UNLIMITED = Number.MAX_SAFE_INTEGER

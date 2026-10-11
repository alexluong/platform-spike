// SPEC §3 and §4, as data. Tests derive expectations from these tables.

export const PLATFORM_ACTIONS = [
  'platform.merchant.create',
  'platform.merchant.view',
  'platform.merchant.suspend',
  'platform.break_glass',
  'platform.audit.view',
] as const

/** Grantable actions checked against the merchant resource (§4 scope = merchant, or "merchant or store"). */
export const MERCHANT_SCOPE_ACTIONS = ['merchant.view', 'merchant.update', 'member.manage', 'role.manage', 'store.create'] as const

/** Grantable actions checked against a store (§4 scope = store, or "merchant or store"). */
export const STORE_SCOPE_ACTIONS = [
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
] as const

export const GRANTABLE: readonly string[] = [...new Set<string>([...MERCHANT_SCOPE_ACTIONS, ...STORE_SCOPE_ACTIONS])]

export const SYSTEM_ROLES: Record<'owner' | 'admin' | 'developer' | 'staff', readonly string[]> = {
  owner: GRANTABLE,
  admin: GRANTABLE,
  developer: ['merchant.view', 'store.view', 'product.view', 'order.view', 'app.install', 'app.uninstall', 'app.view'],
  staff: [
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
}

/** §5: never grantable to apps, even if requested. */
export const FORBIDDEN_APP_SCOPES = ['role.manage', 'member.manage', 'agent.grant', 'app.install', 'app.uninstall'] as const

/** What `/api/me/permissions?storeId=` should report for a set of permissions held at that store. */
export function atStore(perms: readonly string[]): string[] {
  return (STORE_SCOPE_ACTIONS as readonly string[]).filter((a) => perms.includes(a)).sort()
}

/** What `/api/me/permissions?merchantId=` should report for a set of permissions held at merchant scope. */
export function atMerchant(perms: readonly string[]): string[] {
  return (MERCHANT_SCOPE_ACTIONS as readonly string[]).filter((a) => perms.includes(a)).sort()
}

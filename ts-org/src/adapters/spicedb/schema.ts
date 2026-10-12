// SpiceDB schema, generated from the permission catalog (kernel/catalog.ts). A line-for-line port of
// Go's spicedb.Schema() (go/internal/adapters/spicedb/schema.go): schema.test.ts checks the output
// equals go/internal/adapters/spicedb/schema.zed. The platform owns the schema; merchants only ever
// write relationships (custom roles are data).
//
// One addition for stack e, behind `membership` (on in the app): `merchant#member`, the IdP's
// organization membership, and `agent_register = member - suspended`. Go's `a` checks agent
// registration in SQL; d's executor asks the engine (`agent.register` at the merchant), so the
// engine needs to know who is a member. Nothing else reads it.
import { GRANTABLE, NEVER_FOR_APPS, type Permission } from '../../kernel/catalog.js'

/** Catalog action id → SpiceDB permission name ("order.refund" → "order_refund"). */
export const perm = (action: string) => action.replaceAll('.', '_')

const REFUND: Permission = 'order.refund'
const isView = (a: string) => a.endsWith('.view')

export function schema(opts: { membership: boolean }): string {
  const lines: string[] = []
  const w = (s = '') => lines.push(s)

  w('// GENERATED from the permission catalog; do not edit.')
  w('use expiration')
  w()
  w('/** a merchant user; delegate = the live agent grants this user created */')
  w('definition user {')
  w('\trelation delegate: agent_grant#agent')
  w('}')
  w()
  w('/** platform staff (platform_admin, support) */')
  w('definition staff {}')
  w()
  w('definition app {}')
  w()
  w('definition agent {}')
  w()
  w('caveat refund_limit(amount int, limit int) {')
  w('\tamount <= limit')
  w('}')
  w()
  w('definition platform {')
  w('\trelation admin: staff')
  w('\trelation support: staff')
  w('\tpermission platform_merchant_create = admin')
  w('\tpermission platform_merchant_view = admin + support')
  w('\tpermission platform_merchant_suspend = admin')
  w('\tpermission platform_app_register = admin')
  w('\tpermission platform_audit_view = admin')
  w('\tpermission platform_break_glass = admin + support')
  w('}')
  w()
  w('/** a system or custom role: which grantable permissions it holds */')
  w('definition role {')
  for (const a of GRANTABLE) {
    if (a === REFUND) w(`\trelation ${perm(a)}: user:* | user:* with refund_limit | agent:* | agent:* with refund_limit`)
    else w(`\trelation ${perm(a)}: user:* | agent:*`)
  }
  w('\trelation role_manage_owner: user:*')
  w('}')
  w()
  w('/** one role assignment: subject holds role (at the scope that points to this binding) */')
  w('definition role_binding {')
  w('\trelation subject: user | user#delegate')
  w('\trelation role: role')
  for (const a of GRANTABLE) w(`\tpermission ${perm(a)} = subject & role->${perm(a)}`)
  w('\tpermission role_manage_owner = subject & role->role_manage_owner')
  w('}')
  w()
  w('/** an agent grant on a store; every relation expires */')
  w('definition agent_grant {')
  w('\trelation agent: agent with expiration')
  for (const a of GRANTABLE) w(`\trelation ${perm(a)}: agent with expiration`)
  w('}')
  w()
  w('/** an app installed on a store with scopes */')
  w('definition app_install {')
  for (const a of GRANTABLE) if (!NEVER_FOR_APPS.includes(a)) w(`\trelation ${perm(a)}: app`)
  w('}')
  w()
  w('definition merchant {')
  w('\trelation platform: platform')
  w('\trelation binding: role_binding')
  w('\trelation any_user: user:*')
  w('\trelation suspended: user:* | agent:* | app:*')
  w('\trelation break_glass_viewer: staff with expiration')
  if (opts.membership) w('\trelation member: user')
  w('\tpermission platform_break_glass = platform->platform_break_glass')
  w('\tpermission role_manage_owner = (binding->role_manage_owner & any_user) - suspended')
  if (opts.membership) w('\tpermission agent_register = member - suspended')
  for (const a of GRANTABLE) {
    const p = perm(a)
    w(`\tpermission ${p}_held = binding->${p}`)
    let expr = `(${p}_held & any_user) - suspended`
    if (isView(a)) expr = `(${expr}) + break_glass_viewer`
    w(`\tpermission ${p} = ${expr}`)
  }
  w('}')
  w()
  w('definition store {')
  w('\trelation merchant: merchant')
  w('\trelation binding: role_binding')
  w('\trelation any_user: user:*')
  w('\trelation grant: agent_grant')
  w('\trelation install: app_install')
  for (const a of GRANTABLE) {
    const p = perm(a)
    w(`\tpermission ${p}_held = binding->${p} + merchant->${p}_held`)
    let expr = `(${p}_held & (any_user + grant->${p}))`
    if (!NEVER_FOR_APPS.includes(a)) expr = `(${expr} + install->${p})`
    expr = `${expr} - merchant->suspended`
    if (isView(a)) expr = `(${expr}) + merchant->break_glass_viewer`
    w(`\tpermission ${p} = ${expr}`)
  }
  w('}')
  return lines.join('\n') + '\n'
}

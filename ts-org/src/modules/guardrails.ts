// No-escalation guardrails (SPEC §3, §5, §6), checked through can(): the caller must hold every
// permission they hand out, at that scope, and a refund limit at least as high.
import type { Can } from '../kernel/action.js'
import type { Resource } from '../kernel/authz.js'
import { UNLIMITED } from '../kernel/catalog.js'
import { forbidden } from '../kernel/errors.js'

export async function assertHoldsAll(can: Can, permissions: readonly string[], at: Resource) {
  const perms = [...new Set(permissions)]
  if (perms.length === 0) return
  const ds = await can.many(perms, at)
  const missing = perms.filter((_, i) => !ds[i]!.decision)
  if (missing.length) {
    const suspended = ds.find((d) => d.context?.reason === 'merchant_suspended')
    if (suspended) throw forbidden('merchant_suspended')
    throw forbidden('escalation', `caller lacks: ${missing.join(', ')}`)
  }
}

/** Caller's refund limit at `at` must be ≥ `limit` (undefined/null = no limit). Asked as
 *  "may the caller refund this amount here" so the engine's limit rule decides. */
export async function assertRefundLimitAtLeast(can: Can, limit: number | null | undefined, at: Resource) {
  const d = await can('order.refund', at, { amountCents: limit ?? UNLIMITED })
  if (!d.decision) throw forbidden('escalation', 'refund limit above your own')
}

// /api/me and /api/me/permissions (batch can = AuthZEN action search over the catalog).
import { z } from 'zod'
import { defineAction } from '../kernel/action.js'
import { GRANTABLE, STORE_ACTIONS } from '../kernel/catalog.js'
import { invalid } from '../kernel/errors.js'
import { findStore, storeResource } from './lookup.js'
import { merchantCheck } from './merchants.js'

export function meActions() {
  const me = defineAction({
    id: 'me.view',
    mutating: false,
    input: z.object({}),
    authorize: async () => null,
    async run({ principal }) {
      return { id: principal.id, kind: principal.kind, ...(principal.merchantId ? { merchantId: principal.merchantId } : {}) }
    },
  })

  const permissions = defineAction({
    id: 'me.permissions',
    mutating: false,
    input: z.object({ storeId: z.string().optional(), merchantId: z.string().optional() }),
    authorize: async () => null,
    async run({ tx, principal, can }, i) {
      let actions: readonly string[]
      let resource
      if (i.storeId) {
        resource = storeResource((await findStore(tx, principal, i.storeId)).id)
        actions = STORE_ACTIONS
      } else if (i.merchantId) {
        resource = await merchantCheck(tx, principal, i.merchantId)
        actions = [...GRANTABLE, 'platform.break_glass']
      } else throw invalid('invalid_input', 'storeId or merchantId required')
      const ds = await can.many([...actions], resource)
      return { actions: actions.filter((_, n) => ds[n]!.decision) }
    },
  })

  return [me, permissions]
}

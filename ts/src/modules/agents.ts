// Agents (SPEC §6): registered by a merchant user, act through expiring per-store grants.
import { and, eq, isNull } from 'drizzle-orm'
import { z } from 'zod'
import { newId } from '../db/ids.js'
import { agentGrants, agents } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { isGrantable } from '../kernel/catalog.js'
import { forbidden, invalid, notFound } from '../kernel/errors.js'
import type { ClientRegistry } from './apps.js'
import { assertHoldsAll } from './guardrails.js'
import { findStore, merchantResource, storeResource } from './lookup.js'

/** Longest agent grant: one year. The spec names no cap; without one, a large value is an invalid
 *  Date (500) and a grant that never practically expires. */
const MAX_GRANT_SECONDS = 365 * 24 * 3600

export function agentActions(deps: { clients: ClientRegistry }) {
  const register = defineAction({
    id: 'agent.register',
    mutating: true,
    kinds: ['user'],
    input: z.object({ name: z.string().min(1) }),
    authorize: async ({ principal }) => {
      if (!principal.merchantId) throw forbidden('forbidden', 'not a member of any merchant')
      return { action: 'agent.register', resource: merchantResource(principal.merchantId) }
    },
    async run({ tx, principal, emit }, i) {
      const c = await deps.clients.createClient(i.name, principal.credential)
      const id = newId('agent')
      await tx.insert(agents).values({ id, merchantId: principal.merchantId!, createdBy: principal.id, name: i.name, clientId: c.clientId })
      emit({ type: 'agent.registered', agentId: id })
      return { id, clientId: c.clientId, clientSecret: c.clientSecret }
    },
  })

  const grant = defineAction({
    id: 'agent.grant',
    mutating: true,
    input: z.object({
      storeId: z.string(),
      agentId: z.string().min(1),
      permissions: z.array(z.string()).min(1),
      expiresInSeconds: z.number().int().positive().max(MAX_GRANT_SECONDS),
    }),
    authorize: async ({ db, principal }, i) => ({ action: 'agent.grant', resource: storeResource((await findStore(db, principal, i.storeId)).id) }),
    async run({ tx, principal, can, emit }, i) {
      const s = await findStore(tx, principal, i.storeId)
      const [a] = await tx
        .select()
        .from(agents)
        .where(and(eq(agents.id, i.agentId), eq(agents.merchantId, s.merchantId)))
      if (!a) throw notFound('agent')
      // Only the registrant grants their agent: otherwise an ex-member's agent keeps working under a
      // teammate's grant (review-a finding 1; same rule as stack a/b).
      if (a.createdBy !== principal.id) throw forbidden('forbidden', "only the agent's registrant can grant it")
      const bad = i.permissions.filter((p) => !isGrantable(p))
      if (bad.length) throw invalid('not_grantable', `not grantable: ${bad.join(', ')}`)
      const permissions = [...new Set(i.permissions)]
      await assertHoldsAll(can, permissions, storeResource(s.id))
      const expiresAt = new Date(Date.now() + i.expiresInSeconds * 1000)
      const id = newId('grant')
      await tx.insert(agentGrants).values({ id, merchantId: s.merchantId, agentId: a.id, storeId: s.id, grantedBy: principal.id, permissions, expiresAt })
      emit({ type: 'agent.granted', grantId: id })
      return { id, expiresAt: expiresAt.toISOString() }
    },
  })

  const revoke = defineAction({
    id: 'agent.revoke',
    mutating: true,
    input: z.object({ storeId: z.string(), grantId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'agent.grant', resource: storeResource((await findStore(db, principal, i.storeId)).id) }),
    async run({ tx, emit }, i) {
      const r = await tx
        .update(agentGrants)
        .set({ revokedAt: new Date() })
        .where(and(eq(agentGrants.id, i.grantId), eq(agentGrants.storeId, i.storeId), isNull(agentGrants.revokedAt)))
        .returning()
      if (!r.length) throw notFound('grant')
      emit({ type: 'agent.revoked', grantId: i.grantId })
      return null
    },
  })

  return [register, grant, revoke]
}

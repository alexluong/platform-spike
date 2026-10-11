// The one executor: authenticate → validate → authorize (can) → run → outbox, in one transaction.
import type { Db } from '../db/client.js'
import { audit, outbox } from '../db/schema.js'
import type { ActionDef, Can, Check, Registry } from './action.js'
import { type Authorizer, type Decision, subjectOf } from './authz.js'
import { AppError, forbidden, invalid, unauthenticated } from './errors.js'
import type { Principal } from './principal.js'

export interface Executor {
  execute<O = unknown>(actionId: string, principal: Principal | null, rawInput: unknown): Promise<O>
}

export function bindCan(authz: Authorizer, principal: Principal): Can {
  const subject = subjectOf(principal)
  const can = ((action, resource, context) => authz.evaluate({ subject, action: { name: action }, resource, context })) as Can
  can.many = (actions, resource, context) =>
    authz.evaluateMany({ subject, resource, context, evaluations: actions.map((name) => ({ action: { name } })) })
  return can
}

/** Map a deny to the error the API returns: the engine's reason when it gave one. */
export function denyError(d: Decision): AppError {
  const reason = d.context?.reason
  return forbidden(typeof reason === 'string' ? reason : 'forbidden')
}

export function makeExecutor(deps: { db: Db; authz: Authorizer; registry: Registry }): Executor {
  const { db, authz, registry } = deps
  return {
    async execute(actionId, principal, rawInput) {
      const def = registry.get(actionId) as ActionDef | undefined
      if (!def) throw new Error(`unknown action ${actionId}`)

      if (def.public) {
        const input = parse(def, rawInput)
        const p = principal ?? { kind: 'customer', id: 'anonymous', credential: '' }
        return db.transaction((tx) => def.run({ principal: p, tx, can: denyAll, emit: () => {} }, input))
      }

      // 1. authenticate
      if (!principal) throw unauthenticated()
      // 2. token/scope check: is this kind of credential allowed this kind of thing
      if (def.kinds && !def.kinds.includes(principal.kind)) throw forbidden()
      const input = parse(def, rawInput)

      // 3. relationship + condition checks through can()
      const checks = await def.authorize({ principal, db }, input)
      const list: Check[] = checks == null ? [] : Array.isArray(checks) ? checks : [checks]
      const can = bindCan(authz, principal)
      const breakGlassUses = new Map<string, { action: string; merchantId: string }>()
      for (const c of list) {
        const d = await can(c.action, c.resource, c.context)
        if (!d.decision) throw denyError(d)
        if (d.context?.breakGlass) {
          const use = { action: c.action, merchantId: String(d.context.merchantId ?? '') }
          breakGlassUses.set(JSON.stringify(use), use)
        }
      }

      // 4. run + outbox (+ break-glass audit) in one transaction
      return db.transaction(async (tx) => {
        const events: Record<string, unknown>[] = []
        const result = await def.run({ principal, tx, can, emit: (e) => events.push(e) }, input)
        if (def.mutating) {
          await tx.insert(outbox).values({ action: def.id, actor: principal.id, payload: { input: input as object, events } })
        }
        for (const use of breakGlassUses.values()) {
          await tx.insert(audit).values({ actor: principal.id, action: use.action, merchantId: use.merchantId })
        }
        return result
      })
    },
  }
}

function parse(def: ActionDef, raw: unknown) {
  const r = def.input.safeParse(raw ?? {})
  if (!r.success) throw invalid('invalid_input', r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '))
  return r.data
}

const denyAll: Can = Object.assign(async () => ({ decision: false }), {
  many: async (actions: string[]) => actions.map(() => ({ decision: false })),
})

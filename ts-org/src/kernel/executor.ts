// The one executor: authenticate → validate → authorize (can) → run → outbox, in one transaction.
import { and, eq } from 'drizzle-orm'
import type { Db, Queryable } from '../db/client.js'
import { appInstalls, audit, outbox } from '../db/schema.js'
import type { ActionDef, Can, Check, Registry } from './action.js'
import { type Authorizer, type Decision, type Resource, subjectOf } from './authz.js'
import { AppError, forbidden, invalid, unauthenticated } from './errors.js'
import type { Principal } from './principal.js'

export interface Executor {
  execute<O = unknown>(actionId: string, principal: Principal | null, rawInput: unknown): Promise<O>
}

/**
 * can() bound to the calling principal. `q` is where the SQL side of the checks runs: the pool
 * before the request's transaction opens, the transaction itself inside `run` (never a second
 * connection from the same pool while the transaction is open). `onDecision` sees every decision
 * (the executor audits break-glass reads with it, batch checks included).
 */
export function bindCan(authz: Authorizer, principal: Principal, q: Queryable, onDecision?: (action: string, d: Decision) => void): Can {
  const subject = subjectOf(principal)
  const can = (async (action, resource, context) => {
    const d = (await appGate(q, principal, resource)) ?? (await authz.evaluate({ subject, action: { name: action }, resource, context }))
    onDecision?.(action, d)
    return d
  }) as Can
  can.many = async (actions, resource, context) => {
    const gated = await appGate(q, principal, resource)
    const ds = gated
      ? actions.map(() => gated)
      : await authz.evaluateMany({ subject, resource, context, evaluations: actions.map((name) => ({ action: { name } })) })
    ds.forEach((d, n) => onDecision?.(actions[n]!, d))
    return ds
  }
  return can
}

/** Apps have no merchant: their tenant boundary is the install. Check it in SQL before the engine
 *  (SPEC §1.6 "twice"): an app needs an install row for (app, store), and is denied at merchant
 *  scope. Returns a deny, or null to go on to the engine. */
async function appGate(q: Queryable, p: Principal, resource: Resource): Promise<Decision | null> {
  if (p.kind !== 'app' || resource.type === 'platform') return null
  if (resource.type !== 'store') return { decision: false }
  const [row] = await q
    .select({ id: appInstalls.id })
    .from(appInstalls)
    .where(and(eq(appInstalls.appId, p.id), eq(appInstalls.storeId, resource.id)))
    .limit(1)
  return row ? null : { decision: false }
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
      const breakGlassUses = new Map<string, { action: string; merchantId: string }>()
      const recordBreakGlass = (action: string, d: Decision) => {
        if (!d.decision || !d.context?.breakGlass) return
        const use = { action, merchantId: String(d.context.merchantId ?? '') }
        breakGlassUses.set(JSON.stringify(use), use)
      }
      const can = bindCan(authz, principal, db, recordBreakGlass)
      for (const c of list) {
        const d = await can(c.action, c.resource, c.context)
        if (!d.decision) throw denyError(d)
      }

      // 4. run + outbox (+ break-glass audit) in one transaction. Checks made inside run (batch
      //    can for /me/permissions, guardrails) are audited too: every break-glass read counts.
      return db.transaction(async (tx) => {
        const events: Record<string, unknown>[] = []
        const runCan = bindCan(authz, principal, tx, recordBreakGlass)
        const result = await def.run({ principal, tx, can: runCan, emit: (e) => events.push(e) }, input)
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

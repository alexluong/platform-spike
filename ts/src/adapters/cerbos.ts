// AuthZEN can() → Cerbos. Cerbos is stateless: this adapter asks the PIP (the app's DB) for the
// principal's attributes (role assignments resolved into permissions per scope, installs,
// grants, break-glass) and the resource's attributes (tenant, merchant status), then calls
// CheckResources / PlanResources. Rule outputs carry the deny reason ("merchant_suspended")
// and mark break-glass reads so the executor can audit them.
import { GRPC } from '@cerbos/grpc'
import { PlanKind, type PlanExpressionOperand, type Principal as CerbosPrincipal } from '@cerbos/core'
import type { Authorizer, Decision, EvaluationRequest, EvaluationsRequest, Resource, ResourceFilter, Subject } from '../kernel/authz.js'

export interface CerbosPip {
  subject(kind: string, id: string): Promise<{ roles: string[]; attr: Record<string, unknown> }>
  resource(type: string, id: string): Promise<Record<string, unknown> | null>
}

export function makeCerbosAuthorizer(opts: { address: string; pip: CerbosPip }) {
  const client = new GRPC(opts.address, { tls: false })
  const { pip } = opts

  const principalOf = async (s: Subject): Promise<CerbosPrincipal> => {
    const { roles, attr } = await pip.subject(s.type, s.id)
    return { id: `${s.type}:${s.id}`, roles: roles.length ? roles : ['none'], attr: attr as CerbosPrincipal['attr'] }
  }

  async function evaluateMany(req: EvaluationsRequest): Promise<Decision[]> {
    if (req.evaluations.length === 0) return []
    const principal = await principalOf(req.subject)
    // Group evaluations by (resource, context): one Cerbos resource entry each.
    type Entry = { resource: Resource; context?: Record<string, unknown>; actions: string[]; idx: number[] }
    const entries: Entry[] = []
    const resourceAttrs = new Map<string, Record<string, unknown> | null>()
    req.evaluations.forEach((e, i) => {
      const resource = e.resource ?? req.resource
      if (!resource) throw new Error('evaluation without resource')
      const context = { ...req.context, ...e.context }
      const key = JSON.stringify([resource.type, resource.id, context])
      let entry = entries.find((x) => JSON.stringify([x.resource.type, x.resource.id, x.context]) === key)
      if (!entry) entries.push((entry = { resource, context, actions: [], idx: [] }))
      entry.actions.push(e.action.name)
      entry.idx.push(i)
    })
    for (const e of entries) {
      const k = `${e.resource.type}:${e.resource.id}`
      if (!resourceAttrs.has(k)) resourceAttrs.set(k, await pip.resource(e.resource.type, e.resource.id))
    }
    const out: Decision[] = new Array(req.evaluations.length).fill({ decision: false, context: { reason: 'not_found' } })
    const live = entries.filter((e) => resourceAttrs.get(`${e.resource.type}:${e.resource.id}`) != null)
    if (live.length === 0) return out
    const res = await client.checkResources({
      principal,
      resources: live.map((e) => ({
        resource: {
          kind: e.resource.type,
          id: e.resource.id,
          attr: { ...resourceAttrs.get(`${e.resource.type}:${e.resource.id}`), ...amountAttr(e.context) } as never,
        },
        actions: e.actions,
      })),
    })
    live.forEach((e, n) => {
      const r = res.results[n]!
      const attrs = resourceAttrs.get(`${e.resource.type}:${e.resource.id}`)!
      e.actions.forEach((action, j) => {
        const allowed = r.isAllowed(action) === true
        const outputs = r.outputs.filter((o) => o.action === action).map((o) => o.value)
        const context: Decision['context'] = {}
        if (outputs.includes('merchant_suspended')) context.reason = 'merchant_suspended'
        if (allowed && outputs.includes('break_glass')) {
          context.breakGlass = true
          context.merchantId = attrs.merchantId
        }
        out[e.idx[j]!] = { decision: allowed, context }
      })
    })
    return out
  }

  const authorizer: Authorizer & { healthy(): Promise<boolean> } = {
    async evaluate(req: EvaluationRequest) {
      const [d] = await evaluateMany({ subject: req.subject, context: req.context, evaluations: [{ action: req.action, resource: req.resource }] })
      return d!
    },
    evaluateMany,

    /** PlanResources → a filter on ids. Understands `id/storeId in [...]` and `== x`; else 'unsupported'. */
    async searchResources(req): Promise<ResourceFilter> {
      const principal = await principalOf(req.subject)
      const plan = await client.planResources({
        principal,
        resource: { kind: req.resource.type, attr: (req.resource.properties ?? {}) as never },
        action: req.action.name,
      })
      if (plan.kind === PlanKind.ALWAYS_ALLOWED) return { kind: 'all' }
      if (plan.kind === PlanKind.ALWAYS_DENIED) return { kind: 'none' }
      return plan.kind === PlanKind.CONDITIONAL ? idsFromCondition(plan.condition) : { kind: 'unsupported' }
    },

    async healthy() {
      try {
        await client.checkHealth()
        return true
      } catch {
        return false
      }
    },
  }
  return authorizer
}

function amountAttr(context?: Record<string, unknown>) {
  return typeof context?.amountCents === 'number' ? { amountCents: context.amountCents } : {}
}

const ID_FIELDS = new Set(['request.resource.id', 'request.resource.attr.storeId'])

export function idsFromCondition(c: PlanExpressionOperand): ResourceFilter {
  if (!('operator' in c)) return { kind: 'unsupported' }
  const [a, b] = c.operands
  const name = a && 'name' in a ? a.name : undefined
  const value = b && 'value' in b ? b.value : undefined
  if (!name || !ID_FIELDS.has(name)) return { kind: 'unsupported' }
  if (c.operator === 'in' && Array.isArray(value)) return { kind: 'ids', ids: value.map(String) }
  if (c.operator === 'eq' && typeof value === 'string') return { kind: 'ids', ids: [value] }
  return { kind: 'unsupported' }
}

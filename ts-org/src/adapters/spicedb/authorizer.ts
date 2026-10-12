// AuthZEN can() → SpiceDB: evaluate → CheckPermission, evaluateMany → CheckBulkPermissions,
// searchResources → LookupResources. Go's counterpart: go/internal/adapters/spicedb/spicedb.go.
//
// Read-your-writes: every check asks for at-least-as-fresh as the ZedToken the relay stored with
// its last write (table authz_consistency), read from the DB on each call. Any app instance sees
// every instance's writes; Go's `a` keeps the token in process memory (one instance only).
//
// What d's executor expects from the engine and SpiceDB's answer can't carry (Cerbos returns them
// as rule outputs): the deny reason `merchant_suspended` for the merchant's own principals, and a
// `breakGlass` marker with the merchant id on staff reads, which the executor audits. Both come from
// the app DB through the same PIP stack d uses (modules/access.ts), only on the paths that need them.
import { eq } from 'drizzle-orm'
import { v1 } from '@authzed/authzed-node'
import type { Queryable } from '../../db/client.js'
import { authzConsistency } from '../../db/schema.js'
import type { Authorizer, Decision, EvaluationRequest, EvaluationsRequest, Resource, ResourceFilter, Subject } from '../../kernel/authz.js'
import type { AccessResolver } from '../../modules/access.js'
import { atLeastAsFresh, fullyConsistent, obj, PLATFORM_ID, type SpiceClient, subj } from './client.js'
import { perm, schema } from './schema.js'

/** Principal kind → schema definition. Customers are never in the engine. */
const SUBJECT_TYPE: Record<string, string> = { platform: 'staff', user: 'user', app: 'app', agent: 'agent' }

export function makeSpiceDbAuthorizer(deps: { client: SpiceClient; db: Queryable; pip: Pick<AccessResolver, 'subject' | 'resource'> }) {
  const { client: c, db, pip } = deps

  async function consistency() {
    const [row] = await db.select({ token: authzConsistency.token }).from(authzConsistency).where(eq(authzConsistency.id, 1))
    return row ? atLeastAsFresh(row.token) : fullyConsistent()
  }

  const resourceRef = (r: Resource) => obj(r.type, r.type === 'platform' ? PLATFORM_ID : r.id)

  function item(subject: Subject, action: string, resource: Resource, context?: Record<string, unknown>) {
    const st = SUBJECT_TYPE[subject.type]
    if (!st) return null
    // order.refund carries the amount for the refund_limit caveat. Without one (batch checks,
    // "holds order.refund at all" in guardrails) the question is "held at any limit": amount 0.
    const amount = action === 'order.refund' ? (typeof context?.amountCents === 'number' ? context.amountCents : 0) : undefined
    return v1.CheckBulkPermissionsRequestItem.create({
      resource: resourceRef(resource),
      permission: perm(action),
      subject: subj(st, subject.id),
      context: amount === undefined ? undefined : v1.PbStruct.fromJson({ amount }),
    })
  }

  async function evaluateMany(req: EvaluationsRequest): Promise<Decision[]> {
    const evals = req.evaluations.map((e) => {
      const resource = e.resource ?? req.resource
      if (!resource) throw new Error('evaluation without resource')
      return { action: e.action.name, resource, context: { ...req.context, ...e.context } }
    })
    const out: Decision[] = evals.map(() => ({ decision: false }))
    const items: v1.CheckBulkPermissionsRequestItem[] = []
    const idx: number[] = []
    evals.forEach((e, i) => {
      const it = item(req.subject, e.action, e.resource, e.context)
      if (it) items.push(it), idx.push(i)
    })
    if (items.length) {
      const res = await c.checkBulkPermissions(v1.CheckBulkPermissionsRequest.create({ consistency: await consistency(), items }))
      res.pairs.forEach((pair, j) => {
        const r = pair.response
        if (r.oneofKind === 'error') throw new Error(`spicedb bulk check ${items[j]!.permission}: ${r.error.message}`)
        if (r.oneofKind !== 'item') throw new Error('spicedb bulk check: empty response')
        const p = r.item.permissionship
        out[idx[j]!] =
          p === v1.CheckPermissionResponse_Permissionship.HAS_PERMISSION
            ? { decision: true }
            : { decision: false, context: p === v1.CheckPermissionResponse_Permissionship.CONDITIONAL_PERMISSION ? { reason: 'missing_context' } : {} }
      })
    }
    await annotate(req.subject, evals, out)
    return out
  }

  /** The executor's extras (see top): break-glass marker on staff reads, merchant_suspended on denies. */
  async function annotate(subject: Subject, evals: { action: string; resource: Resource }[], out: Decision[]) {
    const facts = new Map<string, Promise<{ merchantId?: string; storeId?: string; status?: string } | null>>()
    const factsOf = (r: Resource) => {
      const k = `${r.type}:${r.id}`
      if (!facts.has(k)) facts.set(k, pip.resource(r.type, r.id))
      return facts.get(k)!
    }
    let belongs: Promise<{ merchantId: string; installs: Record<string, unknown> }> | undefined
    for (const [i, e] of evals.entries()) {
      if (e.resource.type === 'platform') continue
      const d = out[i]!
      if (d.decision && subject.type === 'platform' && e.action !== 'platform.break_glass') {
        d.context = { ...d.context, breakGlass: true, merchantId: (await factsOf(e.resource))?.merchantId }
      } else if (!d.decision && (subject.type === 'user' || subject.type === 'agent' || subject.type === 'app')) {
        const f = await factsOf(e.resource)
        if (f?.status !== 'suspended') continue
        belongs ??= pip.subject(subject.type, subject.id).then(({ attr }) => ({
          merchantId: String(attr.merchantId ?? ''),
          installs: (attr.installs ?? {}) as Record<string, unknown>,
        }))
        const s = await belongs
        // own principals only (Cerbos d: same tenant, or an app installed on this store)
        if ((s.merchantId && s.merchantId === f.merchantId) || (e.resource.type === 'store' && e.resource.id in s.installs))
          d.context = { ...d.context, reason: 'merchant_suspended' }
      }
    }
  }

  const authorizer: Authorizer & { healthy(): Promise<boolean>; writeSchema(): Promise<void> } = {
    async evaluate(req: EvaluationRequest) {
      const [d] = await evaluateMany({ subject: req.subject, context: req.context, evaluations: [{ action: req.action, resource: req.resource }] })
      return d!
    },
    evaluateMany,

    /** LookupResources: every store the subject may act on; the caller narrows to the merchant in SQL. */
    async searchResources(req): Promise<ResourceFilter> {
      const st = SUBJECT_TYPE[req.subject.type]
      if (!st) return { kind: 'none' }
      if (req.resource.type !== 'store') return { kind: 'unsupported' }
      const rs = await c.lookupResources(
        v1.LookupResourcesRequest.create({
          consistency: await consistency(),
          resourceObjectType: 'store',
          permission: perm(req.action.name),
          subject: subj(st, req.subject.id),
        }),
      )
      return { kind: 'ids', ids: rs.filter((r) => r.permissionship === v1.LookupPermissionship.HAS_PERMISSION).map((r) => r.resourceObjectId) }
    },

    async healthy() {
      try {
        await c.readSchema(v1.ReadSchemaRequest.create({}))
        return true
      } catch {
        return false
      }
    },

    /** Bootstrap: the generated schema (idempotent). */
    async writeSchema() {
      await c.writeSchema(v1.WriteSchemaRequest.create({ schema: schema({ membership: true }) }))
    },
  }
  return authorizer
}

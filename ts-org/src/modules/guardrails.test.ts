import { describe, expect, it } from 'vitest'
import type { Can } from '../kernel/action.js'
import { UNLIMITED } from '../kernel/catalog.js'
import { idsFromCondition } from '../adapters/cerbos.js'
import { assertHoldsAll, assertRefundLimitAtLeast } from './guardrails.js'

const at = { type: 'store' as const, id: 's1' }
function canWith(held: string[], limit?: number): Can {
  const one = async (a: string, _r: unknown, ctx?: Record<string, unknown>) => {
    if (!held.includes(a)) return { decision: false }
    if (a === 'order.refund' && typeof ctx?.amountCents === 'number' && limit !== undefined) return { decision: ctx.amountCents <= limit }
    return { decision: true }
  }
  return Object.assign(one, { many: async (as: string[]) => Promise.all(as.map((a) => one(a, at))) }) as Can
}

describe('guardrails', () => {
  it('holding every permission passes', async () => {
    await expect(assertHoldsAll(canWith(['order.view', 'store.view']), ['order.view', 'store.view'], at)).resolves.toBeUndefined()
  })
  it('a missing permission is 403 escalation', async () => {
    await expect(assertHoldsAll(canWith(['order.view']), ['order.view', 'order.refund'], at)).rejects.toMatchObject({ status: 403, code: 'escalation' })
  })
  it('suspension wins over escalation', async () => {
    const can = Object.assign(async () => ({ decision: false, context: { reason: 'merchant_suspended' } }), {
      many: async (as: string[]) => as.map(() => ({ decision: false, context: { reason: 'merchant_suspended' } })),
    }) as Can
    await expect(assertHoldsAll(can, ['order.view'], at)).rejects.toMatchObject({ code: 'merchant_suspended' })
  })
  it('refund limit: caller limit ≥ role limit; "no limit" asks for UNLIMITED', async () => {
    const limited = canWith(['order.refund'], 500)
    await expect(assertRefundLimitAtLeast(limited, 500, at)).resolves.toBeUndefined()
    await expect(assertRefundLimitAtLeast(limited, 501, at)).rejects.toMatchObject({ code: 'escalation' })
    await expect(assertRefundLimitAtLeast(limited, null, at)).rejects.toMatchObject({ code: 'escalation' })
    await expect(assertRefundLimitAtLeast(canWith(['order.refund'], UNLIMITED), null, at)).resolves.toBeUndefined()
  })
})

describe('PlanResources → SQL filter', () => {
  it('storeId in [...] becomes an id list', () => {
    expect(idsFromCondition({ operator: 'in', operands: [{ name: 'request.resource.attr.storeId' }, { value: ['s1', 's2'] }] } as never)).toEqual({ kind: 'ids', ids: ['s1', 's2'] })
  })
  it('anything else is unsupported (caller falls back to per-store checks)', () => {
    expect(idsFromCondition({ operator: 'or', operands: [] } as never)).toEqual({ kind: 'unsupported' })
  })
})

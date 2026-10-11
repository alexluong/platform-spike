import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import { buildRegistry, defineAction } from './action.js'
import type { Authorizer, Decision } from './authz.js'
import { makeExecutor } from './executor.js'
import type { Principal } from './principal.js'

/** Fake DB: records inserts; transaction just calls through. */
function fakeDb() {
  const inserts: { table: unknown; values: unknown }[] = []
  const tx = { insert: (table: unknown) => ({ values: async (values: unknown) => void inserts.push({ table, values }) }) }
  return { inserts, db: { transaction: (fn: (t: unknown) => unknown) => fn(tx) } as never }
}

function fakeAuthz(decide: (action: string) => Decision): Authorizer {
  return {
    evaluate: async (r) => decide(r.action.name),
    evaluateMany: async (r) => r.evaluations.map((e) => decide(e.action.name)),
  }
}

const user: Principal = { kind: 'user', id: 'u1', merchantId: 'm1', credential: 'Bearer x' }
let ran = 0
const act = defineAction({
  id: 'thing.do',
  mutating: true,
  kinds: ['user'],
  input: z.object({ n: z.number() }),
  authorize: async () => ({ action: 'thing.do', resource: { type: 'store', id: 's1' } }),
  run: async (ctx, i) => {
    ran++
    ctx.emit({ n: i.n })
    return { ok: i.n }
  },
})
const registry = buildRegistry([act])

describe('executor', () => {
  it('401 without a principal, before validation', async () => {
    const { db } = fakeDb()
    const ex = makeExecutor({ db, authz: fakeAuthz(() => ({ decision: true })), registry })
    await expect(ex.execute('thing.do', null, {})).rejects.toMatchObject({ status: 401, code: 'unauthenticated' })
  })

  it('403 for a principal kind the action does not accept (token check)', async () => {
    const { db } = fakeDb()
    const ex = makeExecutor({ db, authz: fakeAuthz(() => ({ decision: true })), registry })
    await expect(ex.execute('thing.do', { ...user, kind: 'app' }, { n: 1 })).rejects.toMatchObject({ status: 403 })
  })

  it('400 on invalid input', async () => {
    const { db } = fakeDb()
    const ex = makeExecutor({ db, authz: fakeAuthz(() => ({ decision: true })), registry })
    await expect(ex.execute('thing.do', user, { n: 'x' })).rejects.toMatchObject({ status: 400, code: 'invalid_input' })
  })

  it('deny → 403 with the engine reason, and run never happens', async () => {
    const { db, inserts } = fakeDb()
    const before = ran
    const ex = makeExecutor({ db, authz: fakeAuthz(() => ({ decision: false, context: { reason: 'merchant_suspended' } })), registry })
    await expect(ex.execute('thing.do', user, { n: 1 })).rejects.toMatchObject({ status: 403, code: 'merchant_suspended' })
    expect(ran).toBe(before)
    expect(inserts).toHaveLength(0)
  })

  it('allow → runs and writes one outbox row with the emitted events', async () => {
    const { db, inserts } = fakeDb()
    const ex = makeExecutor({ db, authz: fakeAuthz(() => ({ decision: true })), registry })
    expect(await ex.execute('thing.do', user, { n: 7 })).toEqual({ ok: 7 })
    expect(inserts).toHaveLength(1)
    expect(inserts[0]!.values).toMatchObject({ action: 'thing.do', actor: 'u1', payload: { events: [{ n: 7 }] } })
  })

  it('break-glass decisions add an audit row with the catalog action', async () => {
    const { db, inserts } = fakeDb()
    const ex = makeExecutor({ db, authz: fakeAuthz(() => ({ decision: true, context: { breakGlass: true, merchantId: 'm9' } })), registry })
    await ex.execute('thing.do', user, { n: 1 })
    expect(inserts.map((i) => i.values)).toContainEqual({ actor: 'u1', action: 'thing.do', merchantId: 'm9' })
  })
})

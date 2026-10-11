import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import { buildRegistry, defineAction } from './action.js'
import type { Authorizer, Decision } from './authz.js'
import { makeExecutor } from './executor.js'
import type { Principal } from './principal.js'

/** Fake DB: records inserts; selects return `rows`; transaction just calls through. */
function fakeDb(rows: unknown[] = []) {
  const inserts: { table: unknown; values: unknown }[] = []
  const selects = { n: 0 }
  const select = () => {
    selects.n++
    const chain = { from: () => chain, where: () => chain, limit: async () => rows }
    return chain
  }
  const tx = { select, insert: (table: unknown) => ({ values: async (values: unknown) => void inserts.push({ table, values }) }) }
  return { inserts, selects, db: { select, transaction: (fn: (t: unknown) => unknown) => fn(tx) } as never }
}

function fakeAuthz(decide: (action: string) => Decision, calls = { n: 0 }): Authorizer {
  return {
    evaluate: async (r) => (calls.n++, decide(r.action.name)),
    evaluateMany: async (r) => (calls.n++, r.evaluations.map((e) => decide(e.action.name))),
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
const listing = defineAction({
  id: 'thing.list',
  mutating: false,
  input: z.object({}),
  authorize: async () => null,
  run: async ({ can }) => (await can.many(['a.view', 'b.view'], { type: 'store', id: 's1' })).map((d) => d.decision),
})
const anyKind = defineAction({
  id: 'thing.read',
  mutating: false,
  input: z.object({}),
  authorize: async () => ({ action: 'thing.read', resource: { type: 'store', id: 's1' } }),
  run: async () => 'ran',
})
const registry = buildRegistry([act, listing, anyKind])
const app: Principal = { kind: 'app', id: 'app1', credential: 'Bearer y' }

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

  it('break-glass decisions inside run (batch can) are audited too', async () => {
    const { db, inserts } = fakeDb()
    const ex = makeExecutor({ db, authz: fakeAuthz(() => ({ decision: true, context: { breakGlass: true, merchantId: 'm9' } })), registry })
    await ex.execute('thing.list', user, {})
    const rows = inserts.map((i) => i.values)
    expect(rows).toContainEqual({ actor: 'u1', action: 'a.view', merchantId: 'm9' })
    expect(rows).toContainEqual({ actor: 'u1', action: 'b.view', merchantId: 'm9' })
  })

  it('an app with no install row on the store is denied in SQL, before the engine', async () => {
    const { db, selects } = fakeDb([])
    const calls = { n: 0 }
    const ex = makeExecutor({ db, authz: fakeAuthz(() => ({ decision: true }), calls), registry })
    await expect(ex.execute('thing.read', app, {})).rejects.toMatchObject({ status: 403 })
    expect(await ex.execute('thing.list', app, {})).toEqual([false, false])
    expect(selects.n).toBe(2)
    expect(calls.n).toBe(0)
  })

  it('an app with an install row goes on to the engine', async () => {
    const { db } = fakeDb([{ id: 'inst1' }])
    const calls = { n: 0 }
    const ex = makeExecutor({ db, authz: fakeAuthz(() => ({ decision: true }), calls), registry })
    expect(await ex.execute('thing.list', app, {})).toEqual([true, true])
    expect(calls.n).toBe(1)
  })
})

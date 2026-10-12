// Error classification of the SpiceDB RelationSync (SPEC §1 Operational rules): only errors SpiceDB
// will repeat forever are permanent (dead-lettered); everything else is retried by the relay.
import { describe, expect, it } from 'vitest'
import { PermanentSyncError } from '../../outbox/relay.js'
import { makeSpiceDbSync } from './sync.js'

/** Drizzle-shaped fake: every select resolves to `rows`. */
const fakeTx = (rows: unknown[]) => {
  const chain: any = { from: () => chain, where: () => Promise.resolve(rows) }
  return { select: () => chain } as never
}
const failingClient = (code: number) => ({ writeRelationships: async () => Promise.reject(Object.assign(new Error(`grpc ${code}`), { code })) }) as never

describe('SpiceDB sync errors', () => {
  const tx = fakeTx([{ merchantId: 'm1' }])

  it('InvalidArgument / FailedPrecondition → permanent', async () => {
    for (const code of [3, 9]) await expect(makeSpiceDbSync(failingClient(code)).apply({ type: 'store.created', storeId: 's1' }, tx)).rejects.toBeInstanceOf(PermanentSyncError)
  })

  it('Unavailable / DeadlineExceeded → transient (rethrown as is)', async () => {
    for (const code of [14, 4]) {
      const err = await makeSpiceDbSync(failingClient(code)).apply({ type: 'store.created', storeId: 's1' }, tx).catch((e) => e)
      expect(err).not.toBeInstanceOf(PermanentSyncError)
      expect(err.code).toBe(code)
    }
  })

  it('unknown event types and missing ids are permanent; events SpiceDB ignores are no-ops', async () => {
    const sync = makeSpiceDbSync(failingClient(14))
    await expect(sync.apply({ type: 'nope.happened' }, tx)).rejects.toBeInstanceOf(PermanentSyncError)
    await expect(sync.apply({ type: 'role.assigned' }, tx)).rejects.toBeInstanceOf(PermanentSyncError)
    await expect(sync.apply({ type: 'order.placed', orderId: 'o1' }, tx)).resolves.toBeUndefined()
  })
})

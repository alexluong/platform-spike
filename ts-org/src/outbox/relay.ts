// Outbox relay (SPEC §1.4 and Operational rules): applies outbox events to a relationship engine
// through the RelationSync port. Engine-neutral; Go's counterpart is go/internal/outbox/relay.go.
//
// - In order: one drainer at a time (transaction-scoped advisory lock), rows by id.
// - Transient errors are retried forever; the failing row blocks the rows after it; a loud log at
//   10 attempts. Only errors the adapter marks PermanentSyncError are dead-lettered
//   (processed_at set, last_error "dead: …").
// - The request that wrote rows settles them before it responds (`settle`); a background loop
//   (`start`) retries whatever is left.
// - Waiting for the lock holds no connection: `pg_try_advisory_xact_lock`, then poll. (Go's relay
//   blocks on `pg_advisory_xact_lock` with a pool connection held: review-a 19.)
// - The engine's consistency token after the last write is stored in the drain's transaction
//   (`authz_consistency`), so checks on any instance can ask for at-least-that-fresh.
import { and, asc, isNull, lte, sql } from 'drizzle-orm'
import type pg from 'pg'
import { makeDb, withTransaction, type Tx } from '../db/client.js'
import { authzConsistency, outbox } from '../db/schema.js'

/** An outbox event as the modules emit it (`emit({ type, …ids })`). */
export interface SyncEvent {
  type: string
  [k: string]: unknown
}

/** The engine side of the relay. `apply` reads whatever state it needs through `q` (the drain's
 *  transaction: no second connection) and returns the engine's consistency token if it wrote. */
export interface RelationSync {
  apply(ev: SyncEvent, q: Tx): Promise<string | undefined>
}

/** The engine will never accept this event (unknown type, rejected by the schema): dead-letter it. */
export class PermanentSyncError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message)
  }
}

const LOCK_KEY = 777_001
const BATCH = 100
const ALERT_ATTEMPTS = 10

export interface Relay {
  /** One pass: lock, apply up to BATCH pending rows in order, commit. */
  batch(): Promise<{ locked: boolean; applied: number; failed: boolean }>
  /** Apply every row visible now; true when none with id ≤ the current max is left pending. */
  settle(timeoutMs: number): Promise<boolean>
  start(everyMs: number): () => void
}

type Log = Pick<Console, 'error' | 'warn'>

export function makeRelay(deps: { pool: pg.Pool; sync: RelationSync; log?: Log }): Relay {
  const { pool, sync } = deps
  const log = deps.log ?? console
  const db = makeDb(pool)

  async function batch() {
    return withTransaction(pool, async (tx) => {
      const lock = await tx.execute<{ ok: boolean }>(sql`SELECT pg_try_advisory_xact_lock(${LOCK_KEY}) AS ok`)
      if (!lock.rows[0]?.ok) return { locked: false, applied: 0, failed: false }
      const rows = await tx.select().from(outbox).where(isNull(outbox.processedAt)).orderBy(asc(outbox.id)).limit(BATCH)
      let applied = 0
      let failed = false
      let token: string | undefined
      for (const row of rows) {
        const events = ((row.payload as { events?: SyncEvent[] })?.events ?? []).filter((e) => e && typeof e.type === 'string')
        const dead: string[] = []
        let transient: unknown
        for (const ev of events) {
          try {
            token = (await sync.apply(ev, tx)) ?? token
          } catch (err) {
            if (err instanceof PermanentSyncError) {
              dead.push(`${ev.type}: ${err.message}`)
              log.error(`outbox ${row.id} event ${ev.type} dead-lettered: ${err.message}`)
              continue
            }
            transient = err
            break
          }
        }
        const attempts = row.attempts + 1
        if (transient !== undefined) {
          // Never drop: a dropped revocation keeps access forever. Later rows wait behind this one.
          const msg = transient instanceof Error ? transient.message : String(transient)
          if (attempts === ALERT_ATTEMPTS || attempts % 100 === 0)
            log.error(`outbox ${row.id} (${row.action}) still failing after ${attempts} attempts; relay keeps retrying: ${msg}`)
          await tx.update(outbox).set({ attempts, lastError: msg }).where(sql`${outbox.id} = ${row.id}`)
          failed = true
          break
        }
        await tx
          .update(outbox)
          .set({ processedAt: new Date(), attempts, lastError: dead.length ? `dead: ${dead.join('; ')}` : null })
          .where(sql`${outbox.id} = ${row.id}`)
        applied++
      }
      if (token) {
        await tx
          .insert(authzConsistency)
          .values({ id: 1, token })
          .onConflictDoUpdate({ target: authzConsistency.id, set: { token, updatedAt: new Date() } })
      }
      return { locked: true, applied, failed }
    })
  }

  async function settle(timeoutMs: number) {
    const deadline = Date.now() + timeoutMs
    const [{ max } = { max: null }] = await db.select({ max: sql<number | null>`max(${outbox.id})` }).from(outbox)
    if (max == null) return true
    const pending = async () => (await db.select({ id: outbox.id }).from(outbox).where(and(isNull(outbox.processedAt), lte(outbox.id, Number(max)))).limit(1)).length > 0
    for (;;) {
      let r = { locked: false, applied: 0, failed: false }
      try {
        r = await batch()
      } catch (err) {
        log.warn(`outbox drain: ${err instanceof Error ? err.message : err}`)
        r.failed = true
      }
      if (!(await pending())) return true
      if (Date.now() >= deadline) return false
      if (!r.locked || r.failed || r.applied === 0) await sleep(r.failed ? 100 : 10)
    }
  }

  function start(everyMs: number) {
    let running = false
    const timer = setInterval(async () => {
      if (running) return
      running = true
      try {
        for (;;) {
          const r = await batch()
          if (!r.locked || r.failed || r.applied < BATCH) break
        }
      } catch (err) {
        log.warn(`outbox relay: ${err instanceof Error ? err.message : err}`)
      } finally {
        running = false
      }
    }, everyMs)
    timer.unref()
    return () => clearInterval(timer)
  }

  return { batch, settle, start }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

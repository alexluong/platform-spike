import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres'
import { migrate } from 'drizzle-orm/node-postgres/migrator'
import type pg from 'pg'
import * as schema from './schema.js'

export type Db = NodePgDatabase<typeof schema>
/** Transaction handle; same query API as Db. */
export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0]
export type Queryable = Db | Tx

export const makeDb = (pool: pg.Pool): Db => drizzle(pool, { schema })

/** A transaction on one connection checked out of `pool`, handed to `fn` both as a Drizzle handle
 *  and as the raw client, so another library (Better Auth) can run its writes on the same
 *  connection, inside the same transaction. */
export async function withTransaction<T>(pool: pg.Pool, fn: (tx: Tx, client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect()
  try {
    return await drizzle(client, { schema }).transaction((tx) => fn(tx, client))
  } finally {
    client.release()
  }
}

export async function migrateApp(db: Db, migrationsFolder: string) {
  await migrate(db, { migrationsFolder })
}

import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres'
import { migrate } from 'drizzle-orm/node-postgres/migrator'
import type pg from 'pg'
import * as schema from './schema.js'

export type Db = NodePgDatabase<typeof schema>
/** Transaction handle; same query API as Db. */
export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0]
export type Queryable = Db | Tx

export const makeDb = (pool: pg.Pool): Db => drizzle(pool, { schema })

export async function migrateApp(db: Db, migrationsFolder: string) {
  await migrate(db, { migrationsFolder })
}

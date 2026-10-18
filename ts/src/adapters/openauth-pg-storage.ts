// OpenAuth StorageAdapter on Postgres. OpenAuth 0.4.3 ships memory, DynamoDB and Cloudflare KV
// adapters only; its interface is a key/value store (get/set with expiry/remove/prefix scan), so
// this is one table. Keys are string arrays joined with 0x1f (OpenAuth's own `joinKey`).
//
// What OpenAuth puts here: its signing keys (ES256) and cookie-encryption keys (RSA-OAEP), password
// hashes (`email/<email>/password`), authorization codes (60 s), refresh tokens, and the
// email → subject link. Users, kinds and everything else stay in the app's tables.
import { joinKey, splitKey, type StorageAdapter } from '@openauthjs/openauth/storage/storage'
import type pg from 'pg'

export const KV_TABLE = 'openauth_kv'

export async function migrateKv(pool: pg.Pool) {
  // collate "C": byte order, so the prefix scan (LIKE 'p%') can use the primary-key index and the
  // 0x1f separator sorts predictably.
  await pool.query(`create table if not exists ${KV_TABLE} (
    key text collate "C" primary key,
    value jsonb not null,
    expiry timestamptz
  )`)
  await pool.query(`create index if not exists ${KV_TABLE}_expiry on ${KV_TABLE} (expiry) where expiry is not null`)
}

/** Expired rows are invisible to reads; this removes them. OpenAuth never deletes on its own. */
export async function sweepKv(pool: pg.Pool) {
  const r = await pool.query(`delete from ${KV_TABLE} where expiry is not null and expiry <= now()`)
  return r.rowCount ?? 0
}

const likePrefix = (s: string) => s.replace(/[\\%_]/g, (c) => `\\${c}`) + '%'

export function PostgresStorage(pool: pg.Pool): StorageAdapter {
  return {
    async get(key) {
      const r = await pool.query(`select value from ${KV_TABLE} where key = $1 and (expiry is null or expiry > now())`, [joinKey(key)])
      return r.rows[0]?.value
    },
    async set(key, value, expiry) {
      await pool.query(
        `insert into ${KV_TABLE} (key, value, expiry) values ($1, $2, $3)
         on conflict (key) do update set value = excluded.value, expiry = excluded.expiry`,
        [joinKey(key), JSON.stringify(value), expiry ?? null],
      )
    },
    async remove(key) {
      await pool.query(`delete from ${KV_TABLE} where key = $1`, [joinKey(key)])
    },
    async *scan(prefix) {
      const r = await pool.query(`select key, value from ${KV_TABLE} where key like $1 and (expiry is null or expiry > now()) order by key`, [
        likePrefix(joinKey(prefix)),
      ])
      for (const row of r.rows) yield [splitKey(row.key), row.value]
    },
  }
}

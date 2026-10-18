// Probe 7 (TASK-62): instance deletion: API, time, and whether it frees DB rows.
// Creates a "used" instance (login setup + 20 users + a login), counts its rows in every table with
// an instance_id column, deletes it through the System API, and recounts over time.
//   mise exec -- node bench/zitadel-instances/probe-delete.ts > bench/zitadel-instances/evidence/probe-delete.txt
import { createInstance, login, ok, pool, provisionLogin, psql, ROWS_FN, sleep, systemToken, z } from './lib.ts'

const tag = Date.now().toString(36)
const log = (...a: unknown[]) => console.log(...a)

log(`# probe-delete ${new Date().toISOString()}`)
psql(ROWS_FN)
const I = await createInstance(`pd-${tag}`, `pd-${tag}.idp.internal`)
const cfg = await provisionLogin(I)
await pool(
  Array.from({ length: 20 }, (_, i) => i),
  4,
  (i) =>
    ok('user', z('/v2/users/new', { instance: I.domain, token: I.pat, json: { organizationId: cfg.orgId, username: `u${i}@x.test`, human: { profile: { givenName: 'U', familyName: `${i}` }, email: { email: `u${i}@x.test`, isVerified: true }, password: { password: 'Password1!-x' } } } })),
)
await login(I, cfg)
await sleep(3000) // let async projections settle

const rows = () => {
  const out = psql(`SELECT tbl, n FROM public.zb_instance_rows('${I.id}') ORDER BY n DESC;`)
  const list = out ? out.split('\n').map((l) => l.split('|')) : []
  return { total: list.reduce((a, [, n]) => a + Number(n), 0), tables: list.length, top: list.slice(0, 6).map(([t, n]) => `${t}=${n}`).join(' ') }
}
const before = rows()
log(`instance ${I.id}: ${before.total} rows in ${before.tables} tables; top: ${before.top}`)

const t0 = performance.now()
const del = await z(`/system/v1/instances/${I.id}`, { method: 'DELETE', token: systemToken() })
log(`DELETE /system/v1/instances/{id}: ${del.status} in ${Math.round(performance.now() - t0)}ms ${del.text.slice(0, 120)}`)
const disc = await z('/.well-known/openid-configuration', { instance: I.domain })
log(`discovery right after: ${disc.status} ${disc.text.slice(0, 100)}`)
const sys = await z('/system/v1/instances/_search', { token: systemToken(), json: { queries: [{ idQuery: { id: I.id } }] } })
log(`System API search by id after delete: totalResult=${sys.json?.details?.totalResult ?? 0}`)
for (const wait of [0, 5, 30, 90]) {
  if (wait) await sleep(wait * 1000 - (wait === 5 ? 0 : 0))
  const r = rows()
  log(`+${wait}s: ${r.total} rows in ${r.tables} tables; top: ${r.top || '-'}`)
}
// Can the domain be reused right away?
const again = await z('/system/v1/instances/_create', { token: systemToken(), json: { instanceName: `pd2-${tag}`, customDomain: I.domain, machine: { userName: 'owner', name: 'owner', personalAccessToken: { expirationDate: '2099-01-01T00:00:00Z' } } } })
log(`re-create an instance with the deleted instance's domain: ${again.status} ${again.status < 300 ? 'ok' : again.text.slice(0, 120)}`)
log('\ndone')

// Evidence for results/d.md (cross-system writes): do Better Auth's organization writes join the
// app's transaction, and do they stay off Better Auth's own pool? Runs inside the app container:
//   DOCKER_HOST=ssh://cs-ws docker exec -i ps-d-d-app-1 node --input-type=module - < ts-org/scripts/tx-probe.mjs
import pg from 'pg'
import { sql } from 'drizzle-orm'
import { makeBetterAuth, newInternalKey } from '/app/dist/adapters/better-auth.js'
import { withTransaction } from '/app/dist/db/client.js'

const url = process.env.DATABASE_URL
const authPool = new pg.Pool({ connectionString: url, max: 1, connectionTimeoutMillis: 3000 })
const appPool = new pg.Pool({ connectionString: url, max: 2 })
const id = makeBetterAuth({ pool: authPool, baseUrl: 'http://localhost:8086', secret: process.env.AUTH_SECRET, apiResource: 'urn:platform-spike:api', rateLimit: false, internalKey: newInternalKey() })
const u = await id.createUser(`probe-${Date.now()}@example.com`, 'Cf-0123456789abcdef-Aa1!')
const orgId = `m_probe_${Date.now()}`
const count = async (q) => Number((await appPool.query(q, [orgId])).rows[0].n)

// Hold Better Auth's only pooled connection: any tenancy call that used it would time out.
const held = await authPool.connect()
let seenInside
try {
  await withTransaction(appPool, async (tx, client) => {
    const t = id.tenancyFor(client)
    await t.port.createOrganization({ id: orgId, name: 'probe' })
    await t.port.addMember(orgId, u.id)
    const inv = await t.port.invite(orgId, 'Someone@Example.com', u.id)
    seenInside = (await tx.execute(sql`select count(*)::int as n from member where "organizationId" = ${orgId}`)).rows[0].n
    console.log('inside tx: member rows visible to the app tx =', seenInside, '; invitation email stored as', inv.email)
    console.log('outside tx before commit: organization rows =', await count('select count(*) n from organization where id = $1'))
    throw new Error('boom (simulated failure after the IdP writes)')
  })
} catch (e) {
  console.log('tx failed:', e.message)
} finally {
  held.release()
}
console.log('after rollback: organization rows =', await count('select count(*) n from organization where id = $1'),
  '; member rows =', await count('select count(*) n from member where "organizationId" = $1'),
  '; invitation rows =', await count('select count(*) n from invitation where "organizationId" = $1'))

// Unique index (one merchant per user) through the IdP port → 409 already_member.
const org2 = `${orgId}_b`
await withTransaction(appPool, async (_tx, client) => {
  const t = id.tenancyFor(client)
  await t.port.createOrganization({ id: org2, name: 'probe2' })
  await t.port.addMember(org2, u.id)
})
try {
  await withTransaction(appPool, async (_tx, client) => {
    const t = id.tenancyFor(client)
    await t.port.createOrganization({ id: `${org2}_c`, name: 'probe3' })
    await t.port.addMember(`${org2}_c`, u.id)
  })
} catch (e) {
  console.log('second membership:', e.status, e.code)
}
// Accept through Better Auth's own endpoint (session lookup, recipient check, member insert, session
// update) inside the app tx, with Better Auth's pool held again: does any of it leave the tx?
const email2 = `probe2-${Date.now()}@example.com`
const u2 = await id.createUser(email2, 'Cf-0123456789abcdef-Aa1!')
const signIn = await id.auth.api.signInEmail({ body: { email: email2, password: 'Cf-0123456789abcdef-Aa1!' }, returnHeaders: true })
const token = signIn.headers.get('set-auth-token')
let invId
await withTransaction(appPool, async (_tx, client) => {
  invId = (await id.tenancyFor(client).port.invite(org2, email2, u.id)).id
})
const held2 = await authPool.connect()
try {
  const r = await withTransaction(appPool, async (_tx, client) => id.tenancyFor(client).port.acceptInvitation(invId, `Bearer ${token}`))
  console.log('accept inside the app tx, Better Auth pool held:', JSON.stringify(r))
} catch (e) {
  console.log('accept inside the app tx failed:', e.message)
} finally {
  held2.release()
}
// The OAuth provider writes through ctx.context.adapter (not the tx-aware lookup): with Better Auth's
// pool held, client creation inside the app tx can't proceed.
const held3 = await authPool.connect()
try {
  await withTransaction(appPool, async (_tx, client) => id.tenancyFor(client).port && id.createClient('probe', `Bearer ${token}`))
  console.log('createClient inside the app tx: ran without Better Auth pool')
} catch (e) {
  console.log('createClient inside the app tx with Better Auth pool held:', e.message)
} finally {
  held3.release()
}
// Review-d: every other port call (status, member removal, invitation list/find/cancel, client
// link) inside the app tx with Better Auth's pool held, then a rollback: nothing may stick.
const held4 = await authPool.connect()
let invC
try {
  await withTransaction(appPool, async (_tx, client) => {
    const p = id.tenancyFor(client).port
    invC = (await p.invite(org2, `probe3-${Date.now()}@example.com`, u.id)).id
  })
  await withTransaction(appPool, async (_tx, client) => {
    const p = id.tenancyFor(client).port
    await p.setStatus(org2, 'suspended')
    await p.listInvitations(org2)
    await p.findInvitation(invC)
    await p.cancelInvitation(invC)
    await p.removeMember(org2, u.id)
    await p.attachClient('no-such-client', org2)
    throw new Error('boom 2')
  })
} catch (e) {
  console.log('status/remove/cancel/list/find/attach in tx, pool held:', e.message)
} finally {
  held4.release()
}
console.log('after rollback 2: status =', (await appPool.query('select status from organization where id = $1', [org2])).rows[0]?.status,
  '; member rows =', Number((await appPool.query('select count(*) n from member where "organizationId" = $1', [org2])).rows[0].n),
  '; invitation status =', (await appPool.query('select status from invitation where id = $1', [invC])).rows[0]?.status)
await authPool.end(); await appPool.end()
process.exit(0)

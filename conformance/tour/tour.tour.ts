// A narrated walk through the spike, chapter by chapter, against any stack:
//   STACK=a HOST=<docker host> pnpm tour
// Each chapter matches a section of the repo README ("Follow along"). Every request is printed with
// who sent it and what came back; a step whose status isn't the expected one stops the tour.
import { test } from 'vitest'
import type { Api, Res } from '../src/client'
import { env } from '../src/env'
import { driver, merchantWithStore, newCustomer, newMerchant, newSupport, platformAdmin, sleep } from '../src/world'

const c = { dim: '\x1b[2m', bold: '\x1b[1m', green: '\x1b[32m', red: '\x1b[31m', cyan: '\x1b[36m', reset: '\x1b[0m' }
const log = (s = '') => process.stdout.write(s + '\n')

function chapter(n: number, title: string, story: string) {
  log(`\n${c.bold}${c.cyan}── ${n}. ${title} ${'─'.repeat(Math.max(0, 60 - title.length))}${c.reset}`)
  log(`${c.dim}${story}${c.reset}`)
}
const say = (s: string) => log(`\n${s}`)

function brief(body: unknown): string {
  if (body === undefined) return ''
  const s = JSON.stringify(body)
  return s.length > 160 ? s.slice(0, 157) + '...' : s
}

/** Send a request, print it, and stop the tour if the status isn't one of `expect`. */
async function call<T = any>(api: Api, method: 'GET' | 'POST' | 'PATCH' | 'DELETE', path: string, expect: number | number[], body?: unknown): Promise<T> {
  const r: Res<T> =
    method === 'GET' ? await api.get<T>(path) : method === 'DELETE' ? await api.delete<T>(path) : method === 'PATCH' ? await api.patch<T>(path, body) : await api.post<T>(path, body)
  const want = Array.isArray(expect) ? expect : [expect]
  const good = want.includes(r.status)
  const color = !good ? c.red : r.status < 300 ? c.green : c.cyan
  log(`  ${c.dim}${api.actor.padEnd(10)}${c.reset} ${method.padEnd(6)} ${path}${body !== undefined ? ` ${c.dim}${brief(body)}${c.reset}` : ''}`)
  log(`  ${' '.repeat(10)} ${color}← ${r.status}${c.reset} ${c.dim}${brief(r.body)}${c.reset}`)
  if (!good) throw new Error(`expected ${want.join(' or ')}, got ${r.status}: ${r.text}`)
  return r.body
}
const DENIED = [403, 404] // other tenants' resources may answer 404 so their existence doesn't leak

test(`tour of stack ${env.stack}`, async () => {
  log(`${c.bold}Platform spike tour — stack ${env.stack} at ${driver.baseUrl}${c.reset}`)
  log(`${c.dim}Every user below is created through /api/_test/users and logged in through the stack's real login flow.${c.reset}`)

  // 1 ─────────────────────────────────────────────────────────────────────────
  chapter(1, 'Platform staff create a merchant', 'The platform admin onboards a merchant and names its owner. Support staff can look but not act.')
  const admin = await platformAdmin()
  const { m, s } = await merchantWithStore()
  say(`The admin created merchant ${m.id} with an owner, and the owner opened store ${s.id}. The admin can list merchants:`)
  await call(admin.api, 'GET', '/api/platform/merchants', 200)
  const support = await newSupport()
  say('Support can view merchants too, but creating one is denied:')
  await call(support.api, 'GET', '/api/platform/merchants', 200)
  await call(support.api, 'POST', '/api/platform/merchants', 403, { name: 'nope', ownerUserId: m.owner.id })
  say("Neither of them can read the merchant's data. Merchant data needs break-glass (chapter 8):")
  await call(admin.api, 'GET', `/api/stores/${s.id}/orders`, DENIED)

  // 2 ─────────────────────────────────────────────────────────────────────────
  chapter(2, 'System roles', 'Every merchant has owner, admin, developer and staff. Staff run the shop floor but cannot refund or manage roles.')
  await call(m.owner.api, 'GET', `/api/merchants/${m.id}/roles`, 200)
  const staff = await m.memberWithRole('staff', m.scope, 'staff')
  say('A staff member adds a product (allowed) and then tries to create a role (denied):')
  const product = await call(staff.api, 'POST', `/api/stores/${s.id}/products`, 201, { title: 'Mug', priceCents: 1500 })
  await call(staff.api, 'POST', `/api/merchants/${m.id}/roles`, 403, { name: 'sneaky', permissions: ['order.view'] })

  // 3 ─────────────────────────────────────────────────────────────────────────
  chapter(3, 'Orders, payments, delivery', 'A customer buys; the owner captures payment and ships. State rules come after permission checks.')
  const customer = await newCustomer()
  const order = await call(customer.api, 'POST', `/api/stores/${s.id}/orders`, 201, { items: [{ productId: product.id, qty: 4 }] })
  say('The customer can see their own order; capture moves it to paid, a shipment to fulfilling:')
  await call(customer.api, 'GET', '/api/me/orders', 200)
  await call(m.owner.api, 'POST', `/api/orders/${order.id}/payments/capture`, 201)
  const ship = await call(m.owner.api, 'POST', `/api/orders/${order.id}/shipments`, 201, { carrier: 'ups' })
  await call(m.owner.api, 'POST', `/api/shipments/${ship.id}/status`, 200, { status: 'in_transit' })
  say('Shipment status only moves forward (409), and a customer can never capture (403, before any state rule):')
  await call(m.owner.api, 'POST', `/api/shipments/${ship.id}/status`, 409, { status: 'label_created' })
  await call(customer.api, 'POST', `/api/orders/${order.id}/payments/capture`, 403)

  // 4 ─────────────────────────────────────────────────────────────────────────
  chapter(4, 'Custom roles are data', 'The owner defines "Refund clerk": view orders, refund up to $50. Edits apply on the very next request.')
  const clerkRole = await call(m.owner.api, 'POST', `/api/merchants/${m.id}/roles`, 201, {
    name: 'Refund clerk',
    permissions: ['order.view', 'order.refund'],
    refundLimitCents: 5000,
  })
  const clerk = await m.member('clerk')
  say('Assigned at this store only:')
  await call(m.owner.api, 'POST', `/api/merchants/${m.id}/role-assignments`, 201, { userId: clerk.id, roleId: clerkRole.id, scope: { type: 'store', id: s.id } })
  const small = await m.paidOrder(s.id, 3000, customer)
  const big = await m.paidOrder(s.id, 8000, customer)
  say('Refunding $30 is within the limit; $80 is over it:')
  await call(clerk.api, 'POST', `/api/orders/${small.id}/refund`, 200, { amountCents: 3000 })
  await call(clerk.api, 'POST', `/api/orders/${big.id}/refund`, 403, { amountCents: 8000 })
  say('What the clerk may do at this store, as the UI would ask (a batch check):')
  await call(clerk.api, 'GET', `/api/me/permissions?storeId=${s.id}`, 200)
  say('The owner removes refunds from the role. The clerk loses it immediately; no new login needed:')
  await call(m.owner.api, 'PATCH', `/api/merchants/${m.id}/roles/${clerkRole.id}`, 200, { permissions: ['order.view'] })
  await call(clerk.api, 'POST', `/api/orders/${big.id}/refund`, 403, { amountCents: 1000 })

  // 5 ─────────────────────────────────────────────────────────────────────────
  chapter(5, 'Guardrails: no escalation', 'A manager may manage roles, but only hand out what they hold themselves.')
  const manager = await m.memberWithPerms(['role.manage', 'order.view'], m.scope, { label: 'manager' })
  say('Creating a role with order.view (held) works; adding order.refund (not held) is escalation:')
  await call(manager.api, 'POST', `/api/merchants/${m.id}/roles`, 201, { name: 'Viewer', permissions: ['order.view'] })
  await call(manager.api, 'POST', `/api/merchants/${m.id}/roles`, 403, { name: 'Refunder', permissions: ['order.view', 'order.refund'] })

  // 6 ─────────────────────────────────────────────────────────────────────────
  chapter(6, 'Apps', 'The platform registers an app; the owner installs it on one store with fewer scopes than it asked for.')
  const app = await call(admin.api, 'POST', '/api/platform/apps', 201, { name: 'Order sync', scopes: ['order.view', 'product.create'] })
  const install = await call(m.owner.api, 'POST', `/api/stores/${s.id}/apps`, 201, { appId: app.id, scopes: ['order.view'] })
  const appApi = m.owner.api.as(await driver.loginClient(app.clientId, app.clientSecret), 'app')
  say('The app reads orders (granted) but cannot create products (requested, not granted):')
  await call(appApi, 'GET', `/api/stores/${s.id}/orders`, 200)
  await call(appApi, 'POST', `/api/stores/${s.id}/products`, 403, { title: 'x', priceCents: 1 })
  say('Uninstalling cuts it off at once:')
  await call(m.owner.api, 'DELETE', `/api/stores/${s.id}/apps/${install.id}`, 204)
  await call(appApi, 'GET', `/api/stores/${s.id}/orders`, DENIED)

  // 7 ─────────────────────────────────────────────────────────────────────────
  chapter(7, 'AI agents', 'A staff member lets an agent read orders for 5 seconds. The agent never exceeds that user, or that time.')
  const lead = await m.memberWithPerms(['order.view', 'order.refund', 'agent.grant'], { type: 'store', id: s.id }, { label: 'lead' })
  const agent = await call(lead.api, 'POST', '/api/agents', 201, { name: 'Refund helper' })
  await call(lead.api, 'POST', `/api/stores/${s.id}/agent-grants`, 201, { agentId: agent.id, permissions: ['order.view'], expiresInSeconds: 5 })
  const agentApi = m.owner.api.as(await driver.loginClient(agent.clientId, agent.clientSecret), 'agent')
  say('Within the grant: reading works, refunding (not granted) does not:')
  await call(agentApi, 'GET', `/api/stores/${s.id}/orders`, 200)
  await call(agentApi, 'POST', `/api/orders/${big.id}/refund`, 403, { amountCents: 100 })
  say('Waiting for the grant to expire...')
  await sleep(6000)
  await call(agentApi, 'GET', `/api/stores/${s.id}/orders`, DENIED)

  // 8 ─────────────────────────────────────────────────────────────────────────
  chapter(8, 'Break-glass', "Support needs to look into this merchant's orders: a read-only, expiring, audited grant.")
  await call(support.api, 'GET', `/api/stores/${s.id}/orders`, DENIED)
  await call(support.api, 'POST', '/api/platform/break-glass', 201, { merchantId: m.id, reason: 'customer ticket 123', minutes: 5 })
  say('Now support can read, but still not write:')
  await call(support.api, 'GET', `/api/stores/${s.id}/orders`, 200)
  await call(support.api, 'POST', `/api/orders/${big.id}/cancel`, 403)
  say('Every read under break-glass is in the audit log:')
  await call(admin.api, 'GET', `/api/platform/audit?merchantId=${m.id}`, 200)

  // 9 ─────────────────────────────────────────────────────────────────────────
  chapter(9, 'Tenant isolation', "Another merchant's owner probes this merchant's store, orders and roles.")
  const other = await newMerchant()
  const intruder = other.owner.api.as(other.owner.token, 'other-own')
  await call(intruder, 'GET', `/api/stores/${s.id}/orders`, DENIED)
  await call(intruder, 'GET', `/api/orders/${order.id}`, DENIED)
  await call(intruder, 'GET', `/api/merchants/${m.id}/roles`, DENIED)

  // 10 ────────────────────────────────────────────────────────────────────────
  chapter(10, 'Suspension', 'The platform suspends the merchant: its people are locked out until reinstated.')
  await call(admin.api, 'POST', `/api/platform/merchants/${m.id}/suspend`, 200)
  await call(m.owner.api, 'GET', `/api/stores/${s.id}/orders`, 403)
  await call(admin.api, 'POST', `/api/platform/merchants/${m.id}/reinstate`, 200)
  await call(m.owner.api, 'GET', `/api/stores/${s.id}/orders`, 200)

  log(`\n${c.bold}${c.green}Tour complete on stack ${env.stack}.${c.reset} The full rules are in spec/SPEC.md; every case above has a test file in conformance/tests/.\n`)
})

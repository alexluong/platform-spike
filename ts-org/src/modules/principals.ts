// Map a validated credential to an app principal (kinds live in the app DB, not the IdP).
import { eq } from 'drizzle-orm'
import type { Queryable } from '../db/client.js'
import { member } from '../db/idp-tables.js'
import { agents, apps, appUsers } from '../db/schema.js'
import type { Principal } from '../kernel/principal.js'

export type Credential = { type: 'session'; userId: string } | { type: 'client'; clientId: string; scopes: string[] }

export function makePrincipalResolver(db: Queryable, requiredClientScope: string) {
  return async function resolve(cred: Credential, raw: string): Promise<Principal | null> {
    if (cred.type === 'session') {
      const [u] = await db.select().from(appUsers).where(eq(appUsers.id, cred.userId))
      if (!u) return null
      if (u.kind === 'platform') return { kind: 'platform', id: u.id, platformRole: u.platformRole ?? undefined, credential: raw }
      if (u.kind === 'customer') return { kind: 'customer', id: u.id, credential: raw }
      // membership from the IdP's organization tables on every request, never from the session
      const [m] = await db.select({ merchantId: member.organizationId }).from(member).where(eq(member.userId, u.id))
      return { kind: 'user', id: u.id, merchantId: m?.merchantId, credential: raw }
    }
    if (!cred.scopes.includes(requiredClientScope)) return null
    const [a] = await db.select().from(apps).where(eq(apps.clientId, cred.clientId))
    if (a) return { kind: 'app', id: a.id, credential: raw }
    const [g] = await db.select().from(agents).where(eq(agents.clientId, cred.clientId))
    if (g) return { kind: 'agent', id: g.id, merchantId: g.merchantId, credential: raw }
    return null
  }
}

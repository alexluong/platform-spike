// Stack d: TypeScript (Hono) app, built from c: Better Auth + organization plugin + Cerbos. SPEC §10, §15.
// STARTING POINT: a copy of stacks/c.ts (Better Auth email/password sign-in with the bearer plugin;
// OAuth provider client_credentials for apps/agents) with the port changed. The stack's builder
// adjusts it to the real login path (e.g. if the organization plugin changes sign-in or tokens).
// features: ['idp-tenancy'] opts into tests/idp-tenancy.test.ts (SPEC §15.2, §15.3).
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App, which also hosts Better Auth (SPEC table: port 8086). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8086`
/** RFC 8707 resource the app accepts as token audience (stacks/d/compose.yaml API_RESOURCE). */
const apiResource = process.env.D_API_RESOURCE ?? 'urn:platform-spike:api'

async function fail(what: string, res: Response): Promise<never> {
  throw new Error(`stack d ${what}: HTTP ${res.status} ${await res.text().catch(() => '')}`)
}

const driver: StackDriver = {
  baseUrl,
  features: ['idp-tenancy'],
  async loginUser(email, password) {
    const res = await fetch(`${baseUrl}/api/auth/sign-in/email`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    if (!res.ok) return fail('sign-in', res)
    const token = res.headers.get('set-auth-token')
    if (!token) throw new Error('stack d sign-in: no set-auth-token header (bearer plugin)')
    return token
  },
  async loginClient(clientId, clientSecret) {
    const res = await fetch(`${baseUrl}/api/auth/oauth2/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret, scope: 'api', resource: apiResource }),
    })
    if (!res.ok) return fail('client_credentials', res)
    const body = (await res.json()) as { access_token?: string }
    if (!body.access_token) throw new Error('stack d client_credentials: no access_token')
    return body.access_token
  },
}
export default driver

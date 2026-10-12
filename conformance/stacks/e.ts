// Stack e: the stack-d app with SpiceDB instead of Cerbos (AUTHZ=spicedb): Better Auth + organization
// plugin + SpiceDB. SPEC §10, §15. Login path is d's (the authz engine changes neither sign-in nor
// tokens): email/password with the session token from `set-auth-token` (bearer plugin); apps/agents
// use the OAuth provider's client_credentials grant. Suspension (§15.3) is enforced inside Better
// Auth, as in d.
// features: ['idp-tenancy'] opts into tests/idp-tenancy.test.ts (SPEC §15.2, §15.3).
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App, which also hosts Better Auth (SPEC table: port 8087). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8087`
/** RFC 8707 resource the app accepts as token audience (stacks/e/compose.yaml API_RESOURCE). */
const apiResource = process.env.E_API_RESOURCE ?? 'urn:platform-spike:api'

async function fail(what: string, res: Response): Promise<never> {
  throw new Error(`stack e ${what}: HTTP ${res.status} ${await res.text().catch(() => '')}`)
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
    if (!token) throw new Error('stack e sign-in: no set-auth-token header (bearer plugin)')
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
    if (!body.access_token) throw new Error('stack e client_credentials: no access_token')
    return body.access_token
  },
}
export default driver

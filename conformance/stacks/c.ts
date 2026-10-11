// Stack c: TypeScript (Hono) app + Better Auth (in the app) + Cerbos. SPEC §10, §11.
// Users: Better Auth email/password sign-in; the bearer plugin returns the session token in the
// `set-auth-token` header. Apps/agents: Better Auth OAuth provider, client_credentials grant for a
// JWT access token (aud = the API resource, scope `api`). Only the app port (8083) is needed.
import type { StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App, which also hosts Better Auth (SPEC table: port 8083). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8083`
/** RFC 8707 resource the app accepts as token audience (stacks/c/compose.yaml API_RESOURCE). */
const apiResource = process.env.C_API_RESOURCE ?? 'urn:platform-spike:api'

async function fail(what: string, res: Response): Promise<never> {
  throw new Error(`stack c ${what}: HTTP ${res.status} ${await res.text().catch(() => '')}`)
}

const driver: StackDriver = {
  baseUrl,
  async loginUser(email, password) {
    const res = await fetch(`${baseUrl}/api/auth/sign-in/email`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    if (!res.ok) return fail('sign-in', res)
    const token = res.headers.get('set-auth-token')
    if (!token) throw new Error('stack c sign-in: no set-auth-token header (bearer plugin)')
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
    if (!body.access_token) throw new Error('stack c client_credentials: no access_token')
    return body.access_token
  },
}
export default driver

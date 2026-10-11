// Stack c: TypeScript (Hono) app + Better Auth (in the app) + Cerbos. SPEC §10, §11.
import { DriverNotImplementedError, type StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App, which also hosts Better Auth (SPEC table: port 8083). */
const baseUrl = process.env.BASE_URL ?? `http://${env.host}:8083`

const driver: StackDriver = {
  baseUrl,
  async loginUser(_email, _password) {
    // TODO(stack c): Better Auth email/password sign-in (e.g. POST /api/auth/sign-in/email) returning
    // a bearer token (bearer or JWT plugin); return that token.
    throw new DriverNotImplementedError('c', 'loginUser', 'Better Auth email/password sign-in returning a bearer/JWT token')
  },
  async loginClient(_clientId, _clientSecret) {
    // TODO(stack c): exchange app/agent credentials via the Better Auth mechanism the app uses
    // (API key plugin or OAuth client credentials); return the bearer token.
    throw new DriverNotImplementedError('c', 'loginClient', 'Better Auth API key or OAuth client credentials')
  },
}
export default driver

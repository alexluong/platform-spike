// Stack h2: stack h's Go app with the in-app OpenID provider (zitadel/oidc pkg/op), pools as rows,
// one issuer per pool. SPEC §10, §16. features: ['multi-pool'] opts into tests/multi-pool.test.ts
// (SPEC §16.6). Only the app port (8098) is needed.
//
// STUB: the builder replaces every method below with the stack's real, headless login path
// (start from stacks/h.ts: authorize → POST /login → code → token, per pool issuer).
import { DriverNotImplementedError, type StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App (SPEC §16 table: port 8098). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8098`

const todo = (method: string, what: string) => new DriverNotImplementedError('h2', method, what)

const driver: StackDriver = {
  baseUrl,
  features: ['multi-pool'],
  async loginUser(_email, _password) {
    throw todo(
      'loginUser',
      'auth code + PKCE as in stacks/h.ts, at the issuer of the pool the account lives in: kind platform → pool `workforce`, user → pool `platform`, customer → pool `shop`.',
    )
  },
  async loginClient(_clientId, _clientSecret) {
    throw todo('loginClient', 'client_credentials at the token endpoint of the pool that holds the app/agent client (as in stacks/h.ts).')
  },
  async loginTenant(_merchantId, _kind, _email, _password) {
    throw todo(
      'loginTenant',
      "auth code + PKCE at the merchant's tenant pool issuer (GET /api/merchants/:mid/identity → issuer), staff vs customers kept apart by kind. Must reject while the merchant is suspended.",
    )
  },
  async loginWithShop(_merchantId, _shopEmail, _shopPassword) {
    throw todo(
      'loginWithShop',
      "Start auth code + PKCE at the merchant's tenant pool (customers), choose Shop: follow the redirect to the shop pool's authorize, log in there as the Shop buyer, follow the callback back to the tenant pool, exchange the code; return the tenant-issued token. Must reject while the merchant is suspended.",
    )
  },
}
export default driver

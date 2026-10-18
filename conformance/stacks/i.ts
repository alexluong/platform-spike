// Stack i: stack a's Go app + Zitadel with one instance per merchant on one deployment + SpiceDB.
// SPEC §10, §16. features: ['multi-pool'] opts into tests/multi-pool.test.ts (SPEC §16.6).
//
// STUB: the builder replaces every method below with the stack's real, headless login path.
// Pools (SPEC §16.1): workforce instance (platform staff), platform instance with orgs `accounts`
// (merchant owners, partners) and `shop` (Shop buyers), one instance per merchant with orgs
// `staff` and `customers`. The instance is picked by the Host / `x-zitadel-instance-host` header.
import { DriverNotImplementedError, type StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App (SPEC §16 table: port 8096). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8096`
/** Zitadel (SPEC §16 table: port 8097), only if the driver talks to it directly. Override with I_ZITADEL_URL. */
export const zitadelUrl = process.env.I_ZITADEL_URL ?? `http://${env.host}:8097`

const todo = (method: string, what: string) => new DriverNotImplementedError('i', method, what)

const driver: StackDriver = {
  baseUrl,
  features: ['multi-pool'],
  async loginUser(_email, _password) {
    throw todo(
      'loginUser',
      "OIDC auth code + PKCE as in stacks/a.ts, against the pool the account lives in: kind platform → the `workforce` instance, user → the `platform` instance (org `accounts`), customer → the `platform` instance (org `shop`). Pick the instance the way the app does (driver-config / directory), not by guessing hosts.",
    )
  },
  async loginClient(_clientId, _clientSecret) {
    throw todo('loginClient', 'client_credentials at the token endpoint of the instance that holds the app/agent machine user (as in stacks/a.ts).')
  },
  async loginTenant(_merchantId, _kind, _email, _password) {
    throw todo(
      'loginTenant',
      "OIDC auth code + PKCE at the merchant's own Zitadel instance (org `staff` for kind user, `customers` for kind customer); find the instance from the app (GET /api/merchants/:mid/identity → issuer, or a test-mode driver-config per merchant). Must reject while the merchant is suspended.",
    )
  },
  async loginWithShop(_merchantId, _shopEmail, _shopPassword) {
    throw todo(
      'loginWithShop',
      "Start auth code + PKCE at the merchant's instance (org `customers`), pick the Shop generic OIDC IdP (idp intent), log in at the platform instance (org `shop`) as the Shop buyer, follow the callback back to the merchant's instance, finish there; return the merchant-instance token. Must reject while the merchant is suspended.",
    )
  },
}
export default driver

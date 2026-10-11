// Stack b: Go app + Ory Kratos + Hydra (OIDC) + OpenFGA. SPEC §10, §11.
import { DriverNotImplementedError, type StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App (SPEC table: port 8082). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8082`
/** TODO(stack b): set the real published ports for Kratos public, Hydra public and Hydra admin. */
export const kratosPublicUrl = process.env.KRATOS_PUBLIC_URL ?? `http://${env.host}:4433`
export const hydraPublicUrl = process.env.HYDRA_PUBLIC_URL ?? `http://${env.host}:4444`
export const hydraAdminUrl = process.env.HYDRA_ADMIN_URL ?? `http://${env.host}:4445`

const driver: StackDriver = {
  baseUrl,
  async loginUser(_email, _password) {
    // TODO(stack b): Kratos native (API) login flow with password, then Hydra authorization code
    // flow; accept the login and consent challenges through Hydra's admin API (standing in for the
    // login UI); exchange the code; return the access token.
    throw new DriverNotImplementedError('b', 'loginUser', 'Kratos native login flow + Hydra auth code with login/consent accepted via admin API')
  },
  async loginClient(_clientId, _clientSecret) {
    // TODO(stack b): Hydra client_credentials grant.
    throw new DriverNotImplementedError('b', 'loginClient', 'Hydra client_credentials grant')
  },
}
export default driver

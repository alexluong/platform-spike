// Stack a: Go app + Zitadel (OIDC) + SpiceDB. SPEC §10, §11.
import { DriverNotImplementedError, type StackDriver } from '../src/driver'
import { env } from '../src/env'

/** App (SPEC table: port 8081). */
const baseUrl = process.env.APP_URL ?? `http://${env.host}:8081`
/** Zitadel, published by the stack's compose file. TODO(stack a): set the real published port. */
export const zitadelUrl = process.env.ZITADEL_URL ?? `http://${env.host}:8080`

const driver: StackDriver = {
  baseUrl,
  async loginUser(_email, _password) {
    // TODO(stack a): OIDC authorization code flow + PKCE driven headless through Zitadel's
    // Session API (create session with user + password check) and the OIDC auth-request
    // finalize call; exchange the code at the token endpoint; return the access token.
    throw new DriverNotImplementedError('a', 'loginUser', 'Zitadel session API + OIDC authorization code (+PKCE), headless')
  },
  async loginClient(_clientId, _clientSecret) {
    // TODO(stack a): OAuth2 client_credentials grant at Zitadel's token endpoint.
    throw new DriverNotImplementedError('a', 'loginClient', 'Zitadel client_credentials grant')
  },
}
export default driver

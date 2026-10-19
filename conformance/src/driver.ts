// SPEC §10: one driver per stack, in conformance/stacks/<stack>.ts.
export interface StackDriver {
  baseUrl: string
  /** Bearer token for /api, obtained through the stack's real, headless login path. */
  loginUser(email: string, password: string): Promise<string>
  /** Bearer token for apps and agents (client credentials or the stack's equivalent). */
  loginClient(clientId: string, clientSecret: string): Promise<string>
  /**
   * Optional test groups the stack opts into (SPEC §15.4: `idp-tenancy` for stacks d, e, a2;
   * SPEC §16.6: `multi-pool` for stacks i, h2).
   */
  features?: string[]
  /**
   * SPEC §16.4 (`multi-pool`): customer token from the merchant's tenant pool (v4.1: tenant pools
   * hold customers only; staff are platform accounts and use loginUser), through the stack's real
   * login path. Rejects when the pool refuses (wrong password, another pool's identity, merchant
   * suspended).
   */
  loginTenant?(merchantId: string, email: string, password: string): Promise<string>
  /**
   * SPEC §16.4/§16.5 (`multi-pool`): "Sign in with Shop". Log in at the merchant's tenant customers
   * pool with the Shop account as the upstream OIDC provider; the driver drives both legs and returns
   * a token issued by the merchant's tenant pool. Rejects when either leg refuses.
   */
  loginWithShop?(merchantId: string, shopEmail: string, shopPassword: string): Promise<string>
}

export class DriverNotImplementedError extends Error {
  constructor(stack: string, method: string, todo: string) {
    super(`driver for stack ${stack}: ${method} not implemented (conformance/stacks/${stack}.ts). TODO: ${todo}`)
    this.name = 'DriverNotImplementedError'
  }
}

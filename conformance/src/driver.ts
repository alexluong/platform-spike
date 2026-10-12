// SPEC §10: one driver per stack, in conformance/stacks/<stack>.ts.
export interface StackDriver {
  baseUrl: string
  /** Bearer token for /api, obtained through the stack's real, headless login path. */
  loginUser(email: string, password: string): Promise<string>
  /** Bearer token for apps and agents (client credentials or the stack's equivalent). */
  loginClient(clientId: string, clientSecret: string): Promise<string>
  /** Optional test groups the stack opts into (SPEC §15.4: `idp-tenancy` for stacks d, e, a2). */
  features?: string[]
}

export class DriverNotImplementedError extends Error {
  constructor(stack: string, method: string, todo: string) {
    super(`driver for stack ${stack}: ${method} not implemented (conformance/stacks/${stack}.ts). TODO: ${todo}`)
    this.name = 'DriverNotImplementedError'
  }
}

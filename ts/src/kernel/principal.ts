// Who is calling, after the token was validated and mapped to app records.
export type PrincipalKind = 'platform' | 'user' | 'customer' | 'app' | 'agent'

export interface Principal {
  kind: PrincipalKind
  /** user id (platform/user/customer), app id, or agent id */
  id: string
  merchantId?: string
  platformRole?: 'platform_admin' | 'support'
  /** Raw Authorization header; only the identity adapter may interpret it. */
  credential: string
}

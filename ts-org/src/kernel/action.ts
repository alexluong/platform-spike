// Action = unit of capability (SPEC §1.1). Every operation is one ActionDef in the registry; one
// executor runs them all. HTTP handlers only parse the request into `input`.
import type { z } from 'zod'
import type { Queryable, Tx } from '../db/client.js'
import type { Action, Authorizer, Decision, Resource } from './authz.js'
import type { Principal, PrincipalKind } from './principal.js'
import type { Tenancy } from './tenancy.js'

/** One engine check the executor must pass before `run`. */
export interface Check {
  action: string
  resource: Resource
  context?: Record<string, unknown>
}

/** can() bound to the calling principal; what actions use for guardrails. */
export interface Can {
  (action: string, resource: Resource, context?: Record<string, unknown>): Promise<Decision>
  many(actions: string[], resource: Resource, context?: Record<string, unknown>): Promise<Decision[]>
}

export interface AuthorizeCtx {
  principal: Principal
  db: Queryable
}

export interface RunCtx {
  principal: Principal
  tx: Tx
  can: Can
  /** The IdP's tenancy side (organizations, members, invitations), bound to `tx`: its writes commit
   *  or roll back with the action's own. */
  idp: Tenancy
  /** Record a domain event in the outbox, committed with the change. */
  emit(payload: Record<string, unknown>): void
}

export interface ActionDef<I = any, O = any> {
  /** `<module>.<verb>`; catalog actions use their catalog id. */
  id: string
  input: z.ZodType<I>
  /** Reads skip the outbox. */
  mutating: boolean
  /** No authentication at all (public product list). */
  public?: boolean
  /** Token/scope check: which credential kinds may call this at all. Default: any authenticated. */
  kinds?: readonly PrincipalKind[]
  /** Relationship + condition checks, through can(). `null` = no engine check (customer actions,
   *  checked in SQL). May throw not_found while resolving the resource. */
  authorize(ctx: AuthorizeCtx, input: I): Promise<Check | Check[] | null>
  run(ctx: RunCtx, input: I): Promise<O>
}

export const defineAction = <I, O>(def: ActionDef<I, O>) => def

export type Registry = ReadonlyMap<string, ActionDef>

export function buildRegistry(...groups: ActionDef[][]): Registry {
  const m = new Map<string, ActionDef>()
  for (const def of groups.flat()) {
    if (m.has(def.id)) throw new Error(`duplicate action ${def.id}`)
    m.set(def.id, def)
  }
  return m
}

export type { Action, Authorizer }

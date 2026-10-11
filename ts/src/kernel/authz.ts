// One can() in OpenID AuthZEN 1.0 Access Evaluation shape (in-process). The engine sits behind it.
// Callers pass ids; the adapter's PIP loads attributes (Cerbos is stateless: the app is the PIP).

export interface Subject {
  type: string // principal kind
  id: string
  properties?: Record<string, unknown>
}
export interface Resource {
  type: 'platform' | 'merchant' | 'store'
  id: string
  properties?: Record<string, unknown>
}
export interface Action {
  name: string
  properties?: Record<string, unknown>
}
export interface EvaluationRequest {
  subject: Subject
  action: Action
  resource: Resource
  context?: Record<string, unknown>
}
export interface Decision {
  decision: boolean
  context?: { reason?: string; breakGlass?: boolean; [k: string]: unknown }
}

/** AuthZEN Access Evaluations: shared defaults + per-item overrides. */
export interface EvaluationsRequest {
  subject: Subject
  resource?: Resource
  context?: Record<string, unknown>
  evaluations: Array<{ action: Action; resource?: Resource; context?: Record<string, unknown> }>
}

export interface Authorizer {
  evaluate(req: EvaluationRequest): Promise<Decision>
  evaluateMany(req: EvaluationsRequest): Promise<Decision[]>
  /** Resource search for one action: ids of `type` (within `filter`) the subject may act on. */
  searchResources?(req: {
    subject: Subject
    action: Action
    resource: { type: Resource['type']; properties?: Record<string, unknown> }
  }): Promise<ResourceFilter>
}

/** Result of a resource search, as a filter the caller can turn into SQL. */
export type ResourceFilter = { kind: 'all' } | { kind: 'none' } | { kind: 'ids'; ids: string[] } | { kind: 'unsupported' }

export const subjectOf = (p: { kind: string; id: string }): Subject => ({ type: p.kind, id: p.id })

// Thin helpers over @authzed/authzed-node (protobuf-ts messages): connect, build relationships,
// write/delete/read, classify errors. Shared by the authorizer and the relationship sync.
import { protobuf, v1 } from '@authzed/authzed-node'

export type SpiceClient = v1.ZedPromiseClientInterface
export type Rel = v1.Relationship

/** Plaintext gRPC inside the compose network, preshared key. */
export function connect(endpoint: string, presharedKey: string): SpiceClient {
  return v1.NewClient(presharedKey, endpoint, v1.ClientSecurity.INSECURE_PLAINTEXT_CREDENTIALS).promises
}

/** The single platform object (Go uses the same id). */
export const PLATFORM_ID = 'main'

export const obj = (objectType: string, objectId: string) => v1.ObjectReference.create({ objectType, objectId })
export const subj = (type: string, id: string, optionalRelation = '') => v1.SubjectReference.create({ object: obj(type, id), optionalRelation })
export const rel = (resource: v1.ObjectReference, relation: string, subject: v1.SubjectReference, opts: { expiresAt?: Date; caveat?: { name: string; context: Record<string, number> } } = {}) =>
  v1.Relationship.create({
    resource,
    relation,
    subject,
    optionalExpiresAt: opts.expiresAt ? protobuf.Timestamp.fromDate(opts.expiresAt) : undefined,
    optionalCaveat: opts.caveat ? v1.ContextualizedCaveat.create({ caveatName: opts.caveat.name, context: protobuf.Struct.fromJson(opts.caveat.context) }) : undefined,
  })

const update = (operation: v1.RelationshipUpdate_Operation) => (rs: Rel[]) => rs.map((relationship) => v1.RelationshipUpdate.create({ operation, relationship }))
export const touch = update(v1.RelationshipUpdate_Operation.TOUCH)
export const del = update(v1.RelationshipUpdate_Operation.DELETE)

export const fullyConsistent = () => v1.Consistency.create({ requirement: { oneofKind: 'fullyConsistent', fullyConsistent: true } })
export const atLeastAsFresh = (token: string) =>
  v1.Consistency.create({ requirement: { oneofKind: 'atLeastAsFresh', atLeastAsFresh: v1.ZedToken.create({ token }) } })

/** Write updates in one transaction; returns the ZedToken (undefined when nothing to write). */
export async function write(c: SpiceClient, updates: v1.RelationshipUpdate[]): Promise<string | undefined> {
  if (updates.length === 0) return undefined
  const r = await c.writeRelationships(v1.WriteRelationshipsRequest.create({ updates }))
  return r.writtenAt?.token
}

export type Filter = { resourceType: string; resourceId?: string; relation?: string; subjectType?: string; subjectId?: string; subjectRelation?: string }

function filter(f: Filter) {
  return v1.RelationshipFilter.create({
    resourceType: f.resourceType,
    optionalResourceId: f.resourceId ?? '',
    optionalRelation: f.relation ?? '',
    optionalSubjectFilter: f.subjectType
      ? v1.SubjectFilter.create({
          subjectType: f.subjectType,
          optionalSubjectId: f.subjectId ?? '',
          optionalRelation: f.subjectRelation !== undefined ? v1.SubjectFilter_RelationFilter.create({ relation: f.subjectRelation }) : undefined,
        })
      : undefined,
  })
}

/** Delete every relationship matching the filter; returns the ZedToken. */
export async function deleteWhere(c: SpiceClient, f: Filter): Promise<string | undefined> {
  const r = await c.deleteRelationships(v1.DeleteRelationshipsRequest.create({ relationshipFilter: filter(f) }))
  return r.deletedAt?.token
}

/** Read relationships matching the filter, fully consistent (the relay reconciles against them). */
export async function read(c: SpiceClient, f: Filter): Promise<Rel[]> {
  const rs = await c.readRelationships(v1.ReadRelationshipsRequest.create({ consistency: fullyConsistent(), relationshipFilter: filter(f) }))
  return rs.flatMap((r) => (r.relationship ? [r.relationship] : []))
}

// gRPC status codes (grpc-js is only a transitive dependency)
const GRPC_INVALID_ARGUMENT = 3
const GRPC_FAILED_PRECONDITION = 9

/** Errors SpiceDB will repeat on every retry: the request itself is wrong (schema, arguments). */
export function isPermanent(err: unknown): boolean {
  const code = (err as { code?: unknown })?.code
  return code === GRPC_INVALID_ARGUMENT || code === GRPC_FAILED_PRECONDITION
}

/** Key of a relationship without caveat/expiry: what makes two relationships "the same tuple". */
export const relKey = (r: Rel) => `${r.resource?.objectType}:${r.resource?.objectId}#${r.relation}@${r.subject?.object?.objectType}:${r.subject?.object?.objectId}${r.subject?.optionalRelation ? '#' + r.subject.optionalRelation : ''}`

// Port onto the identity provider's tenancy side (SPEC §15.1): organizations (= merchants),
// membership, invitations. The IdP is the single writer of these records; modules call this port
// inside the request's transaction (an instance is bound to it), and read the records in SQL
// (db/idp-tables.ts). Modules never import the IdP.

export type MerchantStatus = 'active' | 'suspended'

export interface InvitationRecord {
  id: string
  organizationId: string
  email: string
  status: string // pending | accepted | canceled | rejected
  expiresAt: Date
}

export interface Tenancy {
  createOrganization(o: { id: string; name: string }): Promise<void>
  /** false when there is no such organization */
  setStatus(organizationId: string, status: MerchantStatus): Promise<boolean>
  /** throws 409 already_member when the user is in any organization */
  addMember(organizationId: string, userId: string): Promise<void>
  /** false when the user is not a member of that organization */
  removeMember(organizationId: string, userId: string): Promise<boolean>
  invite(organizationId: string, email: string, inviterId: string): Promise<InvitationRecord>
  listInvitations(organizationId: string): Promise<InvitationRecord[]>
  findInvitation(id: string): Promise<InvitationRecord | null>
  /** pending → canceled; false when it wasn't pending */
  cancelInvitation(id: string): Promise<boolean>
  /** The IdP's accept: checks the caller is the recipient, the invitation is pending and unexpired,
   *  then makes the caller a member. Throws 403 / 404 / 409 AppErrors. */
  acceptInvitation(id: string, callerCredential: string): Promise<{ organizationId: string }>
  /** Record in the IdP that an OAuth client (an agent) belongs to an organization; the IdP's token
   *  policy (suspension) follows that link. */
  attachClient(clientId: string, organizationId: string): Promise<void>
}

// Package authz is the authorization port: an AuthZEN 1.0 Access Evaluation
// shaped Authorizer (in-process) and a relationship-sync port fed by the
// outbox. Engines (SpiceDB, OpenFGA, ...) are adapters behind these.
package authz

import (
	"context"
	"errors"
	"time"
)

// Subject is the AuthZEN subject. Type is a principal kind (perm.Kind).
type Subject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource is the AuthZEN resource. Type is a scope type (platform|merchant|store).
type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is the AuthZEN action; Name is a catalog action id.
type Action struct {
	Name string `json:"name"`
}

// Request is one access evaluation.
type Request struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// Decision is the AuthZEN response; Reason goes in context.reason on the wire.
type Decision struct {
	Decision bool   `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// Context keys the platform passes to engines.
const (
	CtxAmountCents = "amountCents" // order.refund condition
)

// Authorizer is the relationship/condition check. It does not know about
// suspension, tenants or principal kinds: the executor's can() handles those
// first and then asks the engine.
type Authorizer interface {
	Evaluate(ctx context.Context, req Request) (Decision, error)
	EvaluateMany(ctx context.Context, reqs []Request) ([]Decision, error)
}

// Event is an engine-neutral fact written to the outbox in the same
// transaction as the change. A RelationSync adapter turns it into engine writes.
// Events carry the full desired state of their object, so re-applying is idempotent.
type Event struct {
	Type string `json:"type"`

	MerchantID string `json:"merchantId,omitempty"`
	StoreID    string `json:"storeId,omitempty"`
	UserID     string `json:"userId,omitempty"`

	// role.upserted / role.deleted
	RoleID           string   `json:"roleId,omitempty"`
	Permissions      []string `json:"permissions,omitempty"`
	RefundLimitCents *int64   `json:"refundLimitCents,omitempty"`
	// role.upserted for the owner role carries the internal owner-manage right.
	OwnerRole bool `json:"ownerRole,omitempty"`

	// assignment.*
	AssignmentID string `json:"assignmentId,omitempty"`
	ScopeType    string `json:"scopeType,omitempty"`
	ScopeID      string `json:"scopeId,omitempty"`

	// app.*
	InstallID string `json:"installId,omitempty"`
	AppID     string `json:"appId,omitempty"`

	// agent_grant.*
	GrantID   string     `json:"grantId,omitempty"`
	AgentID   string     `json:"agentId,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`

	// platform_role.assigned
	PlatformRole string `json:"platformRole,omitempty"`
}

// Event types.
const (
	EvMerchantCreated     = "merchant.created"
	EvMerchantSuspended   = "merchant.suspended"
	EvMerchantReinstated  = "merchant.reinstated"
	EvStoreCreated        = "store.created"
	EvRoleUpserted        = "role.upserted"
	EvRoleDeleted         = "role.deleted"
	EvAssignmentCreated   = "assignment.created"
	EvAssignmentDeleted   = "assignment.deleted"
	EvAppInstalled        = "app.installed"
	EvAppUninstalled      = "app.uninstalled"
	EvAgentGrantCreated   = "agent_grant.created"
	EvAgentGrantRevoked   = "agent_grant.revoked"
	EvBreakGlassOpened    = "break_glass.opened"
	EvPlatformRoleGranted = "platform_role.granted"
)

// RelationSync applies outbox events to the engine. Stateless engines (Cerbos)
// would implement it as a no-op.
//
// Errors are retried forever (in order) unless they wrap ErrPermanent: an event the
// engine will never accept (unknown type, rejected by the schema). Only those are
// dead-lettered. Dropping a transient failure would silently leave a revocation
// (uninstall, unassign, revoke) unapplied.
type RelationSync interface {
	Apply(ctx context.Context, ev Event) error
}

// ErrPermanent marks a RelationSync error that retrying cannot fix.
var ErrPermanent = errors.New("permanent sync error")

// Package spicedb adapts the authz ports to SpiceDB: Authorizer (AuthZEN
// Evaluate/EvaluateMany → CheckPermission/CheckBulkPermissions) and
// RelationSync (outbox events → relationship writes), with ZedToken
// read-your-writes.
package spicedb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/perm"
)

// Client implements authz.Authorizer and authz.RelationSync.
type Client struct {
	api *authzed.Client
	// Latest ZedToken from our own writes. Checks ask for at-least-this-fresh, so a
	// change is visible to the next request. In memory: one app instance in this spike
	// (several instances would keep it in the DB or a shared cache).
	token atomic.Pointer[v1.ZedToken]
}

// New dials SpiceDB (plaintext gRPC inside the compose network).
func New(endpoint, presharedKey string) (*Client, error) {
	api, err := authzed.NewClient(endpoint,
		grpcutil.WithInsecureBearerToken(presharedKey),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &Client{api: api}, nil
}

// WriteSchema writes the generated schema (bootstrap).
func (c *Client) WriteSchema(ctx context.Context) error {
	resp, err := c.api.WriteSchema(ctx, &v1.WriteSchemaRequest{Schema: Schema()})
	if err == nil {
		c.token.Store(resp.WrittenAt)
	}
	return err
}

// Ping checks SpiceDB is reachable and has a schema.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.api.ReadSchema(ctx, &v1.ReadSchemaRequest{})
	return err
}

func (c *Client) consistency() *v1.Consistency {
	if t := c.token.Load(); t != nil {
		return &v1.Consistency{Requirement: &v1.Consistency_AtLeastAsFresh{AtLeastAsFresh: t}}
	}
	return &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}}
}

func (c *Client) remember(t *v1.ZedToken) {
	if t != nil {
		c.token.Store(t)
	}
}

// subjectType maps a principal kind to a schema definition. Customers are never in the engine.
var subjectType = map[string]string{
	string(perm.KindPlatform): "staff",
	string(perm.KindUser):     "user",
	string(perm.KindApp):      "app",
	string(perm.KindAgent):    "agent",
}

var errNoSubject = errors.New("subject kind not modelled in SpiceDB")

func toCheck(req authz.Request) (*v1.CheckBulkPermissionsRequestItem, error) {
	st, ok := subjectType[req.Subject.Type]
	if !ok {
		return nil, errNoSubject
	}
	item := &v1.CheckBulkPermissionsRequestItem{
		Resource:   &v1.ObjectReference{ObjectType: req.Resource.Type, ObjectId: req.Resource.ID},
		Permission: Perm(req.Action.Name),
		Subject:    &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: st, ObjectId: req.Subject.ID}},
	}
	if v, ok := req.Context[authz.CtxAmountCents]; ok {
		s, err := structpb.NewStruct(map[string]any{"amount": v})
		if err != nil {
			return nil, err
		}
		item.Context = s
	}
	return item, nil
}

func decision(p v1.CheckPermissionResponse_Permissionship) authz.Decision {
	switch p {
	case v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION:
		return authz.Decision{Decision: true}
	case v1.CheckPermissionResponse_PERMISSIONSHIP_CONDITIONAL_PERMISSION:
		return authz.Decision{Reason: "missing_context"}
	}
	return authz.Decision{Reason: "denied"}
}

// Evaluate is AuthZEN access evaluation → CheckPermission.
func (c *Client) Evaluate(ctx context.Context, req authz.Request) (authz.Decision, error) {
	item, err := toCheck(req)
	if errors.Is(err, errNoSubject) {
		return authz.Decision{Reason: "denied"}, nil
	} else if err != nil {
		return authz.Decision{}, err
	}
	resp, err := c.api.CheckPermission(ctx, &v1.CheckPermissionRequest{
		Consistency: c.consistency(), Resource: item.Resource, Permission: item.Permission, Subject: item.Subject, Context: item.Context,
	})
	if err != nil {
		return authz.Decision{}, err
	}
	return decision(resp.Permissionship), nil
}

// EvaluateMany is AuthZEN evaluations → CheckBulkPermissions.
func (c *Client) EvaluateMany(ctx context.Context, reqs []authz.Request) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(reqs))
	var items []*v1.CheckBulkPermissionsRequestItem
	var idx []int
	for i, r := range reqs {
		item, err := toCheck(r)
		if errors.Is(err, errNoSubject) {
			out[i] = authz.Decision{Reason: "denied"}
			continue
		} else if err != nil {
			return nil, err
		}
		items = append(items, item)
		idx = append(idx, i)
	}
	if len(items) == 0 {
		return out, nil
	}
	resp, err := c.api.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{Consistency: c.consistency(), Items: items})
	if err != nil {
		return nil, err
	}
	for j, pair := range resp.Pairs {
		switch r := pair.Response.(type) {
		case *v1.CheckBulkPermissionsPair_Item:
			out[idx[j]] = decision(r.Item.Permissionship)
		case *v1.CheckBulkPermissionsPair_Error:
			return nil, fmt.Errorf("bulk check %s: %s", items[j].Permission, r.Error.Message)
		}
	}
	return out, nil
}

// --- relationship sync ---

func obj(t, id string) *v1.ObjectReference { return &v1.ObjectReference{ObjectType: t, ObjectId: id} }

func subj(t, id, rel string) *v1.SubjectReference {
	return &v1.SubjectReference{Object: obj(t, id), OptionalRelation: rel}
}

func rel(res *v1.ObjectReference, relation string, s *v1.SubjectReference) *v1.Relationship {
	return &v1.Relationship{Resource: res, Relation: relation, Subject: s}
}

func expiring(r *v1.Relationship, at *time.Time) *v1.Relationship {
	if at != nil {
		r.OptionalExpiresAt = timestamppb.New(*at)
	}
	return r
}

func touch(rs ...*v1.Relationship) []*v1.RelationshipUpdate {
	out := make([]*v1.RelationshipUpdate, len(rs))
	for i, r := range rs {
		out[i] = &v1.RelationshipUpdate{Operation: v1.RelationshipUpdate_OPERATION_TOUCH, Relationship: r}
	}
	return out
}

func del(rs ...*v1.Relationship) []*v1.RelationshipUpdate {
	out := make([]*v1.RelationshipUpdate, len(rs))
	for i, r := range rs {
		out[i] = &v1.RelationshipUpdate{Operation: v1.RelationshipUpdate_OPERATION_DELETE, Relationship: r}
	}
	return out
}

func (c *Client) write(ctx context.Context, updates []*v1.RelationshipUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	resp, err := c.api.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: updates})
	if err != nil {
		return err
	}
	c.remember(resp.WrittenAt)
	return nil
}

func (c *Client) deleteResource(ctx context.Context, typ, id string) error {
	resp, err := c.api.DeleteRelationships(ctx, &v1.DeleteRelationshipsRequest{
		RelationshipFilter: &v1.RelationshipFilter{ResourceType: typ, OptionalResourceId: id},
	})
	if err != nil {
		return err
	}
	c.remember(resp.DeletedAt)
	return nil
}

var wildcards = []string{"user", "agent", "app"}

// Apply turns one outbox event into relationship writes. Idempotent (TOUCH / DELETE).
func (c *Client) Apply(ctx context.Context, ev authz.Event) error {
	platform := obj("platform", "main")
	switch ev.Type {
	case authz.EvMerchantCreated:
		m := obj("merchant", ev.MerchantID)
		return c.write(ctx, touch(rel(m, "platform", subj("platform", "main", "")), rel(m, "any_user", subj("user", "*", ""))))

	case authz.EvMerchantSuspended, authz.EvMerchantReinstated:
		m := obj("merchant", ev.MerchantID)
		var rs []*v1.Relationship
		for _, t := range wildcards {
			rs = append(rs, rel(m, "suspended", subj(t, "*", "")))
		}
		if ev.Type == authz.EvMerchantSuspended {
			return c.write(ctx, touch(rs...))
		}
		return c.write(ctx, del(rs...))

	case authz.EvStoreCreated:
		s := obj("store", ev.StoreID)
		return c.write(ctx, touch(rel(s, "merchant", subj("merchant", ev.MerchantID, "")), rel(s, "any_user", subj("user", "*", ""))))

	case authz.EvRoleUpserted:
		return c.syncRole(ctx, ev)

	case authz.EvRoleDeleted:
		return c.deleteResource(ctx, "role", ev.RoleID)

	case authz.EvAssignmentCreated:
		b := obj("role_binding", ev.AssignmentID)
		return c.write(ctx, touch(
			rel(b, "subject", subj("user", ev.UserID, "")),
			rel(b, "subject", subj("user", ev.UserID, "delegate")),
			rel(b, "role", subj("role", ev.RoleID, "")),
			rel(obj(ev.ScopeType, ev.ScopeID), "binding", subj("role_binding", ev.AssignmentID, "")),
		))

	case authz.EvAssignmentDeleted:
		if err := c.write(ctx, del(rel(obj(ev.ScopeType, ev.ScopeID), "binding", subj("role_binding", ev.AssignmentID, "")))); err != nil {
			return err
		}
		return c.deleteResource(ctx, "role_binding", ev.AssignmentID)

	case authz.EvAppInstalled:
		i := obj("app_install", ev.InstallID)
		rs := []*v1.Relationship{rel(obj("store", ev.StoreID), "install", subj("app_install", ev.InstallID, ""))}
		for _, p := range ev.Permissions {
			if perm.IsGrantableToApps(p) {
				rs = append(rs, rel(i, Perm(p), subj("app", ev.AppID, "")))
			}
		}
		return c.write(ctx, touch(rs...))

	case authz.EvAppUninstalled:
		if err := c.write(ctx, del(rel(obj("store", ev.StoreID), "install", subj("app_install", ev.InstallID, "")))); err != nil {
			return err
		}
		return c.deleteResource(ctx, "app_install", ev.InstallID)

	case authz.EvAgentGrantCreated:
		g := obj("agent_grant", ev.GrantID)
		rs := []*v1.Relationship{
			expiring(rel(g, "agent", subj("agent", ev.AgentID, "")), ev.ExpiresAt),
			expiring(rel(obj("user", ev.UserID), "delegate", subj("agent_grant", ev.GrantID, "agent")), ev.ExpiresAt),
			rel(obj("store", ev.StoreID), "grant", subj("agent_grant", ev.GrantID, "")),
		}
		for _, p := range ev.Permissions {
			rs = append(rs, expiring(rel(g, Perm(p), subj("agent", ev.AgentID, "")), ev.ExpiresAt))
		}
		return c.write(ctx, touch(rs...))

	case authz.EvAgentGrantRevoked:
		if err := c.write(ctx, del(
			rel(obj("user", ev.UserID), "delegate", subj("agent_grant", ev.GrantID, "agent")),
			rel(obj("store", ev.StoreID), "grant", subj("agent_grant", ev.GrantID, "")),
		)); err != nil {
			return err
		}
		return c.deleteResource(ctx, "agent_grant", ev.GrantID)

	case authz.EvBreakGlassOpened:
		return c.write(ctx, touch(expiring(rel(obj("merchant", ev.MerchantID), "break_glass_viewer", subj("staff", ev.UserID, "")), ev.ExpiresAt)))

	case authz.EvPlatformRoleGranted:
		relation := map[string]string{"platform_admin": "admin", "support": "support"}[ev.PlatformRole]
		if relation == "" {
			return fmt.Errorf("unknown platform role %q", ev.PlatformRole)
		}
		return c.write(ctx, touch(rel(platform, relation, subj("staff", ev.UserID, ""))))
	}
	return fmt.Errorf("spicedb: unhandled event %q", ev.Type)
}

func relKey(r *v1.Relationship) string {
	return r.Relation + "@" + r.Subject.Object.ObjectType + ":" + r.Subject.Object.ObjectId
}

// syncRole makes role:<id> hold exactly the event's permissions: read current, delete extras, touch desired.
func (c *Client) syncRole(ctx context.Context, ev authz.Event) error {
	ro := obj("role", ev.RoleID)
	var desired []*v1.Relationship
	for _, p := range ev.Permissions {
		for _, t := range []string{"user", "agent"} {
			r := rel(ro, Perm(p), subj(t, "*", ""))
			if p == perm.RefundAction && ev.RefundLimitCents != nil {
				ctxStruct, err := structpb.NewStruct(map[string]any{"limit": *ev.RefundLimitCents})
				if err != nil {
					return err
				}
				r.OptionalCaveat = &v1.ContextualizedCaveat{CaveatName: "refund_limit", Context: ctxStruct}
			}
			desired = append(desired, r)
		}
	}
	if ev.OwnerRole {
		desired = append(desired, rel(ro, "role_manage_owner", subj("user", "*", "")))
	}
	want := map[string]bool{}
	for _, r := range desired {
		want[relKey(r)] = true
	}

	stream, err := c.api.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		Consistency:        &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		RelationshipFilter: &v1.RelationshipFilter{ResourceType: "role", OptionalResourceId: ev.RoleID},
	})
	if err != nil {
		return err
	}
	var updates []*v1.RelationshipUpdate
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if !want[relKey(resp.Relationship)] {
			r := resp.Relationship
			r.OptionalCaveat = nil
			updates = append(updates, del(r)...)
		}
	}
	updates = append(updates, touch(desired...)...)
	return c.write(ctx, updates)
}

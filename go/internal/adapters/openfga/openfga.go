// Package openfga adapts the authz ports to OpenFGA: Authorizer (AuthZEN
// Evaluate/EvaluateMany → Check/BatchCheck) and RelationSync (outbox events →
// tuple writes), with HIGHER_CONSISTENCY checks for read-your-writes.
package openfga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	fga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/perm"
)

// StoreName is the OpenFGA store the platform uses.
const StoreName = "platform-spike"

// maxTuplesPerWrite is OpenFGA's default per-request limit (OPENFGA_MAX_TUPLES_PER_WRITE).
const maxTuplesPerWrite = 100

// Client implements authz.Authorizer and authz.RelationSync.
type Client struct {
	api     *client.OpenFgaClient
	storeID string
	modelID string
	now     func() time.Time
}

var higher = fga.CONSISTENCYPREFERENCE_HIGHER_CONSISTENCY

func newAPI(apiURL, storeID, modelID string) (*client.OpenFgaClient, error) {
	return client.NewSdkClient(&client.ClientConfiguration{ApiUrl: apiURL, StoreId: storeID, AuthorizationModelId: modelID})
}

// findStore returns the id of the store named name, or "".
func findStore(ctx context.Context, api *client.OpenFgaClient, name string) (string, error) {
	resp, err := api.ListStores(ctx).Options(client.ClientListStoresOptions{Name: &name}).Execute()
	if err != nil {
		return "", err
	}
	for _, s := range resp.Stores {
		if s.Name == name {
			return s.Id, nil
		}
	}
	return "", nil
}

// New connects to the platform store and pins its latest model (both created by Bootstrap).
func New(ctx context.Context, apiURL string) (*Client, error) {
	api, err := newAPI(apiURL, "", "")
	if err != nil {
		return nil, err
	}
	storeID, err := findStore(ctx, api, StoreName)
	if err != nil {
		return nil, err
	}
	if storeID == "" {
		return nil, fmt.Errorf("openfga: store %q not found (bootstrap not run?)", StoreName)
	}
	api, err = newAPI(apiURL, storeID, "")
	if err != nil {
		return nil, err
	}
	m, err := api.ReadLatestAuthorizationModel(ctx).Execute()
	if err != nil {
		return nil, err
	}
	if m.AuthorizationModel == nil {
		return nil, fmt.Errorf("openfga: store %q has no model (bootstrap not run?)", StoreName)
	}
	modelID := m.AuthorizationModel.Id
	if api, err = newAPI(apiURL, storeID, modelID); err != nil {
		return nil, err
	}
	return &Client{api: api, storeID: storeID, modelID: modelID, now: time.Now}, nil
}

// Bootstrap creates the store if missing and writes the generated model unless
// the latest model already equals it. Idempotent. Returns store and model ids.
func Bootstrap(ctx context.Context, apiURL string) (storeID, modelID string, err error) {
	api, err := newAPI(apiURL, "", "")
	if err != nil {
		return "", "", err
	}
	if storeID, err = findStore(ctx, api, StoreName); err != nil {
		return "", "", err
	}
	if storeID == "" {
		s, err := api.CreateStore(ctx).Body(client.ClientCreateStoreRequest{Name: StoreName}).Execute()
		if err != nil {
			return "", "", err
		}
		storeID = s.Id
	}
	if api, err = newAPI(apiURL, storeID, ""); err != nil {
		return "", "", err
	}
	want, err := modelRequest()
	if err != nil {
		return "", "", err
	}
	latest, err := api.ReadLatestAuthorizationModel(ctx).Execute()
	if err != nil {
		var nf fga.FgaApiNotFoundError
		if !errors.As(err, &nf) {
			return "", "", err
		}
	}
	if latest != nil && latest.AuthorizationModel != nil && sameModel(want, latest.AuthorizationModel) {
		return storeID, latest.AuthorizationModel.Id, nil
	}
	resp, err := api.WriteAuthorizationModel(ctx).Body(want).Execute()
	if err != nil {
		return "", "", err
	}
	return storeID, resp.AuthorizationModelId, nil
}

// modelRequest converts the generated DSL to the SDK's request type. The
// language package yields a proto; the SDK's JSON tags mix proto names
// (type_definitions) with camelCase (computedUserset, tupleToUserset), so
// neither protojson mode decodes into it as is: rename the two camelCase keys.
func modelRequest() (client.ClientWriteAuthorizationModelRequest, error) {
	var req client.ClientWriteAuthorizationModelRequest
	pb, err := transformer.TransformDSLToProto(Model())
	if err != nil {
		return req, err
	}
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(pb)
	if err != nil {
		return req, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return req, err
	}
	raw, err = json.Marshal(renameKeys(generic, map[string]string{"computed_userset": "computedUserset", "tuple_to_userset": "tupleToUserset"}))
	if err != nil {
		return req, err
	}
	return req, json.Unmarshal(raw, &req)
}

func renameKeys(v any, names map[string]string) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if n, ok := names[k]; ok {
				k = n
			}
			out[k] = renameKeys(val, names)
		}
		return out
	case []any:
		for i := range x {
			x[i] = renameKeys(x[i], names)
		}
		return x
	}
	return v
}

// sameModel compares type definitions and conditions as canonical JSON.
func sameModel(want client.ClientWriteAuthorizationModelRequest, got *fga.AuthorizationModel) bool {
	canon := func(v any) any {
		b, _ := json.Marshal(v)
		var out any
		_ = json.Unmarshal(b, &out)
		return out
	}
	return reflect.DeepEqual(canon(want.TypeDefinitions), canon(got.TypeDefinitions)) &&
		reflect.DeepEqual(canon(want.Conditions), canon(got.Conditions)) &&
		want.SchemaVersion == got.SchemaVersion
}

// Ping checks OpenFGA answers for our store and model.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.api.ReadAuthorizationModel(ctx).Execute()
	return err
}

// --- checks ---

// subjectType maps a principal kind to a model type. Customers are never in the engine.
var subjectType = map[string]string{
	string(perm.KindPlatform): "staff",
	string(perm.KindUser):     "user",
	string(perm.KindApp):      "app",
	string(perm.KindAgent):    "agent",
}

var errNoSubject = errors.New("subject kind not modelled in OpenFGA")

func ref(typ, id string) string { return typ + ":" + id }

func (c *Client) toCheck(req authz.Request) (client.ClientCheckRequest, error) {
	st, ok := subjectType[req.Subject.Type]
	if !ok {
		return client.ClientCheckRequest{}, errNoSubject
	}
	// current_time feeds not_expired (agent grants, break-glass): expiry without a cleanup job.
	cctx := map[string]any{"current_time": c.now().UTC().Format(time.RFC3339Nano)}
	if v, ok := req.Context[authz.CtxAmountCents]; ok {
		cctx["amount"] = v
	}
	return client.ClientCheckRequest{
		User: ref(st, req.Subject.ID), Relation: Rel(req.Action.Name), Object: ref(req.Resource.Type, req.Resource.ID), Context: &cctx,
	}, nil
}

// Evaluate is AuthZEN access evaluation → Check (HIGHER_CONSISTENCY: sees our own latest writes).
func (c *Client) Evaluate(ctx context.Context, req authz.Request) (authz.Decision, error) {
	body, err := c.toCheck(req)
	if errors.Is(err, errNoSubject) {
		return authz.Decision{Reason: "denied"}, nil
	} else if err != nil {
		return authz.Decision{}, err
	}
	resp, err := c.api.Check(ctx).Body(body).Options(client.ClientCheckOptions{Consistency: &higher}).Execute()
	if err != nil {
		return authz.Decision{}, err
	}
	if resp.GetAllowed() {
		return authz.Decision{Decision: true}, nil
	}
	return authz.Decision{Reason: "denied"}, nil
}

// EvaluateMany is AuthZEN evaluations → server-side BatchCheck (the SDK chunks by 50).
func (c *Client) EvaluateMany(ctx context.Context, reqs []authz.Request) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(reqs))
	var items []client.ClientBatchCheckItem
	for i, r := range reqs {
		body, err := c.toCheck(r)
		if errors.Is(err, errNoSubject) {
			out[i] = authz.Decision{Reason: "denied"}
			continue
		} else if err != nil {
			return nil, err
		}
		items = append(items, client.ClientBatchCheckItem{
			User: body.User, Relation: body.Relation, Object: body.Object, Context: body.Context, CorrelationId: strconv.Itoa(i),
		})
	}
	if len(items) == 0 {
		return out, nil
	}
	resp, err := c.api.BatchCheck(ctx).Body(client.ClientBatchCheckRequest{Checks: items}).
		Options(client.BatchCheckOptions{Consistency: &higher}).Execute()
	if err != nil {
		return nil, err
	}
	results := resp.GetResult()
	for _, it := range items {
		i, _ := strconv.Atoi(it.CorrelationId)
		res, ok := results[it.CorrelationId]
		if !ok {
			return nil, fmt.Errorf("batch check: no result for %s#%s", it.Object, it.Relation)
		}
		if res.Error != nil {
			return nil, fmt.Errorf("batch check %s#%s: %s", it.Object, it.Relation, res.Error.GetMessage())
		}
		if res.GetAllowed() {
			out[i] = authz.Decision{Decision: true}
		} else {
			out[i] = authz.Decision{Reason: "denied"}
		}
	}
	return out, nil
}

// --- relationship sync ---

func tk(object, relation, user string) client.ClientTupleKey {
	return client.ClientTupleKey{Object: object, Relation: relation, User: user}
}

func withCond(t client.ClientTupleKey, name string, ctx map[string]any) client.ClientTupleKey {
	t.Condition = &fga.RelationshipCondition{Name: name, Context: &ctx}
	return t
}

// expiring puts a tuple under not_expired (no condition when at is nil).
func expiring(t client.ClientTupleKey, at *time.Time) client.ClientTupleKey {
	if at == nil {
		return t
	}
	return withCond(t, "not_expired", map[string]any{"expires_at": at.UTC().Format(time.RFC3339Nano)})
}

func noCond(t client.ClientTupleKey) client.ClientTupleKeyWithoutCondition {
	return client.ClientTupleKeyWithoutCondition{Object: t.Object, Relation: t.Relation, User: t.User}
}

// ignoreConflicts makes writes idempotent: re-applying an outbox event (or a
// TOUCH-like write) must not fail on tuples that already exist / are already gone.
var ignoreConflicts = client.ClientWriteOptions{Conflict: client.ClientWriteConflictOptions{
	OnDuplicateWrites: client.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE,
	OnMissingDeletes:  client.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE,
}}

// write sends writes and deletes, in requests of at most 100 tuples. Each request is
// atomic; a change larger than that is not (none of ours is, in practice).
func (c *Client) write(ctx context.Context, writes []client.ClientTupleKey, deletes []client.ClientTupleKeyWithoutCondition) error {
	for len(writes) > 0 || len(deletes) > 0 {
		var w []client.ClientTupleKey
		var d []client.ClientTupleKeyWithoutCondition
		n := min(len(deletes), maxTuplesPerWrite)
		d, deletes = deletes[:n], deletes[n:]
		n = min(len(writes), maxTuplesPerWrite-len(d))
		w, writes = writes[:n], writes[n:]
		if _, err := c.api.Write(ctx).Body(client.ClientWriteRequest{Writes: w, Deletes: d}).Options(ignoreConflicts).Execute(); err != nil {
			return err
		}
	}
	return nil
}

// upsert writes tuples whose condition context may differ from what is stored
// (a new break-glass expiry, a changed refund limit). OpenFGA has no TOUCH: a
// write of an existing tuple with another condition fails even with
// on_duplicate=ignore, and one request may not delete and write the same tuple.
// So: delete, then write (two requests; a short window without the tuple).
func (c *Client) upsert(ctx context.Context, ts ...client.ClientTupleKey) error {
	dels := make([]client.ClientTupleKeyWithoutCondition, len(ts))
	for i, t := range ts {
		dels[i] = noCond(t)
	}
	if err := c.write(ctx, nil, dels); err != nil {
		return err
	}
	return c.write(ctx, ts, nil)
}

// readObject lists every tuple on object (all relations), paging through Read.
func (c *Client) readObject(ctx context.Context, object string) ([]fga.Tuple, error) {
	var out []fga.Tuple
	var token *string
	pageSize := int32(100)
	for {
		resp, err := c.api.Read(ctx).Body(client.ClientReadRequest{Object: &object}).
			Options(client.ClientReadOptions{PageSize: &pageSize, ContinuationToken: token, Consistency: &higher}).Execute()
		if err != nil {
			return nil, err
		}
		out = append(out, resp.Tuples...)
		if resp.ContinuationToken == "" {
			return out, nil
		}
		t := resp.ContinuationToken
		token = &t
	}
}

// deleteObject deletes every tuple on object. OpenFGA has no delete-by-filter
// (SpiceDB DeleteRelationships), so: read in pages, delete in batches.
func (c *Client) deleteObject(ctx context.Context, object string) error {
	ts, err := c.readObject(ctx, object)
	if err != nil {
		return err
	}
	dels := make([]client.ClientTupleKeyWithoutCondition, len(ts))
	for i, t := range ts {
		dels[i] = noCond(t.Key)
	}
	return c.write(ctx, nil, dels)
}

var wildcards = []string{"user:*", "agent:*", "app:*"}

// Apply turns one outbox event into tuple writes. Idempotent (duplicates and missing deletes ignored).
func (c *Client) Apply(ctx context.Context, ev authz.Event) error {
	switch ev.Type {
	case authz.EvMerchantCreated:
		m := ref("merchant", ev.MerchantID)
		return c.write(ctx, []client.ClientTupleKey{tk(m, "platform", "platform:main"), tk(m, "any_user", "user:*")}, nil)

	case authz.EvMerchantSuspended, authz.EvMerchantReinstated:
		m := ref("merchant", ev.MerchantID)
		var ts []client.ClientTupleKey
		var ds []client.ClientTupleKeyWithoutCondition
		for _, u := range wildcards {
			ts = append(ts, tk(m, "suspended", u))
			ds = append(ds, noCond(tk(m, "suspended", u)))
		}
		if ev.Type == authz.EvMerchantSuspended {
			return c.write(ctx, ts, nil)
		}
		return c.write(ctx, nil, ds)

	case authz.EvStoreCreated:
		s := ref("store", ev.StoreID)
		return c.write(ctx, []client.ClientTupleKey{tk(s, "merchant", ref("merchant", ev.MerchantID)), tk(s, "any_user", "user:*")}, nil)

	case authz.EvRoleUpserted:
		return c.syncRole(ctx, ev)

	case authz.EvRoleDeleted:
		return c.deleteObject(ctx, ref("role", ev.RoleID))

	case authz.EvAssignmentCreated:
		b := ref("role_binding", ev.AssignmentID)
		return c.write(ctx, []client.ClientTupleKey{
			tk(b, "subject", ref("user", ev.UserID)),
			tk(b, "subject", ref("user", ev.UserID)+"#delegate"),
			tk(b, "role", ref("role", ev.RoleID)),
			tk(ref(ev.ScopeType, ev.ScopeID), "binding", b),
		}, nil)

	case authz.EvAssignmentDeleted:
		b := ref("role_binding", ev.AssignmentID)
		if err := c.write(ctx, nil, []client.ClientTupleKeyWithoutCondition{noCond(tk(ref(ev.ScopeType, ev.ScopeID), "binding", b))}); err != nil {
			return err
		}
		return c.deleteObject(ctx, b)

	case authz.EvAppInstalled:
		i := ref("app_install", ev.InstallID)
		ts := []client.ClientTupleKey{tk(ref("store", ev.StoreID), "install", i)}
		for _, p := range ev.Permissions {
			if perm.IsGrantableToApps(p) {
				ts = append(ts, tk(i, Rel(p), ref("app", ev.AppID)))
			}
		}
		return c.write(ctx, ts, nil)

	case authz.EvAppUninstalled:
		i := ref("app_install", ev.InstallID)
		if err := c.write(ctx, nil, []client.ClientTupleKeyWithoutCondition{noCond(tk(ref("store", ev.StoreID), "install", i))}); err != nil {
			return err
		}
		return c.deleteObject(ctx, i)

	case authz.EvAgentGrantCreated:
		g := ref("agent_grant", ev.GrantID)
		a := ref("agent", ev.AgentID)
		ts := []client.ClientTupleKey{
			expiring(tk(g, "agent", a), ev.ExpiresAt),
			tk(ref("user", ev.UserID), "delegate", g+"#agent"), // expiry comes from g#agent
			tk(ref("store", ev.StoreID), "grant", g),
		}
		for _, p := range ev.Permissions {
			ts = append(ts, expiring(tk(g, Rel(p), a), ev.ExpiresAt))
		}
		return c.write(ctx, ts, nil)

	case authz.EvAgentGrantRevoked:
		g := ref("agent_grant", ev.GrantID)
		if err := c.write(ctx, nil, []client.ClientTupleKeyWithoutCondition{
			noCond(tk(ref("user", ev.UserID), "delegate", g+"#agent")),
			noCond(tk(ref("store", ev.StoreID), "grant", g)),
		}); err != nil {
			return err
		}
		return c.deleteObject(ctx, g)

	case authz.EvBreakGlassOpened:
		// A second break-glass by the same staff member replaces the expiry.
		return c.upsert(ctx, expiring(tk(ref("merchant", ev.MerchantID), "break_glass_viewer", ref("staff", ev.UserID)), ev.ExpiresAt))

	case authz.EvPlatformRoleGranted:
		relation := map[string]string{"platform_admin": "admin", "support": "support"}[ev.PlatformRole]
		if relation == "" {
			return fmt.Errorf("unknown platform role %q", ev.PlatformRole)
		}
		return c.write(ctx, []client.ClientTupleKey{tk("platform:main", relation, ref("staff", ev.UserID))}, nil)
	}
	return fmt.Errorf("openfga: unhandled event %q", ev.Type)
}

// tupleID identifies a tuple including its condition (name + context), so a
// changed refund limit counts as a different tuple.
func tupleID(t client.ClientTupleKey) string {
	s := t.Relation + "@" + t.User
	if t.Condition != nil {
		s += "|" + t.Condition.Name
		if t.Condition.Context != nil {
			b, _ := json.Marshal(normalizeNumbers(*t.Condition.Context))
			s += string(b)
		}
	}
	return s
}

// normalizeNumbers makes int64 and float64 limits compare equal (JSON reads numbers as float64).
func normalizeNumbers(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch n := v.(type) {
		case int64:
			out[k] = float64(n)
		case int:
			out[k] = float64(n)
		default:
			out[k] = v
		}
	}
	return out
}

// syncRole makes role:<id> hold exactly the event's permissions: read current,
// delete extras and changed ones, write missing ones.
func (c *Client) syncRole(ctx context.Context, ev authz.Event) error {
	ro := ref("role", ev.RoleID)
	var desired []client.ClientTupleKey
	for _, p := range ev.Permissions {
		for _, u := range []string{"user:*", "agent:*"} {
			t := tk(ro, Rel(p), u)
			if p == perm.RefundAction && ev.RefundLimitCents != nil {
				t = withCond(t, "refund_limit", map[string]any{"limit": *ev.RefundLimitCents})
			}
			desired = append(desired, t)
		}
	}
	if ev.OwnerRole {
		desired = append(desired, tk(ro, "role_manage_owner", "user:*"))
	}
	want := map[string]bool{}
	for _, t := range desired {
		want[tupleID(t)] = true
	}

	current, err := c.readObject(ctx, ro)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	var dels []client.ClientTupleKeyWithoutCondition
	deleted := map[string]bool{} // relation@user keys being deleted
	for _, t := range current {
		id := tupleID(t.Key)
		have[id] = true
		if !want[id] {
			dels = append(dels, noCond(t.Key))
			deleted[t.Key.Relation+"@"+t.Key.User] = true
		}
	}
	var writes, rewrites []client.ClientTupleKey
	for _, t := range desired {
		if have[tupleID(t)] {
			continue
		}
		if deleted[t.Relation+"@"+t.User] {
			rewrites = append(rewrites, t) // same key, other condition: must go after the delete
		} else {
			writes = append(writes, t)
		}
	}
	if err := c.write(ctx, writes, dels); err != nil {
		return err
	}
	return c.write(ctx, rewrites, nil)
}

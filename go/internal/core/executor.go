package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Auth says how an op is authorized.
type Auth int

const (
	AuthAction Auth = iota // catalog action checked through can() (default)
	AuthAny                // any authenticated principal; Run decides (e.g. lists filtered by canMany)
	AuthPublic             // no token
)

// Target is what the check runs against: the scope resource plus its owning merchant.
type Target struct {
	Resource   authz.Resource
	MerchantID string // "" for platform-scoped targets
	Data       any    // object loaded while resolving, for Run
}

// PlatformTarget is the singleton platform resource.
var PlatformTarget = Target{Resource: authz.Resource{Type: string(perm.ScopePlatform), ID: "main"}}

func MerchantTarget(id string) Target {
	return Target{Resource: authz.Resource{Type: string(perm.ScopeMerchant), ID: id}, MerchantID: id}
}

func StoreTarget(storeID, merchantID string, data any) Target {
	return Target{Resource: authz.Resource{Type: string(perm.ScopeStore), ID: storeID}, MerchantID: merchantID, Data: data}
}

// Op is a registry entry: an action bound to an HTTP route. Handlers are thin:
// resolve the target, then the executor authorizes and runs.
type Op struct {
	Action      string // catalog action id; "" when Auth != AuthAction
	Method      string
	Path        string // Go 1.22 mux pattern, e.g. /api/stores/{sid}/products
	Auth        Auth
	Status      int  // success status (default 200)
	CustomerAlt bool // a customer skips the action check; Run checks ownership in SQL
	Target      func(ctx context.Context, r *Req) (Target, error)
	Context     func(r *Req) (map[string]any, error) // condition context for can()
	Run         func(ctx context.Context, r *Req) (any, error)
}

// Querier is the read side of a pgx pool or tx.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Drainer drains pending outbox rows to the authz engine.
type Drainer interface {
	Drain(ctx context.Context) error
}

// Executor runs every action: authenticate → resolve → can() → run → outbox in the same tx → drain.
type Executor struct {
	DB    *pgxpool.Pool
	Authn *Authenticator
	Authz authz.Authorizer
	Relay Drainer
	Log   *slog.Logger
	Now   func() time.Time
}

// Req is one invocation, passed to Target/Context/Run.
type Req struct {
	P      *Principal
	HTTP   *http.Request
	Body   []byte
	Target Target
	Tx     pgx.Tx
	Now    time.Time

	exec      *Executor
	emitted   int
	auditDone bool
}

func (r *Req) Path(name string) string { return r.HTTP.PathValue(name) }

// Decode parses the JSON body into v (empty body = zero value).
func (r *Req) Decode(v any) error {
	if len(r.Body) == 0 {
		return nil
	}
	if err := json.Unmarshal(r.Body, v); err != nil {
		return BadInput("invalid JSON: " + err.Error())
	}
	return nil
}

// Emit writes an outbox row in the request's transaction.
func (r *Req) Emit(ctx context.Context, ev authz.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO outbox(event) VALUES ($1)`, b); err != nil {
		return err
	}
	r.emitted++
	return nil
}

// Can is the one can() (guardrails call it too).
func (r *Req) Can(ctx context.Context, action string, t Target, cctx map[string]any) (bool, error) {
	d, err := r.exec.Can(ctx, r.Tx, r.P, action, t, cctx)
	return d.Decision, err
}

// CanMany is the batch form.
func (r *Req) CanMany(ctx context.Context, checks []Check) ([]bool, error) {
	ds, err := r.exec.CanMany(ctx, r.Tx, r.P, checks)
	if err != nil {
		return nil, err
	}
	out := make([]bool, len(ds))
	for i, d := range ds {
		out[i] = d.Decision
	}
	return out, nil
}

// Check is one item of a batch can().
type Check struct {
	Action  string
	Target  Target
	Context map[string]any
}

// Deny reasons the executor itself produces (before the engine).
const (
	ReasonUnknownAction = "unknown_action"
	ReasonKind          = "principal_kind"
	ReasonScope         = "scope"
	ReasonTenant        = "tenant"
	ReasonSuspended     = "merchant_suspended"
)

// precheck: token/scope check, tenant isolation, suspension. Returns a deny decision or nil.
func (e *Executor) precheck(ctx context.Context, q Querier, p *Principal, action string, t Target) (*authz.Decision, error) {
	a, ok := perm.Get(action)
	if !ok {
		return &authz.Decision{Reason: ReasonUnknownAction}, nil
	}
	if !a.AllowsKind(p.Kind) {
		return &authz.Decision{Reason: ReasonKind}, nil
	}
	if !a.AllowsScope(perm.ScopeType(t.Resource.Type)) {
		return &authz.Decision{Reason: ReasonScope}, nil
	}
	if t.MerchantID != "" && (p.Kind == perm.KindUser || p.Kind == perm.KindAgent) && p.MerchantID != t.MerchantID {
		return &authz.Decision{Reason: ReasonTenant}, nil
	}
	if t.MerchantID != "" && p.Kind != perm.KindPlatform {
		var status string
		if err := q.QueryRow(ctx, `SELECT status FROM merchants WHERE id=$1`, t.MerchantID).Scan(&status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &authz.Decision{Reason: ReasonTenant}, nil
			}
			return nil, err
		}
		if status == "suspended" {
			return &authz.Decision{Reason: ReasonSuspended}, nil
		}
	}
	return nil, nil
}

func subjectOf(p *Principal) authz.Subject {
	s := authz.Subject{Type: string(p.Kind), ID: p.ID}
	if p.MerchantID != "" {
		s.Properties = map[string]any{"merchantId": p.MerchantID}
	}
	return s
}

// Can: precheck, then the engine (relationship + condition).
func (e *Executor) Can(ctx context.Context, q Querier, p *Principal, action string, t Target, cctx map[string]any) (authz.Decision, error) {
	if d, err := e.precheck(ctx, q, p, action, t); err != nil || d != nil {
		if d == nil {
			return authz.Decision{}, err
		}
		return *d, err
	}
	return e.Authz.Evaluate(ctx, authz.Request{
		Subject: subjectOf(p), Action: authz.Action{Name: action}, Resource: t.Resource, Context: cctx,
	})
}

// CanMany: prechecks locally, survivors in one engine batch.
func (e *Executor) CanMany(ctx context.Context, q Querier, p *Principal, checks []Check) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(checks))
	var reqs []authz.Request
	var idx []int
	for i, c := range checks {
		d, err := e.precheck(ctx, q, p, c.Action, c.Target)
		if err != nil {
			return nil, err
		}
		if d != nil {
			out[i] = *d
			continue
		}
		reqs = append(reqs, authz.Request{Subject: subjectOf(p), Action: authz.Action{Name: c.Action}, Resource: c.Target.Resource, Context: c.Context})
		idx = append(idx, i)
	}
	if len(reqs) == 0 {
		return out, nil
	}
	ds, err := e.Authz.EvaluateMany(ctx, reqs)
	if err != nil {
		return nil, err
	}
	for j, d := range ds {
		out[idx[j]] = d
	}
	return out, nil
}

func denial(d authz.Decision) error {
	switch d.Reason {
	case ReasonTenant:
		return ErrNotFound
	case ReasonSuspended:
		return ErrMerchantSuspended
	}
	return ErrForbidden
}

// Handler adapts an Op to HTTP.
func (e *Executor) Handler(op Op) http.HandlerFunc {
	return func(w http.ResponseWriter, hr *http.Request) {
		out, err := e.run(hr.Context(), op, hr)
		if err != nil {
			ae := AsErr(err)
			if ae.Status >= 500 {
				e.Log.Error("request failed", "method", hr.Method, "path", hr.URL.Path, "err", err)
			}
			WriteError(w, ae)
			return
		}
		status := op.Status
		if status == 0 {
			status = http.StatusOK
		}
		if status == http.StatusNoContent {
			w.WriteHeader(status)
			return
		}
		WriteJSON(w, status, out)
	}
}

func (e *Executor) run(ctx context.Context, op Op, hr *http.Request) (any, error) {
	body, err := io.ReadAll(io.LimitReader(hr.Body, 1<<20))
	if err != nil {
		return nil, BadInput("cannot read body")
	}
	r := &Req{HTTP: hr, Body: body, exec: e, Now: e.Now()}
	if op.Auth != AuthPublic {
		p, err := e.Authn.Authenticate(ctx, hr.Header.Get("Authorization"))
		if err != nil {
			return nil, err
		}
		r.P = p
	}

	tx, err := e.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	r.Tx = tx

	if op.Target != nil {
		t, err := op.Target(ctx, r)
		if err != nil {
			return nil, err
		}
		r.Target = t
	}

	if op.Auth == AuthAction && !(op.CustomerAlt && r.P.Kind == perm.KindCustomer) {
		var cctx map[string]any
		if op.Context != nil {
			if cctx, err = op.Context(r); err != nil {
				return nil, err
			}
		}
		d, err := e.Can(ctx, tx, r.P, op.Action, r.Target, cctx)
		if err != nil {
			return nil, fmt.Errorf("can %s: %w", op.Action, err)
		}
		if !d.Decision {
			return nil, denial(d)
		}
		if err := r.auditBreakGlass(ctx, op.Action); err != nil {
			return nil, err
		}
	}

	out, err := op.Run(ctx, r)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if r.emitted > 0 {
		// Drain our own rows (and anything older) before responding, so the next
		// request sees the change. On failure the background relay retries.
		if err := e.Relay.Drain(ctx); err != nil {
			e.Log.Warn("outbox drain failed; relay will retry", "err", err)
		}
	}
	return out, nil
}

// auditBreakGlass: staff reading merchant data is only possible under break-glass; audit every such request.
func (r *Req) auditBreakGlass(ctx context.Context, action string) error {
	a, _ := perm.Get(action)
	if r.P.Kind != perm.KindPlatform || r.Target.MerchantID == "" || !a.Grantable || r.auditDone {
		return nil
	}
	r.auditDone = true
	return Audit(ctx, r.Tx, r.P.ID, action, r.Target.MerchantID, r.Now)
}

// Audit writes an audit entry.
func Audit(ctx context.Context, tx pgx.Tx, actor, action, merchantID string, at time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit(actor, action, merchant_id, at) VALUES ($1,$2,$3,$4)`, actor, action, merchantID, at)
	return err
}

// WriteJSON writes v as JSON.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes the SPEC §9 error body.
func WriteError(w http.ResponseWriter, e *Err) {
	body := map[string]any{"code": e.Code}
	if e.Message != "" {
		body["message"] = e.Message
	}
	WriteJSON(w, e.Status, map[string]any{"error": body})
}

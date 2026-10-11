// Package perm is the platform's permission catalog (SPEC §4) and the system
// roles (SPEC §3). It is pure data: every module, the executor, the authz
// adapters and the schema generator read it. Nothing here knows about an IdP
// or an authz engine.
package perm

import "slices"

// ScopeType is the kind of resource a check runs against.
type ScopeType string

const (
	ScopePlatform ScopeType = "platform"
	ScopeMerchant ScopeType = "merchant"
	ScopeStore    ScopeType = "store"
)

// Kind is a principal kind (SPEC §2), the AuthZEN subject.type.
type Kind string

const (
	KindPlatform Kind = "platform"
	KindUser     Kind = "user"
	KindCustomer Kind = "customer"
	KindApp      Kind = "app"
	KindAgent    Kind = "agent"
)

// Action describes one catalog entry.
type Action struct {
	ID        string
	Grantable bool        // may appear in a custom role
	Scopes    []ScopeType // resource types the check may run against
	// Kinds that may ever perform the action (the token/scope check, SPEC §1.5).
	Kinds []Kind
	// AppsAllowed: grantable, but never to apps (SPEC §5).
	NotForApps bool
	// View: read-only; break-glass grants these.
	View bool
	// Internal: not listed in /api/me/permissions.
	Internal bool
}

var merchantKinds = []Kind{KindUser, KindApp, KindAgent, KindPlatform}

func g(id string, scopes []ScopeType, view bool) Action {
	return Action{ID: id, Grantable: true, Scopes: scopes, Kinds: merchantKinds, View: view}
}

var (
	merchantScope = []ScopeType{ScopeMerchant}
	storeScope    = []ScopeType{ScopeStore, ScopeMerchant} // store actions may be asked at merchant scope too ("held merchant-wide")
	eitherScope   = []ScopeType{ScopeMerchant, ScopeStore}
	platformScope = []ScopeType{ScopePlatform}
	staffOnly     = []Kind{KindPlatform}
)

// Catalog lists every action. Order is stable (used for /me/permissions and the schema).
var Catalog = []Action{
	{ID: "platform.merchant.create", Scopes: platformScope, Kinds: staffOnly},
	{ID: "platform.merchant.view", Scopes: platformScope, Kinds: staffOnly},
	{ID: "platform.merchant.suspend", Scopes: platformScope, Kinds: staffOnly},
	{ID: "platform.app.register", Scopes: platformScope, Kinds: staffOnly, Internal: true},
	{ID: "platform.break_glass", Scopes: merchantScope, Kinds: staffOnly},
	{ID: "platform.audit.view", Scopes: platformScope, Kinds: staffOnly},

	g("merchant.view", merchantScope, true),
	g("merchant.update", merchantScope, false),
	withNoApps(g("member.manage", merchantScope, false)),
	withNoApps(g("role.manage", eitherScope, false)),
	g("store.create", merchantScope, false),
	g("store.view", storeScope, true),
	g("product.create", storeScope, false),
	g("product.update", storeScope, false),
	g("product.view", storeScope, true),
	g("order.view", storeScope, true),
	g("order.cancel", storeScope, false),
	g("order.refund", storeScope, false),
	g("payment.capture", storeScope, false),
	g("payment.view", storeScope, true),
	g("shipment.create", storeScope, false),
	g("shipment.update", storeScope, false),
	g("shipment.view", storeScope, true),
	withNoApps(g("app.install", storeScope, false)),
	withNoApps(g("app.uninstall", storeScope, false)),
	g("app.view", storeScope, true),
	withNoApps(g("agent.grant", storeScope, false)),

	// Internal: "only an owner can assign or remove the owner role" (SPEC §3).
	{ID: "role.manage_owner", Scopes: merchantScope, Kinds: []Kind{KindUser}, Internal: true},
}

func withNoApps(a Action) Action { a.NotForApps = true; return a }

var byID = func() map[string]Action {
	m := map[string]Action{}
	for _, a := range Catalog {
		m[a.ID] = a
	}
	return m
}()

// Get returns the action and whether it exists.
func Get(id string) (Action, bool) { a, ok := byID[id]; return a, ok }

// Grantable lists grantable action ids in catalog order.
func Grantable() []string {
	var out []string
	for _, a := range Catalog {
		if a.Grantable {
			out = append(out, a.ID)
		}
	}
	return out
}

// IsGrantable reports whether id may appear in a custom role.
func IsGrantable(id string) bool { a, ok := byID[id]; return ok && a.Grantable }

// IsGrantableToApps reports whether id may be requested by / granted to an app.
func IsGrantableToApps(id string) bool { a, ok := byID[id]; return ok && a.Grantable && !a.NotForApps }

// AllowsKind is the token/scope check: can this kind of principal ever do it.
func (a Action) AllowsKind(k Kind) bool {
	if !slices.Contains(a.Kinds, k) {
		return false
	}
	if k == KindApp && a.NotForApps {
		return false
	}
	if k == KindPlatform && a.Grantable && !a.View {
		return false // staff only ever read merchant data (break-glass)
	}
	return true
}

// AllowsScope reports whether the action can be checked against this resource type.
func (a Action) AllowsScope(s ScopeType) bool { return slices.Contains(a.Scopes, s) }

// SystemRole is a role defined in code, present in every merchant.
type SystemRole struct {
	ID          string
	Name        string
	Permissions []string
}

const RoleOwner = "owner"

// SystemRoles (SPEC §3). owner and admin get every grantable permission,
// including ones the platform adds later.
var SystemRoles = []SystemRole{
	{ID: "owner", Name: "Owner", Permissions: Grantable()},
	{ID: "admin", Name: "Admin", Permissions: Grantable()},
	{ID: "developer", Name: "Developer", Permissions: []string{
		"merchant.view", "store.view", "product.view", "order.view", "app.install", "app.uninstall", "app.view"}},
	{ID: "staff", Name: "Staff", Permissions: []string{
		"merchant.view", "store.view", "product.view", "product.create", "product.update", "order.view",
		"order.cancel", "shipment.view", "shipment.create", "shipment.update"}},
}

// SystemRole returns the system role with the given id.
func GetSystemRole(id string) (SystemRole, bool) {
	for _, r := range SystemRoles {
		if r.ID == id {
			return r, true
		}
	}
	return SystemRole{}, false
}

// RefundAction carries the refund-limit condition.
const RefundAction = "order.refund"

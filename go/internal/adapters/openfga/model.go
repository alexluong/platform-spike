package openfga

import (
	"fmt"
	"strings"

	"github.com/alexluong/platform-spike/go/internal/perm"
)

// Rel maps a catalog action id to an OpenFGA relation name ("order.refund" → "order_refund").
func Rel(action string) string { return strings.ReplaceAll(action, ".", "_") }

// Model generates the OpenFGA model (DSL) from the permission catalog. The
// platform owns it; merchants only ever write tuples (custom roles are data).
//
// Same shape as the SpiceDB schema (custom-roles "style B": role objects hold
// permissions, role bindings tie a subject to a role at a scope):
//   - role: one wildcard relation per grantable permission (order_refund may carry refund_limit)
//   - role_binding: subject (a user, plus that user's delegated agents) and role
//   - merchant / store: bindings at that scope; store inherits merchant bindings
//   - agent_grant: per-permission relations under the not_expired condition; an agent passes a
//     store check only if a live grant lists the action AND the granting user still holds it
//   - app_install: per-scope relations for an app on a store
//   - suspension: exclusion of user:*, agent:*, app:* at the merchant
//   - break-glass: staff relation on the merchant under not_expired, *_view permissions only
//
// Differences from SpiceDB: expiry is a condition on time (the caller sends
// current_time on every check), not an expiring relationship.
func Model() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	var grantable []perm.Action
	for _, a := range perm.Catalog {
		if a.Grantable {
			grantable = append(grantable, a)
		}
	}

	w("# GENERATED from internal/perm by openfga.Model(); do not edit. Regenerate: go test ./internal/adapters/openfga -run TestModelFileUpToDate -update")
	w("model")
	w("  schema 1.1")
	w("")
	w("# a merchant user; delegate = the agents of the grants this user created")
	w("type user")
	w("  relations")
	w("    define delegate: [agent_grant#agent]")
	w("")
	w("# platform staff (platform_admin, support)")
	w("type staff")
	w("")
	w("type app")
	w("")
	w("type agent")
	w("")
	w("type platform")
	w("  relations")
	w("    define admin: [staff]")
	w("    define support: [staff]")
	w("    define platform_merchant_create: admin")
	w("    define platform_merchant_view: admin or support")
	w("    define platform_merchant_suspend: admin")
	w("    define platform_app_register: admin")
	w("    define platform_audit_view: admin")
	w("    define platform_break_glass: admin or support")
	w("")
	w("# a system or custom role: which grantable permissions it holds")
	w("type role")
	w("  relations")
	for _, a := range grantable {
		if a.ID == perm.RefundAction {
			w("    define %s: [user:*, user:* with refund_limit, agent:*, agent:* with refund_limit]", Rel(a.ID))
		} else {
			w("    define %s: [user:*, agent:*]", Rel(a.ID))
		}
	}
	w("    define role_manage_owner: [user:*]")
	w("")
	w("# one role assignment: subject holds role (at the scope that points to this binding)")
	w("type role_binding")
	w("  relations")
	w("    define subject: [user, user#delegate]")
	w("    define role: [role]")
	for _, a := range grantable {
		w("    define %s: subject and %s from role", Rel(a.ID), Rel(a.ID))
	}
	w("    define role_manage_owner: subject and role_manage_owner from role")
	w("")
	w("# an agent grant on a store; every relation is under not_expired")
	w("type agent_grant")
	w("  relations")
	w("    define agent: [agent with not_expired]")
	for _, a := range grantable {
		w("    define %s: [agent with not_expired]", Rel(a.ID))
	}
	w("")
	w("# an app installed on a store with scopes")
	w("type app_install")
	w("  relations")
	for _, a := range grantable {
		if !a.NotForApps {
			w("    define %s: [app]", Rel(a.ID))
		}
	}
	w("")
	w("type merchant")
	w("  relations")
	w("    define platform: [platform]")
	w("    define binding: [role_binding]")
	w("    define any_user: [user:*]")
	w("    define suspended: [user:*, agent:*, app:*]")
	w("    define break_glass_viewer: [staff with not_expired]")
	w("    define platform_break_glass: platform_break_glass from platform")
	w("    define role_manage_owner: (role_manage_owner from binding and any_user) but not suspended")
	for _, a := range grantable {
		p := Rel(a.ID)
		w("    define %s_held: %s from binding", p, p)
		expr := fmt.Sprintf("(%s_held and any_user) but not suspended", p)
		if a.View {
			expr = fmt.Sprintf("(%s) or break_glass_viewer", expr)
		}
		w("    define %s: %s", p, expr)
	}
	w("")
	w("type store")
	w("  relations")
	w("    define merchant: [merchant]")
	w("    define binding: [role_binding]")
	w("    define any_user: [user:*]")
	w("    define grant: [agent_grant]")
	w("    define install: [app_install]")
	w("    define merchant_suspended: suspended from merchant")
	w("    define merchant_break_glass: break_glass_viewer from merchant")
	for _, a := range grantable {
		p := Rel(a.ID)
		w("    define %s_held: %s from binding or %s_held from merchant", p, p, p)
		w("    define %s_granted: %s from grant", p, p)
		expr := fmt.Sprintf("(%s_held and (any_user or %s_granted))", p, p)
		if !a.NotForApps {
			expr = fmt.Sprintf("(%s or %s from install)", expr, p)
		}
		expr = fmt.Sprintf("%s but not merchant_suspended", expr)
		if a.View {
			expr = fmt.Sprintf("(%s) or merchant_break_glass", expr)
		}
		w("    define %s: %s", p, expr)
	}
	w("")
	w("condition refund_limit(amount: int, limit: int) {")
	w("  amount <= limit")
	w("}")
	w("")
	w("condition not_expired(current_time: timestamp, expires_at: timestamp) {")
	w("  current_time < expires_at")
	w("}")
	return b.String()
}

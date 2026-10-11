package spicedb

import (
	"fmt"
	"strings"

	"github.com/alexluong/platform-spike/go/internal/perm"
)

// Perm maps a catalog action id to a SpiceDB permission name ("order.refund" → "order_refund").
func Perm(action string) string { return strings.ReplaceAll(action, ".", "_") }

// Schema generates the SpiceDB schema from the permission catalog. The
// platform owns it; merchants only ever write relationships (custom roles are data).
//
// Shape (role-binding pattern):
//   - role: one wildcard relation per grantable permission (order_refund may carry the refund_limit caveat)
//   - role_binding: subject (a user, plus that user's delegated agents) × role
//   - merchant / store: bindings at that scope; store inherits merchant bindings
//   - agent_grant: expiring per-permission relations; an agent passes a store check only
//     if a live grant lists the action AND the granting user still holds it (delegate path)
//   - app_install: per-scope relations for an app on a store
//   - suspension: exclusion of user:*, agent:*, app:* at the merchant
//   - break-glass: expiring staff relation on the merchant, *_view permissions only
func Schema() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	grantable := []perm.Action{}
	for _, a := range perm.Catalog {
		if a.Grantable {
			grantable = append(grantable, a)
		}
	}

	w("// GENERATED from internal/perm by spicedb.Schema(); do not edit. Regenerate: go test ./internal/adapters/spicedb -update")
	w("use expiration")
	w("")
	w("/** a merchant user; delegate = the live agent grants this user created */")
	w("definition user {")
	w("\trelation delegate: agent_grant#agent")
	w("}")
	w("")
	w("/** platform staff (platform_admin, support) */")
	w("definition staff {}")
	w("")
	w("definition app {}")
	w("")
	w("definition agent {}")
	w("")
	w("caveat refund_limit(amount int, limit int) {")
	w("\tamount <= limit")
	w("}")
	w("")
	w("definition platform {")
	w("\trelation admin: staff")
	w("\trelation support: staff")
	w("\tpermission platform_merchant_create = admin")
	w("\tpermission platform_merchant_view = admin + support")
	w("\tpermission platform_merchant_suspend = admin")
	w("\tpermission platform_app_register = admin")
	w("\tpermission platform_audit_view = admin")
	w("\tpermission platform_break_glass = admin + support")
	w("}")
	w("")
	w("/** a system or custom role: which grantable permissions it holds */")
	w("definition role {")
	for _, a := range grantable {
		if a.ID == perm.RefundAction {
			w("\trelation %s: user:* | user:* with refund_limit | agent:* | agent:* with refund_limit", Perm(a.ID))
		} else {
			w("\trelation %s: user:* | agent:*", Perm(a.ID))
		}
	}
	w("\trelation role_manage_owner: user:*")
	w("}")
	w("")
	w("/** one role assignment: subject holds role (at the scope that points to this binding) */")
	w("definition role_binding {")
	w("\trelation subject: user | user#delegate")
	w("\trelation role: role")
	for _, a := range grantable {
		w("\tpermission %s = subject & role->%s", Perm(a.ID), Perm(a.ID))
	}
	w("\tpermission role_manage_owner = subject & role->role_manage_owner")
	w("}")
	w("")
	w("/** an agent grant on a store; every relation expires */")
	w("definition agent_grant {")
	w("\trelation agent: agent with expiration")
	for _, a := range grantable {
		w("\trelation %s: agent with expiration", Perm(a.ID))
	}
	w("}")
	w("")
	w("/** an app installed on a store with scopes */")
	w("definition app_install {")
	for _, a := range grantable {
		if !a.NotForApps {
			w("\trelation %s: app", Perm(a.ID))
		}
	}
	w("}")
	w("")
	w("definition merchant {")
	w("\trelation platform: platform")
	w("\trelation binding: role_binding")
	w("\trelation any_user: user:*")
	w("\trelation suspended: user:* | agent:* | app:*")
	w("\trelation break_glass_viewer: staff with expiration")
	w("\tpermission platform_break_glass = platform->platform_break_glass")
	w("\tpermission role_manage_owner = (binding->role_manage_owner & any_user) - suspended")
	for _, a := range grantable {
		p := Perm(a.ID)
		w("\tpermission %s_held = binding->%s", p, p)
		expr := fmt.Sprintf("(%s_held & any_user) - suspended", p)
		if a.View {
			expr = fmt.Sprintf("(%s) + break_glass_viewer", expr)
		}
		w("\tpermission %s = %s", p, expr)
	}
	w("}")
	w("")
	w("definition store {")
	w("\trelation merchant: merchant")
	w("\trelation binding: role_binding")
	w("\trelation any_user: user:*")
	w("\trelation grant: agent_grant")
	w("\trelation install: app_install")
	for _, a := range grantable {
		if !a.AllowsScope(perm.ScopeStore) {
			continue
		}
		p := Perm(a.ID)
		w("\tpermission %s_held = binding->%s + merchant->%s_held", p, p, p)
		expr := fmt.Sprintf("(%s_held & (any_user + grant->%s))", p, p)
		if !a.NotForApps {
			expr = fmt.Sprintf("(%s + install->%s)", expr, p)
		}
		expr = fmt.Sprintf("%s - merchant->suspended", expr)
		if a.View {
			expr = fmt.Sprintf("(%s) + merchant->break_glass_viewer", expr)
		}
		w("\tpermission %s = %s", p, expr)
	}
	w("}")
	return b.String()
}

// Package testsupport: TEST_MODE-only endpoints (SPEC §9 Test support).
package testsupport

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
	"github.com/alexluong/platform-spike/go/internal/identity"
	"github.com/alexluong/platform-spike/go/internal/perm"
	"github.com/jackc/pgx/v5/pgconn"
)

type Module struct {
	Secret string
	IdP    identity.Provisioner
	// DriverConfig is what the conformance login driver needs to log in through
	// the IdP (issuer, client id, ...). Opaque to the app; filled by the composition root.
	DriverConfig map[string]any
}

func (m *Module) Ops() []core.Op {
	return []core.Op{
		{Auth: core.AuthPublic, Method: "POST", Path: "/api/_test/users", Status: 201, Run: m.createUser},
		{Auth: core.AuthPublic, Method: "GET", Path: "/api/_test/driver-config", Run: m.driverConfig},
		{Auth: core.AuthPublic, Method: "POST", Path: "/api/_test/merchants/{mid}/users", Status: 201, Run: m.createTenantUser},
		{Auth: core.AuthPublic, Method: "GET", Path: "/api/_test/home-realm", Run: m.homeRealm},
	}
}

// homeRealm (multi-pool stacks): which platform-level kinds hold this email, from the app's
// records (identifier-first login: the driver picks the platform-level pool from it, as a login
// page would ask "staff, merchant or Shop?"; the core suite's loginUser has no pool argument).
func (m *Module) homeRealm(ctx context.Context, r *core.Req) (any, error) {
	if err := m.check(r); err != nil {
		return nil, err
	}
	if _, ok := m.IdP.(identity.TenantPools); !ok {
		return nil, core.ErrNotFound
	}
	rows, err := r.Tx.Query(ctx, `SELECT kind FROM users WHERE home_merchant_id IS NULL AND email=$1 ORDER BY kind`,
		strings.ToLower(strings.TrimSpace(r.HTTP.URL.Query().Get("email"))))
	if err != nil {
		return nil, err
	}
	kinds := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		kinds = append(kinds, k)
	}
	return map[string]any{"kinds": kinds}, rows.Err()
}

// createTenantUser (SPEC §16.4): an identity in the merchant's own pool and the app record.
// kind user = the merchant's staff (a member with no roles); customer = its customer.
func (m *Module) createTenantUser(ctx context.Context, r *core.Req) (any, error) {
	if err := m.check(r); err != nil {
		return nil, err
	}
	pools, ok := m.IdP.(identity.TenantPools)
	if !ok {
		return nil, core.ErrNotFound
	}
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Kind     string `json:"kind"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.Email == "" || in.Password == "" || (in.Kind != string(perm.KindUser) && in.Kind != string(perm.KindCustomer)) {
		return nil, core.BadInput("email, password and kind (user | customer) are required")
	}
	mid := r.Path("mid")
	var exists bool
	if err := r.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM merchants WHERE id=$1)`, mid).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, core.ErrNotFound
	}
	// Checked before the IdP call: an external IdP's user can't roll back with this transaction.
	if err := r.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE home_merchant_id=$1 AND kind=$2 AND email=$3)`, mid, in.Kind, in.Email).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, core.Conflict("email_taken")
	}
	sub, err := pools.CreateTenantUser(ctx, mid, in.Email, in.Password, in.Kind)
	if errors.Is(err, identity.ErrNotFound) {
		return nil, core.ErrNotFound
	} else if err != nil {
		return nil, conflictOr(err)
	}
	id := db.NewID("u")
	if _, err := r.Tx.Exec(ctx, `INSERT INTO users(id, idp_subject, email, kind, home_merchant_id) VALUES ($1,$2,$3,$4,$5)`,
		id, sub, in.Email, in.Kind, mid); err != nil {
		return nil, conflictOr(err)
	}
	if in.Kind == string(perm.KindUser) {
		if _, err := r.Tx.Exec(ctx, `INSERT INTO memberships(user_id, merchant_id) VALUES ($1,$2)`, id, mid); err != nil {
			return nil, err
		}
		if err := r.Emit(ctx, authz.Event{Type: authz.EvMemberAdded, MerchantID: mid, UserID: id, Subject: sub}); err != nil {
			return nil, err
		}
	}
	return map[string]any{"id": id, "email": in.Email}, nil
}

func conflictOr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return core.Conflict("email_taken")
	}
	return err
}

func (m *Module) check(r *core.Req) error {
	got := r.HTTP.Header.Get("X-Test-Secret")
	if m.Secret == "" || subtle.ConstantTimeCompare([]byte(got), []byte(m.Secret)) != 1 {
		return core.E(http.StatusForbidden, "forbidden", "bad test secret")
	}
	return nil
}

func (m *Module) driverConfig(ctx context.Context, r *core.Req) (any, error) {
	if err := m.check(r); err != nil {
		return nil, err
	}
	return m.DriverConfig, nil
}

func (m *Module) createUser(ctx context.Context, r *core.Req) (any, error) {
	if err := m.check(r); err != nil {
		return nil, err
	}
	var in struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		Kind         string `json:"kind"`
		PlatformRole string `json:"platformRole"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.Email == "" || in.Password == "" {
		return nil, core.BadInput("email and password are required")
	}
	switch perm.Kind(in.Kind) {
	case perm.KindUser, perm.KindCustomer:
		in.PlatformRole = ""
	case perm.KindPlatform:
		if in.PlatformRole != "platform_admin" && in.PlatformRole != "support" {
			return nil, core.BadInput("platformRole must be platform_admin or support")
		}
	default:
		return nil, core.BadInput("kind must be platform, user or customer")
	}
	var exists bool
	if err := r.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 AND home_merchant_id IS NULL)`, in.Email).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, core.Conflict("email_taken")
	}
	sub, err := m.IdP.CreateUser(ctx, in.Email, in.Password, in.Kind)
	if err != nil {
		return nil, err
	}
	id := db.NewID("u")
	var role *string
	if in.PlatformRole != "" {
		role = &in.PlatformRole
	}
	if _, err := r.Tx.Exec(ctx, `INSERT INTO users(id, idp_subject, email, kind, platform_role) VALUES ($1,$2,$3,$4,$5)`,
		id, sub, in.Email, in.Kind, role); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return nil, core.Conflict("email_taken")
		}
		return nil, err
	}
	if role != nil {
		if err := r.Emit(ctx, authz.Event{Type: authz.EvPlatformRoleGranted, UserID: id, PlatformRole: *role}); err != nil {
			return nil, err
		}
	}
	return map[string]any{"id": id, "email": in.Email}, nil
}

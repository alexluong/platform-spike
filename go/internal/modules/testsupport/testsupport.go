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
	}
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
	if err := r.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, in.Email).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, core.Conflict("email_taken")
	}
	sub, err := m.IdP.CreateUser(ctx, in.Email, in.Password)
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


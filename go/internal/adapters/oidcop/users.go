package oidcop

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/argon2"

	"github.com/alexluong/platform-spike/go/internal/core"
	"github.com/alexluong/platform-spike/go/internal/db"
)

// Passwords: argon2id at OWASP's minimum (19 MiB, 2 passes, 1 lane), ~20-40 ms of CPU.
// At most hashSlots hashes run at once: each one holds 19 MiB, and a burst of logins
// would otherwise multiply that and starve the API of CPU. The cap is GOMAXPROCS, and no
// more than half of GOMEMLIMIT's worth of hash buffers (GC garbage from finished
// hashes needs room too): GOMAXPROCS alone follows the host's or the cgroup's CPUs, not
// the container's memory.
const (
	argonMem     = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
)

var hashSlots = make(chan struct{}, hashConcurrency(runtime.GOMAXPROCS(0), debug.SetMemoryLimit(-1)))

func hashConcurrency(procs int, memLimit int64) int {
	n := procs
	if memLimit > 0 && memLimit < math.MaxInt64 {
		n = min(n, int(memLimit/2/(argonMem*1024)))
	}
	return max(n, 1)
}

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hashSlots <- struct{}{}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMem, argonThreads, argonKeyLen)
	<-hashSlots
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMem, argonTime, argonThreads, b64(salt), b64(key))
}

// checkPassword verifies a PHC argon2id string (parameters read from it, so a cost change
// doesn't invalidate old hashes).
func checkPassword(phc, pw string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	hashSlots <- struct{}{}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	<-hashSlots
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified against when the email is unknown, so a miss costs the same as a
// wrong password (no account enumeration by timing; review-g #6).
var dummyHash = hashPassword("dummy password for unknown accounts")

// CreateUser (identity port): writes the user in the caller's transaction when ctx carries
// one (the executor's), so a rolled-back request leaves no identity behind.
func (s *Issuer) CreateUser(ctx context.Context, email, password, _ string) (string, error) {
	id := db.NewID("idu")
	_, err := db.TxOr(ctx, s.db).Exec(ctx, `INSERT INTO idp_users(id, email, password_hash) VALUES ($1,$2,$3)`,
		id, strings.ToLower(strings.TrimSpace(email)), hashPassword(password))
	return id, err
}

// authenticate returns the user id for a correct email + password of an enabled user.
func (s *Issuer) authenticate(ctx context.Context, email, password string) (string, bool) {
	var id, phc string
	var disabled bool
	err := s.db.QueryRow(ctx, `SELECT id, password_hash, disabled_at IS NOT NULL FROM idp_users WHERE email=$1`,
		strings.ToLower(strings.TrimSpace(email))).Scan(&id, &phc, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		checkPassword(dummyHash, password)
		return "", false
	} else if err != nil {
		s.log.Error("login lookup", "err", err)
		return "", false
	}
	if !checkPassword(phc, password) || disabled {
		return "", false
	}
	return id, true
}

// login is the login step of the code flow, headless (SPEC §10): /authorize redirects here
// with ?id=<auth request>; a UI would render a form. GET describes the form, POST checks
// the password, marks the auth request done and answers with the code: a redirect to the
// registered redirect URI (op.AuthResponse), never via the library's callback endpoint.
func (s *Issuer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		core.WriteJSON(w, 200, map[string]any{"authRequestId": r.URL.Query().Get("id"), "fields": []string{"email", "password"}})
		return
	}
	if r.Method != http.MethodPost {
		core.WriteJSON(w, 405, map[string]string{"error": "method_not_allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		core.WriteJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	id, email, pw := r.PostForm.Get("id"), strings.ToLower(strings.TrimSpace(r.PostForm.Get("email"))), r.PostForm.Get("password")
	ip := clientIP(r)
	var pending bool
	if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM idp_auth_requests WHERE id=$1 AND NOT done AND expires_at > now())`, id).Scan(&pending); err != nil || !pending {
		core.WriteJSON(w, 400, map[string]string{"error": "invalid_auth_request"})
		return
	}
	// Each attempt takes a slot before the hash runs, so parallel guesses can't all pass
	// the check before the first failure is counted; a success gives its slot back.
	tooMany := func() {
		w.Header().Set("Retry-After", "60")
		core.WriteJSON(w, 429, map[string]string{"error": "too_many_attempts"})
	}
	keys := []string{"login:" + email + "|" + ip, "login:" + email}
	if !s.limits.allowIP(ip) || !s.limits.attempt(keys[0], maxFailsPerSource) {
		tooMany()
		return
	}
	if !s.limits.attempt(keys[1], maxFailsPerAccount) {
		s.limits.release(keys[0])
		tooMany()
		return
	}
	uid, ok := s.authenticate(r.Context(), email, pw)
	if !ok {
		core.WriteJSON(w, 401, map[string]string{"error": "invalid_credentials"})
		return
	}
	s.limits.release(keys...)
	tag, err := s.db.Exec(r.Context(), `UPDATE idp_auth_requests SET user_id=$2, auth_time=now(), done=true
		WHERE id=$1 AND NOT done AND expires_at > now()`, id, uid)
	if err != nil || tag.RowsAffected() != 1 {
		core.WriteJSON(w, 400, map[string]string{"error": "invalid_auth_request"})
		return
	}
	// The code goes to whoever submitted the password, in this response. The library's
	// /authorize/callback?id= would hand the code to anyone holding the auth request id,
	// and whoever started /authorize has it (blocked in Mount).
	ar, err := s.AuthRequestByID(r.Context(), id)
	if err != nil {
		core.WriteJSON(w, 400, map[string]string{"error": "invalid_auth_request"})
		return
	}
	op.AuthResponse(ar, s.provider, w, r)
}

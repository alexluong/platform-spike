package oidcpool

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
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

// CreateUser (identity port): a platform-level identity, placed by kind (platform → workforce,
// user → platform, customer → shop), in the caller's transaction when ctx carries one.
func (s *Issuer) CreateUser(ctx context.Context, email, password, kind string) (string, error) {
	poolID, err := poolForKind(kind)
	if err != nil {
		return "", err
	}
	id := db.NewID("idu")
	_, err = db.TxOr(ctx, s.db).Exec(ctx, `INSERT INTO idp_users(id, pool_id, user_group, email, password_hash) VALUES ($1,$2,$3,$4,$5)`,
		id, poolID, groupDefault, normEmail(email), hashPassword(password))
	return qualify(poolID, id), err
}

// authenticate returns the user id for a correct email + password of an enabled password user
// in this pool and group. Federated users (no password) never match.
func (s *Issuer) authenticate(ctx context.Context, poolID, group, email, password string) (string, bool) {
	var id string
	var phc *string
	var disabled bool
	err := s.db.QueryRow(ctx, `SELECT id, password_hash, disabled_at IS NOT NULL FROM idp_users WHERE pool_id=$1 AND user_group=$2 AND email=$3`,
		poolID, group, normEmail(email)).Scan(&id, &phc, &disabled)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && phc == nil) {
		checkPassword(dummyHash, password)
		return "", false
	} else if err != nil {
		s.log.Error("login lookup", "err", err)
		return "", false
	}
	if !checkPassword(*phc, password) || disabled {
		return "", false
	}
	return id, true
}

// pendingRequest: the auth request is waiting for a login in this pool; returns its client id.
func (s *Issuer) pendingRequest(ctx context.Context, poolID, id string) (string, bool) {
	var clientID string
	err := s.db.QueryRow(ctx, `SELECT request->>'clientId' FROM idp_auth_requests WHERE id=$1 AND pool_id=$2 AND NOT done AND expires_at > now()`,
		id, poolID).Scan(&clientID)
	return clientID, err == nil
}

// group of the users a pending request may log in: the login client's group, or for a
// federation client at the shop pool, the shop's buyers.
func (s *Issuer) requestGroup(p *Pool, clientID string) string {
	if g := s.loginGroup(p, clientID); g != "" {
		return g
	}
	if p.Kind == kindShop && strings.HasPrefix(clientID, "fed_") {
		return groupDefault
	}
	return ""
}

// handleLogin is the login step of a pool's code flow, headless (SPEC §10): /authorize redirects
// to /oidc/<pool>/login?id=<auth request>; a UI would render a form. GET describes the form, POST
// checks the password against this pool's users of the client's group, marks the request done and
// answers with the code (op.AuthResponse), never via the library's callback endpoint. A suspended
// tenant pool refuses (403).
func (s *Issuer) handleLogin(w http.ResponseWriter, r *http.Request) {
	p := poolFrom(r.Context())
	if r.Method == http.MethodGet {
		fields := []string{"email", "password"}
		out := map[string]any{"authRequestId": r.URL.Query().Get("id"), "fields": fields}
		if p.Kind == kindTenant {
			out["upstreams"] = map[string]string{"shop": s.issuerFor(p.ID) + shopLoginPath + "?id=" + url.QueryEscape(r.URL.Query().Get("id"))}
		}
		core.WriteJSON(w, 200, out)
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
	id, email, pw := r.PostForm.Get("id"), normEmail(r.PostForm.Get("email")), r.PostForm.Get("password")
	ip := clientIP(r)
	clientID, pending := s.pendingRequest(r.Context(), p.ID, id)
	group := s.requestGroup(p, clientID)
	if !pending || group == "" {
		core.WriteJSON(w, 400, map[string]string{"error": "invalid_auth_request"})
		return
	}
	if !s.poolActive(r.Context(), p.ID) {
		core.WriteJSON(w, 403, map[string]string{"error": "pool_suspended"})
		return
	}
	// Each attempt takes a slot before the hash runs, so parallel guesses can't all pass the
	// check before the first failure is counted; a success gives its slot back. Keys are per
	// pool and group: the same email in two pools is two accounts.
	tooMany := func() {
		w.Header().Set("Retry-After", "60")
		core.WriteJSON(w, 429, map[string]string{"error": "too_many_attempts"})
	}
	acct := "login:" + p.ID + "/" + group + ":" + email
	keys := []string{acct + "|" + ip, acct}
	if !s.limits.allowIP(ip) || !s.limits.attempt(keys[0], maxFailsPerSource) {
		tooMany()
		return
	}
	if !s.limits.attempt(keys[1], maxFailsPerAccount) {
		s.limits.release(keys[0])
		tooMany()
		return
	}
	uid, ok := s.authenticate(r.Context(), p.ID, group, email, pw)
	if !ok {
		core.WriteJSON(w, 401, map[string]string{"error": "invalid_credentials"})
		return
	}
	s.limits.release(keys...)
	s.completeLogin(w, r, id, uid)
}

// completeLogin marks the request done for uid and answers with the code: to whoever completed
// the step, in this response (the library's /authorize/callback?id= is closed in limitToken).
func (s *Issuer) completeLogin(w http.ResponseWriter, r *http.Request, id, uid string) {
	tag, err := s.db.Exec(r.Context(), `UPDATE idp_auth_requests SET user_id=$3, auth_time=now(), done=true
		WHERE id=$1 AND pool_id=$2 AND NOT done AND expires_at > now()`, id, pid(r.Context()), uid)
	if err != nil || tag.RowsAffected() != 1 {
		core.WriteJSON(w, 400, map[string]string{"error": "invalid_auth_request"})
		return
	}
	ar, err := s.AuthRequestByID(r.Context(), id)
	if err != nil {
		core.WriteJSON(w, 400, map[string]string{"error": "invalid_auth_request"})
		return
	}
	op.AuthResponse(ar, s.provider, w, r)
}

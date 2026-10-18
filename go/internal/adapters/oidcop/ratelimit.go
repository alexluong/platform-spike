package oidcop

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Failure caps per window (limitWindow).
const (
	maxFailsPerSource  = 10  // email+IP, client id
	maxFailsPerAccount = 100 // email, any IP
	limitWindow        = 15 * time.Minute
)

// limits: in-memory, per instance (N instances allow N times as much). Production needs a
// shared store (Postgres or Redis) or an edge limiter, plus a CAPTCHA on public sign-in.
//   - per client IP: a token bucket over password logins and /token calls;
//   - per key (email+IP, email, client id): failures in a window; at maxFails the key is
//     refused until the window ends. email+IP stops one source guessing; the looser
//     per-email cap bounds a distributed guess without letting one IP lock a user out.
type limits struct {
	mu      sync.Mutex
	ips     map[string]*rate.Limiter
	fails   map[string]*failWindow
	ipRate  rate.Limit
	ipBurst int
	window  time.Duration
}

type failWindow struct {
	n     int
	until time.Time
}

func newLimits(perIPPerSecond float64, burst int, window time.Duration) *limits {
	l := &limits{
		ips: map[string]*rate.Limiter{}, fails: map[string]*failWindow{},
		ipRate: rate.Limit(perIPPerSecond), ipBurst: burst, window: window,
	}
	go l.sweep()
	return l
}

func (l *limits) allowIP(ip string) bool {
	l.mu.Lock()
	lim, ok := l.ips[ip]
	if !ok {
		lim = rate.NewLimiter(l.ipRate, l.ipBurst)
		l.ips[ip] = lim
	}
	l.mu.Unlock()
	return lim.Allow()
}

// locked: key has max failures in its current window.
func (l *limits) locked(key string, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.fails[key]
	return ok && time.Now().Before(f.until) && f.n >= max
}

func (l *limits) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.fails[key]
	if !ok || time.Now().After(f.until) {
		f = &failWindow{until: time.Now().Add(l.window)}
		l.fails[key] = f
	}
	f.n++
}

func (l *limits) sweep() {
	for range time.Tick(time.Minute) {
		l.mu.Lock()
		now := time.Now()
		for k, f := range l.fails {
			if now.After(f.until) {
				delete(l.fails, k)
			}
		}
		for ip, lim := range l.ips {
			if lim.TokensAt(now) >= float64(l.ipBurst) {
				delete(l.ips, ip)
			}
		}
		l.mu.Unlock()
	}
}

// clientIP: the TCP peer. X-Forwarded-For is not trusted: behind a proxy, configure the
// proxy's address and read the header only from it.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limitToken wraps the issuer's /oauth/token: the per-IP bucket for every call, and failed
// client_credentials calls count against the client id (secret guessing). Failed code or
// refresh exchanges don't count: they'd lock the shared public client for everyone.
func (s *Issuer) limitToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			next.ServeHTTP(w, r)
			return
		}
		tooMany := func() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"slow_down","error_description":"too many requests"}`, http.StatusTooManyRequests)
		}
		if !s.limits.allowIP(clientIP(r)) {
			tooMany()
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		_ = r.ParseForm() // the issuer parses again from the cached form
		key := ""
		if r.PostForm.Get("grant_type") == "client_credentials" {
			id, _, ok := r.BasicAuth()
			if !ok {
				id = r.PostForm.Get("client_id")
			}
			key = "client:" + id
			if s.limits.locked(key, maxFailsPerSource) {
				tooMany()
				return
			}
		}
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		if key != "" && (rec.status == 400 || rec.status == 401) {
			s.limits.fail(key)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

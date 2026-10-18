package zitadel

// The identity gateway (stack i). Requests for <label>.<ID_DOMAIN> are a pool's identity host:
//   - browser-facing OIDC paths are proxied to Zitadel with x-zitadel-instance-host (the pool's
//     instance domain, from the directory) and x-zitadel-public-host (the host the client used,
//     the issuer). Client-supplied instance/public/forwarded headers are dropped first: Zitadel
//     also reads Forwarded and X-Forwarded-Host when picking the instance.
//   - Zitadel's admin and user APIs are not reachable through it (404).
//   - /ui/v2/login/* is a headless stand-in for Zitadel's Login UI v2 (a separate Next.js app in
//     a real deployment, which also sits behind the gateway and talks to the Session API as a
//     system user). JSON instead of HTML; the driver plays the browser.
// Any other host goes to the app's API.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var proxied = []string{"/oauth/v2/", "/oidc/v1/", "/.well-known/openid-configuration", "/idps/callback"}

// Gateway wraps the app's handler.
func (x *Instances) Gateway(next http.Handler) http.Handler {
	target, _ := url.Parse(x.cfg.ZitadelURL)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			p := pr.In.Context().Value(poolCtx{}).(*Pool)
			h := pr.Out.Header
			for k := range h {
				lk := strings.ToLower(k)
				if strings.HasPrefix(lk, "x-zitadel-") || strings.HasPrefix(lk, "x-forwarded-") || lk == "forwarded" {
					h.Del(k)
				}
			}
			h.Set("x-zitadel-instance-host", p.InstanceDomain)
			h.Set("x-zitadel-public-host", p.PublicHost)
		},
	}
	suffix := "." + x.cfg.IDDomain
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostname, port, _ := strings.Cut(r.Host, ":")
		label, ok := strings.CutSuffix(strings.ToLower(hostname), suffix)
		if !ok || strings.Contains(label, ".") {
			next.ServeHTTP(w, r)
			return
		}
		p, err := x.poolByLabel(r.Context(), label)
		if err != nil || p.Status != "active" || port != x.cfg.IDPort {
			http.Error(w, "unknown identity host", http.StatusNotFound)
			return
		}
		// A suspended merchant's pool: no logins, no tokens (keys and discovery stay readable).
		if p.MerchantID != "" && r.URL.Path != "/oauth/v2/keys" && r.URL.Path != "/.well-known/openid-configuration" && x.blocked(r.Context(), p) {
			loginError(w, http.StatusForbidden, "merchant suspended", nil)
			return
		}
		if rest, ok := strings.CutPrefix(r.URL.Path, "/ui/v2/login/"); ok {
			x.login(w, r, p, rest)
			return
		}
		for _, pre := range proxied {
			if strings.HasPrefix(r.URL.Path, pre) {
				rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), poolCtx{}, p)))
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
}

type poolCtx struct{}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func loginError(w http.ResponseWriter, status int, msg string, err error) {
	body := map[string]any{"error": msg}
	if err != nil {
		body["detail"] = err.Error()
	}
	writeJSON(w, status, body)
}

// login is the Login UI stand-in. Routes (all JSON):
//
//	POST password {authRequest, loginName, password} → {callbackUrl}
//	POST idp      {authRequest}                      → {authUrl}   (Sign in with Shop; merchant pools)
//	GET  idp/done?authRequest=&id=&token=            → {callbackUrl} (the IdP intent's success URL)
//	GET  login?authRequest=                          → what a UI would render (auth request, org)
func (x *Instances) login(w http.ResponseWriter, r *http.Request, p *Pool, route string) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	switch {
	case r.Method == http.MethodGet && route == "login":
		ar, err := x.authRequest(ctx, p, r.URL.Query().Get("authRequest"))
		if err != nil {
			loginError(w, http.StatusBadRequest, "unknown auth request", err)
			return
		}
		writeJSON(w, 200, map[string]any{"authRequest": ar.ID, "orgId": ar.orgID(), "next": []string{"password", "idp"}})
	case r.Method == http.MethodPost && route == "password":
		var in struct {
			AuthRequest, LoginName, Password string
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			loginError(w, 400, "bad body", err)
			return
		}
		cb, status, err := x.passwordLogin(ctx, p, in.AuthRequest, in.LoginName, in.Password)
		if err != nil {
			loginError(w, status, "login failed", err)
			return
		}
		writeJSON(w, 200, map[string]any{"callbackUrl": cb})
	case r.Method == http.MethodPost && route == "idp":
		var in struct{ AuthRequest string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			loginError(w, 400, "bad body", err)
			return
		}
		u, status, err := x.startShop(ctx, p, in.AuthRequest)
		if err != nil {
			loginError(w, status, "sign in with Shop unavailable", err)
			return
		}
		writeJSON(w, 200, map[string]any{"authUrl": u})
	case r.Method == http.MethodGet && route == "idp/done":
		q := r.URL.Query()
		cb, status, err := x.finishShop(ctx, p, q.Get("authRequest"), q.Get("id"), q.Get("token"))
		if err != nil {
			loginError(w, status, "sign in with Shop failed", err)
			return
		}
		writeJSON(w, 200, map[string]any{"callbackUrl": cb})
	case route == "idp/failed":
		loginError(w, http.StatusUnauthorized, "sign in with Shop failed upstream", errors.New(r.URL.RawQuery))
	default:
		loginError(w, http.StatusNotFound, "unknown login route", nil)
	}
}

type authReq struct {
	ID       string   `json:"id"`
	ClientID string   `json:"clientId"`
	Scope    []string `json:"scope"`
}

func (a authReq) orgID() string {
	for _, s := range a.Scope {
		if id, ok := strings.CutPrefix(s, "urn:zitadel:iam:org:id:"); ok {
			return id
		}
	}
	return ""
}

func (x *Instances) authRequest(ctx context.Context, p *Pool, id string) (authReq, error) {
	var out struct {
		AuthRequest authReq `json:"authRequest"`
	}
	if id == "" {
		return authReq{}, errors.New("authRequest is required")
	}
	err := x.z.Call(ctx, x.z.Login, p.at(), "GET", "/v2/oidc/auth_requests/"+url.PathEscape(id), nil, &out)
	return out.AuthRequest, err
}

// findUser: the user with this email in the org the auth request is for (the org scope).
// Without an org scope, a login must name exactly one user in the instance.
func (x *Instances) findUser(ctx context.Context, p *Pool, orgID, email string) (string, error) {
	// Password users have username <org name>.<email> (instances.go); Shop-linked users
	// (shop.<id>) and other orgs' users never match, even with the same email.
	org := ""
	for name, id := range p.Orgs {
		if id == orgID {
			org = name
		}
	}
	if org == "" {
		return "", errors.New("auth request has no known org scope")
	}
	queries := []any{
		map[string]any{"userNameQuery": map[string]any{"userName": org + "." + email, "method": "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE"}},
		map[string]any{"organizationIdQuery": map[string]any{"organizationId": orgID}},
	}
	// The user list is a projection: a user created a moment ago may not be in it yet. A real
	// login UI has the same lag; retry briefly before saying "unknown user".
	for attempt := 0; ; attempt++ {
		var out struct {
			Result []struct {
				UserID string `json:"userId"`
			} `json:"result"`
		}
		if err := x.z.Call(ctx, x.z.Login, p.at(), "POST", "/v2/users", map[string]any{"queries": queries}, &out); err != nil {
			return "", err
		}
		if len(out.Result) == 1 {
			return out.Result[0].UserID, nil
		}
		if len(out.Result) > 1 || attempt >= 20 {
			return "", fmt.Errorf("%d users match", len(out.Result))
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

type session struct {
	SessionID    string `json:"sessionId"`
	SessionToken string `json:"sessionToken"`
}

func (x *Instances) finalize(ctx context.Context, p *Pool, authRequestID string, s session) (string, error) {
	var cb struct {
		CallbackURL string `json:"callbackUrl"`
	}
	err := x.z.Call(ctx, x.z.Login, p.at(), "POST", "/v2/oidc/auth_requests/"+url.PathEscape(authRequestID),
		map[string]any{"session": s}, &cb)
	return cb.CallbackURL, err
}

func (x *Instances) passwordLogin(ctx context.Context, p *Pool, authRequestID, email, password string) (string, int, error) {
	ar, err := x.authRequest(ctx, p, authRequestID)
	if err != nil {
		return "", 400, err
	}
	uid, err := x.findUser(ctx, p, ar.orgID(), strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return "", 401, err
	}
	var s session
	if err := x.z.Call(ctx, x.z.Login, p.at(), "POST", "/v2/sessions", map[string]any{
		"checks": map[string]any{"user": map[string]any{"userId": uid}, "password": map[string]any{"password": password}},
	}, &s); err != nil {
		return "", 401, err
	}
	cb, err := x.finalize(ctx, p, ar.ID, s)
	if err != nil {
		return "", 401, err
	}
	return cb, 200, nil
}

// startShop: an IdP intent at the merchant's instance for its Shop IdP. The returned URL is the
// platform instance's authorize endpoint (from the IdP's discovery), with this instance's
// /idps/callback as the redirect.
func (x *Instances) startShop(ctx context.Context, p *Pool, authRequestID string) (string, int, error) {
	if p.ShopIdPID == "" {
		return "", 404, errors.New("this pool has no Shop IdP")
	}
	if _, err := x.authRequest(ctx, p, authRequestID); err != nil {
		return "", 400, err
	}
	base := "http://" + p.PublicHost + "/ui/v2/login/"
	q := url.Values{"authRequest": {authRequestID}}.Encode()
	var out struct {
		AuthURL string `json:"authUrl"`
	}
	if err := x.z.Call(ctx, x.z.Login, p.at(), "POST", "/v2/idp_intents", map[string]any{
		"idpId": p.ShopIdPID,
		"urls":  map[string]any{"successUrl": base + "idp/done?" + q, "failureUrl": base + "idp/failed?" + q},
	}, &out); err != nil {
		return "", 502, err
	}
	return out.AuthURL, 200, nil
}

// finishShop: the intent succeeded upstream. Find the merchant-pool user linked to the Shop
// identity, or create one in org customers with the IdP link; tell the app (Shop link); create
// a session with the intent and finalize the auth request.
func (x *Instances) finishShop(ctx context.Context, p *Pool, authRequestID, intentID, intentToken string) (string, int, error) {
	if intentID == "" || intentToken == "" {
		return "", 400, errors.New("id and token are required")
	}
	var in struct {
		UserID  string `json:"userId"`
		IDPInfo struct {
			IDPID    string         `json:"idpId"`
			UserID   string         `json:"userId"`
			UserName string         `json:"userName"`
			Raw      map[string]any `json:"rawInformation"`
		} `json:"idpInformation"`
	}
	if err := x.z.Call(ctx, x.z.Login, p.at(), "POST", "/v2/idp_intents/"+url.PathEscape(intentID),
		map[string]any{"idpIntentToken": intentToken}, &in); err != nil {
		return "", 401, err
	}
	if in.IDPInfo.IDPID != p.ShopIdPID || in.IDPInfo.UserID == "" {
		return "", 401, errors.New("intent is not from this pool's Shop IdP")
	}
	uid := in.UserID
	if uid == "" {
		email, _ := in.IDPInfo.Raw["email"].(string)
		if email == "" {
			email = in.IDPInfo.UserName
		}
		var out struct {
			UserID string `json:"userId"`
		}
		// Username: unique per instance, and a local customer may already use this email as
		// theirs; the Shop identity is never matched to a local account by email (SPEC §16.5).
		err := x.z.Call(ctx, x.z.Login, p.at(), "POST", "/v2/users/human", map[string]any{
			"username":     "shop." + in.IDPInfo.UserID,
			"organization": map[string]any{"orgId": p.Orgs["customers"]},
			"profile":      map[string]any{"givenName": "Shop", "familyName": "Buyer"},
			"email":        map[string]any{"email": email, "isVerified": true},
			"idpLinks":     []any{map[string]any{"idpId": p.ShopIdPID, "userId": in.IDPInfo.UserID, "userName": in.IDPInfo.UserName}},
		}, &out)
		if err != nil {
			return "", 502, fmt.Errorf("create linked user: %w", err)
		}
		uid = out.UserID
	}
	if x.OnShopLink != nil {
		if err := x.OnShopLink(ctx, p.MerchantID, subject(PoolPlatform, in.IDPInfo.UserID), subject(p.Key, uid)); err != nil {
			return "", 401, fmt.Errorf("shop link: %w", err)
		}
	}
	var s session
	for attempt := 0; ; attempt++ { // a just-created user may not be in the projection yet
		err := x.z.Call(ctx, x.z.Login, p.at(), "POST", "/v2/sessions", map[string]any{
			"checks": map[string]any{"user": map[string]any{"userId": uid}, "idpIntent": map[string]any{"idpIntentId": intentID, "idpIntentToken": intentToken}},
		}, &s)
		if err == nil {
			break
		}
		if !IsNotFound(err) || attempt >= 20 {
			return "", 401, err
		}
		time.Sleep(150 * time.Millisecond)
	}
	cb, err := x.finalize(ctx, p, authRequestID, s)
	if err != nil {
		return "", 401, err
	}
	return cb, 200, nil
}

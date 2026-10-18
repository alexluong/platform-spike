package zitadel

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// review-i: the gateway picks the instance from the directory only, strips every
// client-supplied instance-selecting header, and proxies only clean browser OIDC paths.
func TestGatewayRouting(t *testing.T) {
	var mu sync.Mutex
	var got []*http.Request
	zitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Clone(r.Context()))
		mu.Unlock()
		w.WriteHeader(299)
	}))
	defer zitadel.Close()

	x := &Instances{cfg: InstancesConfig{ZitadelURL: zitadel.URL, IDDomain: "cs.internal", IDPort: "8096"}, log: slog.New(slog.DiscardHandler),
		byKey: map[string]*Pool{}, byIss: map[string]*Pool{}, byLabel: map[string]*Pool{}, keys: map[string]*keySet{}}
	// Platform-level pool (no merchant: no block lookup, so no DB needed).
	wf := &Pool{Key: PoolWorkforce, Label: "workforce", InstanceDomain: "workforce.zitadel.internal", PublicHost: "workforce.cs.internal:8096", Status: "active"}
	x.byLabel["workforce"] = wf
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(298) })
	gw := httptest.NewServer(x.Gateway(api))
	defer gw.Close()

	// Raw HTTP/1.1 so paths and headers go out exactly as written.
	send := func(target, host string, hdr ...string) int {
		c, err := net.Dial("tcp", strings.TrimPrefix(gw.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", target, host)
		for _, h := range hdr {
			fmt.Fprintf(c, "%s\r\n", h)
		}
		fmt.Fprint(c, "\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	const host = "workforce.cs.internal:8096"
	cases := []struct {
		name, target, host string
		hdr                []string
		want               int
	}{
		{"discovery", "/.well-known/openid-configuration", host, nil, 299},
		{"authorize", "/oauth/v2/authorize?client_id=x", host, nil, 299},
		{"upper-case host", "/oauth/v2/keys", "WORKFORCE.CS.INTERNAL:8096", nil, 299},
		{"spoofed headers are replaced", "/oauth/v2/keys", host, []string{
			"x-zitadel-instance-host: platform.zitadel.internal", "X-Zitadel-Public-Host: evil.example",
			"X-Forwarded-Host: platform.zitadel.internal", "Forwarded: host=platform.zitadel.internal", "x-zitadel-forwarded: host=x"}, 299},
		{"admin API", "/admin/v1/orgs/me", host, nil, 404},
		{"system API", "/system/v1/instances/_search", host, nil, 404},
		{"user API v2", "/v2/users", host, nil, 404},
		{"dot-dot", "/oauth/v2/../../admin/v1/orgs/me", host, nil, 404},
		{"encoded dot-dot", "/oauth/v2/%2e%2e/%2e%2e/admin/v1/orgs/me", host, nil, 404},
		{"encoded slash", "/oauth/v2/..%2f..%2fadmin/v1/orgs/me", host, nil, 404},
		{"double slash", "/oauth/v2//keys", host, nil, 404},
		{"dot segment", "/oauth/v2/./keys", host, nil, 404},
		{"wrong port", "/oauth/v2/keys", "workforce.cs.internal:8097", nil, 404},
		{"no port", "/oauth/v2/keys", "workforce.cs.internal", nil, 404},
		{"two labels → API", "/oauth/v2/keys", "a.workforce.cs.internal:8096", nil, 298},
		{"trailing dot → API", "/oauth/v2/keys", "workforce.cs.internal.:8096", nil, 298},
		{"other host → API", "/api/me", "cs-ws:8096", nil, 298},
	}
	for _, c := range cases {
		if s := send(c.target, c.host, c.hdr...); s != c.want {
			t.Errorf("%s: %s Host %s → %d, want %d", c.name, c.target, c.host, s, c.want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, r := range got {
		if r.Header.Get("X-Zitadel-Instance-Host") != wf.InstanceDomain || r.Header.Get("X-Zitadel-Public-Host") != wf.PublicHost {
			t.Errorf("%s: instance headers %q / %q", r.URL, r.Header.Get("X-Zitadel-Instance-Host"), r.Header.Get("X-Zitadel-Public-Host"))
		}
		if len(r.Header.Values("X-Zitadel-Instance-Host")) != 1 || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("X-Zitadel-Forwarded") != "" {
			t.Errorf("%s: client header reached Zitadel: %v", r.URL, r.Header)
		}
	}
	if len(got) != 4 {
		t.Errorf("Zitadel got %d requests, want 4", len(got))
	}
}

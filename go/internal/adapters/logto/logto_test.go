package logto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestCheckClient(t *testing.T) {
	const login = "driverspa"
	cases := []struct {
		name, clientID, sub string
		ok                  bool
	}{
		{"user token from the login app", login, "user-id", true},
		{"client_credentials (app/agent)", "m2mapp", "m2mapp", true},
		{"no client_id", "", "user-id", false},
		{"user token from another app with the resource", "otherspa", "user-id", false},
	}
	for _, c := range cases {
		if err := checkClient(c.clientID, c.sub, login); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestTokenType(t *testing.T) {
	jwt := func(header string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + ".e30.sig"
	}
	for in, want := range map[string]string{
		jwt(`{"alg":"ES384","typ":"at+jwt"}`): "at+jwt",
		jwt(`{"alg":"ES384","typ":"JWT"}`):    "JWT",
		jwt(`{"alg":"ES384"}`):                "",
		"not-a-jwt":                           "",
	} {
		if got := tokenType(in); got != want {
			t.Errorf("tokenType(%q) = %q, want %q", in, got, want)
		}
	}
}

// A key removed from the JWKS stops verifying once the key set's max age has passed.
func TestKeySetDropsDeletedKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	jwk := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "k1", Algorithm: "ES384", Use: "sig"}
	var published atomic.Bool
	published.Store(true)
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		set := jose.JSONWebKeySet{}
		if published.Load() {
			set.Keys = []jose.JSONWebKey{jwk}
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: jose.JSONWebKey{Key: priv, KeyID: "k1"}}, nil)
	sig, _ := signer.Sign([]byte(`{"sub":"x"}`))
	tok, _ := sig.CompactSerialize()

	ks := newKeySet(context.Background(), srv.URL, 50*time.Millisecond)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := ks.VerifySignature(ctx, tok); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1 (cached)", n)
	}
	published.Store(false) // key deleted in the IdP
	time.Sleep(60 * time.Millisecond)
	if _, err := ks.VerifySignature(ctx, tok); err == nil {
		t.Fatal("token signed with a deleted key still verifies after maxAge")
	}
}

// A Management API token refused before its expiry is dropped and fetched again once.
func TestAPIRetriesWithFreshTokenOn401(t *testing.T) {
	var issued, calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oidc/token":
			n := issued.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok" + string(rune('0'+n)), "expires_in": 3600})
		case "/api/users":
			calls.Add(1)
			if r.Header.Get("Authorization") == "Bearer tok1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1"})
		}
	}))
	defer srv.Close()
	cfg := Config{InternalURL: srv.URL, AdminClientID: "a", AdminClientSecret: "s"}
	c := &Client{cfg: cfg, http: srv.Client(), mgmt: newTokenSource(srv.Client(), cfg)}
	id, err := c.CreateUser(context.Background(), "a@b.c", "pw", "user")
	if err != nil || id != "u1" {
		t.Fatalf("CreateUser = %q, %v", id, err)
	}
	if issued.Load() != 2 || calls.Load() != 2 {
		t.Fatalf("tokens issued %d, calls %d; want 2, 2", issued.Load(), calls.Load())
	}
}

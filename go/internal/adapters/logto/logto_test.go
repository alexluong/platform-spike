package logto

import (
	"encoding/base64"
	"testing"
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

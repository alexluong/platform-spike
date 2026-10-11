package ory

import "testing"

func TestCheckAccessToken(t *testing.T) {
	const login = "driver-client"
	cases := []struct {
		name, clientID, sub string
		ok                  bool
	}{
		{"user token from the login client", login, "kratos-identity", true},
		{"client_credentials (app/agent)", "app-client", "app-client", true},
		{"ID token (no client_id claim)", "", "kratos-identity", false},
		{"user token from another client with the audience", "other-client", "kratos-identity", false},
	}
	for _, c := range cases {
		if err := checkAccessToken(c.clientID, c.sub, login); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}

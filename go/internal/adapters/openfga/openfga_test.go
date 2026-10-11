package openfga

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexluong/platform-spike/go/internal/authz"
)

// Apply's error classification against the bodies OpenFGA v1.22 really returns
// (captured from the stack b server).
func TestApplyClassifiesErrors(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		permanent  bool
	}{
		{"tuple doesn't fit the model", `{"code":"validation_error","message":"Invalid tuple 'role:x#nope@user:*'. Reason: relation 'role#nope' not found"}`, 400, true},
		{"pinned model gone", `{"code":"authorization_model_not_found","message":"Authorization Model '01M4NN4RWP4QJAEX2M79ESMPHZ' not found"}`, 400, false},
		{"store gone / no model", `{"code":"latest_authorization_model_not_found","message":"No authorization models found for store"}`, 400, false},
		{"conflicting condition", `{"code":"Aborted","message":"transactional write failed due to conflict"}`, 409, false},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		api, err := newAPI(srv.URL, "01M4NN4RVVVS1MA294S95M3THS", "01M4NN4RWP4QJAEX2M79ESMPHX")
		if err != nil {
			t.Fatal(err)
		}
		cl := &Client{api: api, now: time.Now}
		err = cl.Apply(context.Background(), authz.Event{Type: authz.EvMerchantCreated, MerchantID: "m1"})
		srv.Close()
		if err == nil {
			t.Fatalf("%s: no error", c.name)
		}
		if got := errors.Is(err, authz.ErrPermanent); got != c.permanent {
			t.Errorf("%s: permanent=%v, want %v (%v)", c.name, got, c.permanent, err)
		}
	}
}

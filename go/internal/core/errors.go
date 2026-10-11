package core

import (
	"errors"
	"fmt"
	"net/http"
)

// Err is an API error: HTTP status + snake_case code (SPEC §9).
type Err struct {
	Status  int
	Code    string
	Message string
}

func (e *Err) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message) }

func E(status int, code, msg string) *Err { return &Err{Status: status, Code: code, Message: msg} }

var (
	ErrUnauthenticated   = E(http.StatusUnauthorized, "unauthenticated", "missing or invalid token")
	ErrForbidden         = E(http.StatusForbidden, "forbidden", "")
	ErrEscalation        = E(http.StatusForbidden, "escalation", "you cannot grant what you do not hold")
	ErrMerchantSuspended = E(http.StatusForbidden, "merchant_suspended", "merchant is suspended")
	ErrNotFound          = E(http.StatusNotFound, "not_found", "")
)

func BadInput(msg string) *Err  { return E(http.StatusBadRequest, "invalid_input", msg) }
func Conflict(code string) *Err { return E(http.StatusConflict, code, "") }

// AsErr maps any error to an API error. Unknown errors are a 500 without the
// cause (SQL, engine and IdP errors stay in the log, not the response).
func AsErr(err error) *Err {
	var e *Err
	if errors.As(err, &e) {
		return e
	}
	return E(http.StatusInternalServerError, "internal", "")
}

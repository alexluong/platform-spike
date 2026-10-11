package core

import (
	"context"

	"github.com/alexluong/platform-spike/go/internal/authz"
	"github.com/alexluong/platform-spike/go/internal/perm"
)

// Unlimited stands for "no refund limit" in the refund condition. 2^53 is
// exact through JSON/structpb doubles, so engines compare it correctly.
const Unlimited int64 = 1 << 53

// HoldsAll is the no-escalation guardrail (SPEC §3): the caller must hold every
// permission at t, all through can(). refundAmount is the amount order.refund
// is checked with: the role's limit (or Unlimited) when granting a role, 0 when
// only "holds refund at all" matters.
func (r *Req) HoldsAll(ctx context.Context, t Target, perms []string, refundAmount int64) (bool, error) {
	if len(perms) == 0 {
		return true, nil
	}
	checks := make([]Check, len(perms))
	for i, p := range perms {
		checks[i] = Check{Action: p, Target: t, Context: RefundContext(p, refundAmount)}
	}
	ok, err := r.CanMany(ctx, checks)
	if err != nil {
		return false, err
	}
	for _, b := range ok {
		if !b {
			return false, nil
		}
	}
	return true, nil
}

// RefundContext is the condition context for an action (only order.refund has one).
func RefundContext(action string, amount int64) map[string]any {
	if action != perm.RefundAction {
		return nil
	}
	return map[string]any{authz.CtxAmountCents: amount}
}

// NonNil returns s, or an empty slice so JSON says [] not null.
func NonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Dedupe keeps the first occurrence of each string.
func Dedupe(s []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

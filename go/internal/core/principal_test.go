package core

import (
	"testing"

	"github.com/alexluong/platform-spike/go/internal/identity"
	"github.com/alexluong/platform-spike/go/internal/perm"
)

// review-i: a principal of a merchant's own pool is accepted only with a token of that pool
// (stack i used to set no Token.MerchantID, so this rule, which h2 relies on, did not exist
// for i; merged with h2's core it would also have locked every i tenant principal out).
func TestTokenFits(t *testing.T) {
	customer := &Principal{Kind: perm.KindCustomer, HomeMerchantID: "m1"}
	partner := &Principal{Kind: perm.KindUser, MerchantIDs: []string{"m1", "m2"}}
	shop := &Principal{Kind: perm.KindCustomer}
	cases := []struct {
		name string
		tok  identity.Token
		p    *Principal
		want bool
	}{
		{"tenant customer, own pool", identity.Token{MerchantID: "m1"}, customer, true},
		{"tenant customer, other pool", identity.Token{MerchantID: "m2"}, customer, false},
		{"tenant customer, platform-level token", identity.Token{}, customer, false},
		{"staff (platform account), platform token", identity.Token{}, &Principal{Kind: perm.KindUser, MerchantIDs: []string{"m1"}, MerchantID: "m1"}, true},
		{"staff (platform account), a tenant pool's token", identity.Token{MerchantID: "m2"}, &Principal{Kind: perm.KindUser, MerchantIDs: []string{"m1"}, MerchantID: "m1"}, false},
		{"partner, no tenant in token", identity.Token{}, partner, true},
		{"partner, org claim of a member merchant", identity.Token{MerchantID: "m2"}, partner, true},
		{"partner, org claim of another merchant", identity.Token{MerchantID: "m3"}, partner, false},
		{"shop buyer", identity.Token{}, shop, true},
	}
	for _, c := range cases {
		if got := tokenFits(c.tok, c.p); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

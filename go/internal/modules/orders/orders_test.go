package orders

import (
	"math"
	"testing"
)

func TestMulAdd(t *testing.T) {
	cases := []struct {
		total, price, qty, want int64
		ok                      bool
	}{
		{0, 1000, 3, 3000, true},
		{500, 0, math.MaxInt64, 500, true},
		{0, 1000, 1 << 62, 0, false}, // the overflow the suite sends: wrapped to 96000 before
		{math.MaxInt64 - 10, 1, 10, math.MaxInt64, true},
		{math.MaxInt64 - 10, 1, 11, 0, false},
	}
	for _, c := range cases {
		got, ok := mulAdd(c.total, c.price, c.qty)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("mulAdd(%d,%d,%d) = %d,%v; want %d,%v", c.total, c.price, c.qty, got, ok, c.want, c.ok)
		}
	}
}

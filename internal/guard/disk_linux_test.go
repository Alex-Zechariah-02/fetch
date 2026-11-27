// Linux disk byte counts preserve block totals up to the signed byte limit.

package guard

import (
	"math"
	"testing"
)

func TestBlockBytes(t *testing.T) {
	const page = 4096
	for _, tc := range []struct {
		name         string
		blocks, size uint64
		want         int64
	}{
		{"ordinary product", 12, page, 12 * page},
		{"signed maximum", math.MaxInt64, 1, math.MaxInt64},
		{"above signed range", math.MaxInt64 + 1, 1, math.MaxInt64},
		{"above unsigned range", 1<<52 + 1, page, math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := blockBytes(tc.blocks, tc.size); got != tc.want {
				t.Fatalf("blockBytes(%d, %d) = %d, want %d", tc.blocks, tc.size, got, tc.want)
			}
		})
	}
}

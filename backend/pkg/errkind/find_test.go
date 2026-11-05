package errkind

import (
	"errors"
	"fmt"
	"testing"
)

// Find answers the error the mark of that kind classified: never a wrapper
// added above the mark, never a mark of another kind, never an error that
// merely wraps the kind's sentinel by hand.
func TestFind_MarkedErrorOnly(t *testing.T) {
	own := errors.New("path is required")
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"nil", nil, nil},
		{"unmarked", errors.New("boom"), nil},
		{"sentinel wrapped by hand", fmt.Errorf("x: %w: %w", errKindA, own), nil},
		{"other kind only", Mark(errKindB, own), nil},
		{"marked", Mark(errKindA, own), own},
		{"under a wrapper", fmt.Errorf("outer %s: %w", "detail", Mark(errKindA, own)), own},
		{"below a mark of another kind", Mark(errKindB, Mark(errKindA, own)), own},
	}
	for _, tc := range cases {
		if got := Find(tc.err, errKindA); got != tc.want {
			t.Errorf("%s: Find = %v, want %v", tc.name, got, tc.want)
		}
	}
}

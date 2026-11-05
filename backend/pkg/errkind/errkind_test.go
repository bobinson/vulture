package errkind

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

var (
	errKindA = errors.New("kind a")
	errKindB = errors.New("kind b")
)

// Mark classifies without rewording: the text is the cause's, byte for byte,
// errors.Is reaches both the kind and everything the cause wraps, and
// errors.As still finds a typed cause.
func TestMark_TextPreservedIsAndUnwrap(t *testing.T) {
	cause := fmt.Errorf("open repo: %w", &fs.PathError{Op: "open", Path: "repo", Err: fs.ErrNotExist})
	marked := Mark(errKindA, cause)

	if marked.Error() != cause.Error() {
		t.Errorf("Error() = %q, want the cause's text %q", marked.Error(), cause.Error())
	}
	if errors.Unwrap(marked) != cause {
		t.Errorf("Unwrap() = %v, want the cause itself", errors.Unwrap(marked))
	}
	wantIs(t, marked, errKindA, cause, fs.ErrNotExist)
	wantPathError(t, marked, "repo")
}

// A mark names one kind; two marks name both, and an outer wrapper keeps them.
func TestMark_KindsAreDistinctAndStack(t *testing.T) {
	cause := errors.New("boom")
	if errors.Is(Mark(errKindA, cause), errKindB) {
		t.Error("a mark of kind a must not match kind b")
	}
	both := fmt.Errorf("outer: %w", Mark(errKindB, Mark(errKindA, cause)))
	wantIs(t, both, errKindA, errKindB, cause)
	if both.Error() != "outer: boom" {
		t.Errorf("Error() = %q, want %q", both.Error(), "outer: boom")
	}
}

func TestMark_Nil(t *testing.T) {
	if err := Mark(errKindA, nil); err != nil {
		t.Errorf("Mark(kind, nil) = %v, want nil", err)
	}
}

func wantIs(t *testing.T, err error, targets ...error) {
	t.Helper()
	for _, target := range targets {
		if !errors.Is(err, target) {
			t.Errorf("errors.Is(%q, %q) = false, want true", err, target)
		}
	}
}

func wantPathError(t *testing.T, err error, path string) {
	t.Helper()
	var pe *fs.PathError
	if !errors.As(err, &pe) || pe.Path != path {
		t.Errorf("errors.As(*fs.PathError) through the mark: got %v, want path %q", pe, path)
	}
}

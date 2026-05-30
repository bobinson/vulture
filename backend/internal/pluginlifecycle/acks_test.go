package pluginlifecycle_test

// BLOCKER 3 / AC2: interactive ack prompt seam.
//
// Signature pinned by LLD:
//   func PromptAcks(acks []string, in io.Reader, out io.Writer) error
//
// Behaviour:
//   - Prints each ack to `out` before reading
//   - Returns nil iff the operator types literal "YES" + newline
//   - Returns *DeclinedError for any other input (including empty / EOF)
//   - Bounded read: at most 1 KiB consumed from `in` before error
//
// CLI passes os.Stdin / os.Stderr. Tests pass bytes.NewBufferString.

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/pluginlifecycle"
)

func TestPromptAcks_AcceptsUppercaseYES_AC2(t *testing.T) {
	in := bytes.NewBufferString("YES\n")
	out := &bytes.Buffer{}
	err := pluginlifecycle.PromptAcks([]string{"network-egress"}, in, out)
	if err != nil {
		t.Fatalf("PromptAcks(YES): %v", err)
	}
}

func TestPromptAcks_PrintsEachAckToWriter(t *testing.T) {
	in := bytes.NewBufferString("YES\n")
	out := &bytes.Buffer{}
	acks := []string{"network-egress", "runs-real-exploits"}
	if err := pluginlifecycle.PromptAcks(acks, in, out); err != nil {
		t.Fatalf("PromptAcks: %v", err)
	}
	s := out.String()
	for _, a := range acks {
		if !strings.Contains(s, a) {
			t.Errorf("output missing ack %q; got %q", a, s)
		}
	}
}

func TestPromptAcks_RejectsCases_AC2(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"lowercase", "yes\n"},
		{"plain_no", "no\n"},
		{"empty_eof", ""},
		{"random_text", "I really want this plugin\n"},
		{"trailing_space", "YES \n"},
		{"missing_newline", "YES"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := bytes.NewBufferString(tc.input)
			out := &bytes.Buffer{}
			err := pluginlifecycle.PromptAcks([]string{"network-egress"}, in, out)
			if err == nil {
				t.Fatalf("expected error for input %q", tc.input)
			}
			var de *pluginlifecycle.DeclinedError
			if !errors.As(err, &de) {
				t.Errorf("expected *DeclinedError, got %T: %v", err, err)
			}
		})
	}
}

// hostileReader spews 'A' indefinitely. Used to verify the 1KiB
// read bound — PromptAcks must NOT exhaust memory or hang.
type hostileReader struct{ n int }

func (h *hostileReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	h.n += len(p)
	return len(p), nil
}

func TestPromptAcks_BoundedReadOnHostileInput(t *testing.T) {
	hostile := &hostileReader{}
	out := &bytes.Buffer{}
	err := pluginlifecycle.PromptAcks([]string{"network-egress"}, hostile, out)
	if err == nil {
		t.Fatalf("expected error on hostile unbounded input")
	}
	// The implementation MUST cap reads at 1 KiB. We allow a bit of
	// slack for buffered readers (some readers pre-fetch 4096), but
	// the result must NOT consume megabytes.
	if hostile.n > 8*1024 {
		t.Errorf("PromptAcks read %d bytes; expected <= 8KiB cap", hostile.n)
	}
}

// Verifying the function shape matches the LLD signature.
var _ = func(acks []string, in io.Reader, out io.Writer) error {
	return pluginlifecycle.PromptAcks(acks, in, out)
}

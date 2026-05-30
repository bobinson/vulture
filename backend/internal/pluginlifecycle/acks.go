package pluginlifecycle

import (
	"fmt"
	"io"
	"strings"
)

// maxAckInputBytes caps the read from the operator. A hostile / runaway
// stdin must not exhaust memory or hang the install.
const maxAckInputBytes = 1024

// DeclinedError is returned by PromptAcks when the operator did not
// reply with the literal token "YES\n".
type DeclinedError struct {
	Reason string
}

func (e *DeclinedError) Error() string {
	if e.Reason == "" {
		return "ack prompt declined"
	}
	return "ack prompt declined: " + e.Reason
}

// PromptAcks prints each ack as a bullet line to `out`, reads up to
// 1KiB from `in`, and returns nil iff the operator typed the literal
// "YES" followed by a newline. Any other input (including EOF /
// missing newline / lowercase / trailing whitespace) returns a
// *DeclinedError.
//
// BLOCKER 3: the io.Reader / io.Writer seam means tests inject
// bytes.NewBufferString; the CLI passes os.Stdin / os.Stderr.
func PromptAcks(acks []string, in io.Reader, out io.Writer) error {
	if err := printAckList(acks, out); err != nil {
		return err
	}
	line, err := readBoundedLine(in, maxAckInputBytes)
	if err != nil {
		return &DeclinedError{Reason: err.Error()}
	}
	if line != "YES" {
		return &DeclinedError{Reason: fmt.Sprintf("operator typed %q, expected literal YES", line)}
	}
	return nil
}

func printAckList(acks []string, out io.Writer) error {
	if _, err := fmt.Fprintln(out, "This plugin requires the following acknowledgements:"); err != nil {
		return err
	}
	for _, a := range acks {
		if _, err := fmt.Fprintf(out, "  - %s\n", a); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(out, "Type YES (uppercase) to install:"); err != nil {
		return err
	}
	return nil
}

// readBoundedLine reads up to `max` bytes from r, stops at the first
// newline, and returns the line (sans trailing newline) verbatim — no
// trim of surrounding whitespace. Tests require that "YES \n" is
// rejected and "YES" without trailing newline is rejected.
func readBoundedLine(r io.Reader, max int) (string, error) {
	buf := make([]byte, 0, 64)
	one := make([]byte, 1)
	sawNewline := false
	total := 0
	for total < max {
		n, err := r.Read(one)
		if n > 0 {
			total += n
			if one[0] == '\n' {
				sawNewline = true
				break
			}
			buf = append(buf, one[0])
		}
		if err != nil {
			break
		}
	}
	if !sawNewline {
		return string(buf), fmt.Errorf("no newline within %d bytes", max)
	}
	// Reject trailing whitespace by returning verbatim — caller checks
	// for exact "YES".
	return strings.TrimRight(string(buf), "\r"), nil
}

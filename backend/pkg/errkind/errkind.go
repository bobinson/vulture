// Package errkind classifies an error without rewording it. A caller decides
// what to do by kind (errors.Is), while the error's text, which the log
// needs, stays exactly the cause's. Standard library only.
package errkind

import "errors"

// marked is an error classified as kind. Its text is the cause's, unchanged.
type marked struct{ kind, err error }

func (m *marked) Error() string        { return m.err.Error() }
func (m *marked) Unwrap() error        { return m.err }
func (m *marked) Is(target error) bool { return target == m.kind }

// Mark returns err classified as kind: errors.Is(_, kind) holds, Error() is
// err.Error() byte for byte, and Unwrap() is err, so errors.Is and errors.As
// still reach everything err wraps. Mark(kind, nil) is nil.
func Mark(kind, err error) error {
	if err == nil {
		return nil
	}
	return &marked{kind: kind, err: err}
}

// Find returns the outermost error in err's chain that Mark classified as
// kind, or nil. Its text is that error's own: a wrapper added above the mark
// contributes nothing to it.
func Find(err, kind error) error {
	var m *marked
	for errors.As(err, &m) {
		if m.kind == kind {
			return m.err
		}
		err = m.err
	}
	return nil
}

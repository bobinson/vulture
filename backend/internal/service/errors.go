package service

import (
	"errors"
	"fmt"

	"github.com/vulture/backend/pkg/errkind"
	"github.com/vulture/backend/pkg/gitutil"
	"github.com/vulture/backend/pkg/netguard"
)

var ErrNotFound = errors.New("not found")

// ErrInvalidInput classifies an error the caller can fix (a 400). Only
// InvalidInput and InvalidInputMsg mark it: an error that merely wraps the
// sentinel is not a caller error, so the handler fails closed to a generic
// 500.
var ErrInvalidInput = errors.New("invalid input")

// ErrEmailRegistered is Register's refusal of an email that already has an
// account.
var ErrEmailRegistered = errors.New("email already registered")

// InvalidInput marks err as the caller's to fix: the handler answers 400
// with err's own text, so that text must hold only what the caller sent plus
// literals. The text is unchanged; nil stays nil.
func InvalidInput(err error) error { return errkind.Mark(ErrInvalidInput, err) }

// callerError carries the curated literal a caller sees in place of err's
// text, which names something of the server's and goes to the log only.
type callerError struct {
	msg string
	err error
}

func (e *callerError) Error() string { return e.err.Error() }
func (e *callerError) Unwrap() error { return e.err }

// InvalidInputMsg marks err as the caller's to fix, answered with the
// curated literal msg: err's text (a resolved address, git stderr) is logged,
// never shown. The text is unchanged; nil stays nil.
func InvalidInputMsg(err error, msg string) error {
	if err == nil {
		return nil
	}
	return InvalidInput(&callerError{msg: msg, err: err})
}

// CallerMessage is what the caller may see of err: a curated literal
// (curated), or the own text of the error InvalidInput marked, never an
// outer wrapper's. A curated literal wins wherever it sits in the chain, so a
// mark added above it cannot expose the text it hides. ok is false when err
// is not marked.
func CallerMessage(err error) (msg string, curated, ok bool) {
	var ce *callerError
	if errors.As(err, &ce) {
		return ce.msg, true, true
	}
	if own := errkind.Find(err, ErrInvalidInput); own != nil {
		return own.Error(), false, true
	}
	return "", false, false
}

// errRule marks an error of kind for the caller.
type errRule struct {
	kind error
	mark func(error) error
}

// classifyErr marks err by the first rule whose kind it is, else by otherwise.
func classifyErr(err error, rules []errRule, otherwise func(error) error) error {
	for _, r := range rules {
		if errors.Is(err, r.kind) {
			return r.mark(err)
		}
	}
	return otherwise(err)
}

// answerWith marks an error to be answered with the curated literal msg.
func answerWith(msg string) func(error) error {
	return func(err error) error { return InvalidInputMsg(err, msg) }
}

// unmarked leaves an error for the generic 500.
func unmarked(err error) error { return err }

// cloneRules is an allow-list: a refused URL shape keeps its own text, a
// refused host and a git run that git itself failed are answered with a
// literal, and anything else (askpass, key file, store, a git that could not
// start or was stopped with the request) is a server fault.
var cloneRules = []errRule{
	{gitutil.ErrURLNotAllowed, InvalidInput},
	{netguard.ErrHostRefused, answerWith("clone: git host is not permitted or cannot be resolved")},
	{gitutil.ErrCloneFailed, answerWith("clone: git clone failed: the repository is unreachable or the credentials were rejected")},
}

// webhookRules: a refused host is answered with a literal; a parse or
// scheme error is the caller's own input and keeps its text.
var webhookRules = []errRule{
	{netguard.ErrHostRefused, answerWith("invalid webhook_url: host is not permitted or cannot be resolved")},
}

// classifyCloneErr is a clone failure as the caller may see it.
func classifyCloneErr(err error) error {
	return classifyErr(fmt.Errorf("clone: %w", err), cloneRules, unmarked)
}

// classifyWebhookErr is a webhook_url refusal as the caller may see it.
func classifyWebhookErr(err error) error {
	return classifyErr(fmt.Errorf("invalid webhook_url: %w", err), webhookRules, InvalidInput)
}

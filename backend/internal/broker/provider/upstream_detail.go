package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// §5/N6 pass-through: the provider's own words, for the ONE class where they
// cannot carry request content.
//
// WHY THIS EXISTS. N6 makes the error envelope secret-free by using static
// messages, and that is right — an upstream 400 echoes the request, and the
// request holds the prompt. But applied to a 404 the rule hides the one fact
// the operator needs: WHICH model was rejected. Measured: Google answered 33
// times with "models/gemini-pro is not found for API version v1beta … Call
// ModelService.ListModels", the broker logged it and returned "model not found
// or not routable", and the agent surfaced `InternalServerError` with advice to
// check a base URL that was correct. The retired id was diagnosable only from
// broker stdout.
//
// WHY AN ALLOWLIST OF ONE. The model id is not a secret — the caller sent it,
// so returning it discloses nothing new. That argument does NOT extend to a
// 400/413/422, where the provider quotes the offending field back, nor to a 5xx
// whose body is arbitrary. So the pass-through is keyed to status 404/409 only
// and every other class keeps the static message. Widening this list is a
// security decision, not a formatting one.

// upstreamMessageMax bounds the borrowed text. A provider is not obliged to be
// terse and this string reaches logs, the SSE stream and the DB.
const upstreamMessageMax = 300

// upstreamAllowed reports whether a status may carry the provider's own text.
//
// EXACTLY 404, and the narrowness is the point. The disclosure warrant is not
// "this status maps to ErrModelNotFound", it is "the body can only restate
// something the CALLER already sent": a 404 is answered from the model name in
// the URL, so echoing it discloses nothing the caller did not supply.
//
// 409 rode along in the first cut purely because statusError happens to map it
// to the same sentinel — which is reasoning from the classification back to the
// warrant, exactly backwards. Conflict is not "no such model"; its body is
// provider-defined and may describe OTHER state (a concurrent fine-tune, a
// quota object, a billing record), none of it caller-derived.
//
// DELIBERATELY NOT derived from statusError, even though that would remove a
// duplicated literal. The two lists answer different questions — statusError
// asks "how should the client RETRY this", upstreamAllowed asks "may this text
// LEAVE the broker" — and they are correct to disagree on 409. Collapsing them
// would silently re-widen egress the next time a status joins the
// ErrModelNotFound arm. TestConflictIsNotAllowlisted pins the disagreement.
func upstreamAllowed(status int) bool {
	return status == http.StatusNotFound
}

// UpstreamDisclosable is upstreamAllowed, exported so the SERVER can re-apply
// the same predicate rather than infer the decision from a non-empty Message.
//
// Not duplicated logic — the same function. The server needs its own check
// because UpstreamError is an ordinary exported struct: anything that
// constructs one, in this package or a future one, can set Status and Message
// independently, and the field that would be wrong is not a label but the
// disclosed text itself. One predicate, applied at the boundary that produces
// the value AND at the boundary that publishes it.
func UpstreamDisclosable(status int) bool { return upstreamAllowed(status) }

// secretish matches text shaped like a credential. Defence in depth: the
// allowlisted class should never contain one, and "should never" is not a
// guarantee worth betting a key on.
//
// THE COST OF A MISS IS NOT SYMMETRIC WITH THE COST OF A FALSE POSITIVE. A
// missed credential is disclosed to whoever reads a log or an API response; a
// falsely redacted token costs an operator one lookup. So the list errs wide,
// and TestOrdinaryModelIdsAreNotRedacted bounds how wide by pinning that real
// model ids — the one thing this carve-out exists to show — still survive it.
//
// Ordered roughly by specificity; RE2 has no backtracking, so a long
// alternation is still linear in the input.
var secretish = regexp.MustCompile(
	`(?i)(?:` +
		// ── vendor-prefixed, unambiguous ──
		`\bAIza[0-9A-Za-z_\-]{10,}` + // Google API key
		`|\bsk-[0-9A-Za-z_\-]{12,}` + // OpenAI-style
		`|\beyJ[0-9A-Za-z._\-]{16,}` + // JWT (base64 '{"')
		`|\bgh[pousr]_[0-9A-Za-z]{16,}` + // GitHub
		`|\bxox[baprse]-[0-9A-Za-z\-]{10,}` + // Slack
		`|\b(?:AKIA|ASIA|AROA|AIDA|ANPA|AIPA)[0-9A-Z]{12,}` + // AWS key id
		// ── header forms: the scheme word is the signal, so the opaque
		//    token after it needs no shape of its own ──
		`|\bBearer\s+[0-9A-Za-z._\-]{12,}` +
		`|\bBasic\s+[0-9A-Za-z+/=]{16,}` +
		// ── URL userinfo. Only the credential span is replaced; the host is
		//    not a secret and is often the point of the diagnosis ──
		`|[a-z][a-z0-9+.\-]*://[^\s/@:]+:[^\s/@]+@` +
		// ── PEM: the header alone means a key is being pasted ──
		`|-----BEGIN[ A-Z]{0,40}PRIVATE KEY-----` +
		// ── shapeless blobs. Length IS the signal: Azure keys are 32 hex,
		//    sha256-derived tokens 64 hex, AWS secret keys 40 base64. Bounded
		//    by \b so a hyphenated/colon-separated model id cannot reach the
		//    required run length ──
		`|\b[0-9a-f]{32,}\b` +
		`|\b[0-9A-Za-z+/]{38,}={0,2}\b` +
		`)`)

// UpstreamError carries a provider's own diagnosis alongside the typed class.
//
// It WRAPS the sentinel rather than replacing it, so every existing
// `errors.Is(err, ErrModelNotFound)` — including the server's providerErrTable
// — keeps working untouched.
type UpstreamError struct {
	Err      error  // the sentinel: ErrModelNotFound, ErrProviderBadRequest, …
	Provider string // "gemini" / "openai" / "anthropic"
	Status   int    // the upstream HTTP status
	Message  string // the provider's text, sanitised; "" when not allowlisted
}

// Error appends ONLY the borrowed message. The wrapped error already carries
// the status — every arm of statusError formats "%w: upstream status %d" — so
// re-stating it here printed it twice on every broker egress log line:
//
//	model not found: upstream status 404: upstream status 404: no such model
//
// With no message the string is exactly the wrapped error's, which is what
// makes wrapping invisible to any caller that only formats the error.
func (e *UpstreamError) Error() string {
	if e.Message == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%v: %s", e.Err, e.Message)
}

func (e *UpstreamError) Unwrap() error { return e.Err }

// statusErrorWithBody is statusError plus the provider's message, for the
// allowlisted class only. Classification is delegated, never re-implemented,
// so the two cannot drift.
func statusErrorWithBody(providerName string, status int, body []byte) error {
	base := statusError(status)
	if base == nil {
		return nil
	}
	return &UpstreamError{
		Err:      base,
		Provider: providerName,
		Status:   status,
		Message:  upstreamMessage(status, body),
	}
}

// upstreamMessage extracts the provider's human message when the class permits
// it. Every failure to parse yields "" — a missing diagnosis is a smaller
// problem than a wrong or leaky one.
func upstreamMessage(status int, body []byte) string {
	if !upstreamAllowed(status) || len(body) == 0 {
		return ""
	}
	// `error` is json.RawMessage, not a struct, because the field is not one
	// shape across providers. OpenAI and Google send an OBJECT; Ollama and
	// several OpenAI-compatible gateways send a bare STRING:
	//
	//     {"error": "model 'llama9' not found, try pulling it first"}
	//
	// Bound to a struct, that body fails to unmarshal AS A WHOLE, so the whole
	// message was discarded — and silently, as ordinary "no diagnosis". Ollama
	// is the local-model path this carve-out is most useful on, because a
	// mistyped local tag is the commonest way to reach a 404 at all.
	var env struct {
		Error json.RawMessage `json:"error"`
		// Anthropic nests the same idea one level differently.
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	msg := strings.TrimSpace(messageFromErrorField(env.Error))
	if msg == "" {
		msg = strings.TrimSpace(env.Message)
	}
	if msg == "" {
		return ""
	}
	// ORDER IS LOAD-BEARING, and each step must precede the next for a
	// different reason:
	//
	//  1. sanitise FIRST. RE2's `\s` is [\t\n\f\r ] only, but strings.Fields
	//     splits on unicode.IsSpace — so before this ran first, the generic
	//     `Bearer <token>` rule could not see a separator like U+00A0 or
	//     U+3000, and an opaque token leaked verbatim. Measured on all three.
	//  2. redact SECOND, on normalised text.
	//  3. truncate LAST. A secret straddling the cap would otherwise be cut in
	//     half, and the surviving half is still a secret.
	return truncateRunes(redactForLog(msg), upstreamMessageMax)
}

// redactForLog is steps 1 and 2 above as ONE function, because the order
// between them is a correctness property and callers kept getting it wrong —
// including drainErrBody, in the same change that introduced this. Anything
// written to an operator log or returned to a caller goes through here; the
// only thing left to the caller is the length budget, which differs by sink.
func redactForLog(s string) string {
	return secretish.ReplaceAllString(sanitiseForLog(s), "[redacted]")
}

// messageFromErrorField reads the provider's text out of an `error` field that
// may be an object, a bare string, or absent. An unrecognised shape yields "",
// never a Go-rendered dump of the raw JSON.
func messageFromErrorField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var obj struct {
		Message string `json:"message"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Message
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str
	}
	return ""
}

// sanitiseForLog drops anything that can steer a terminal or forge a log line,
// and collapses the rest to a single line.
//
// This string is written to operator logs and, on some deployments, to an
// audit's persisted degraded_reason. A provider is free to return whatever it
// likes, and a 404 message ECHOES A CALLER-SUPPLIED MODEL ID — so the content
// is partly attacker-influenced whenever a scanned tree can steer the model
// name. Measured before this: `\x1b[31m`, BEL and NUL all reached the log
// verbatim. strings.Fields alone handles \n and \r but not the rest of C0/C1.
//
// C0/C1 is necessary but NOT sufficient. Two other classes steer a reader just
// as an ANSI sequence does, and both survive a control-character filter because
// neither is a control character:
//
//   - BIDI OVERRIDES (U+202A-202E, U+2066-2069). A right-to-left override makes
//     a rendered model id read in reverse, so "gemini-evil" can be displayed as
//     "live-inimeg" in the operator's terminal and in the UI. The model id is
//     the ONE thing this carve-out exists to disclose accurately; a string that
//     renders as a different id than it contains defeats the whole feature.
//   - ZERO-WIDTH (U+200B-200D, U+FEFF). Invisible, so an id that LOOKS correct
//     compares unequal — the operator's next step is to diff a name against a
//     config that already matches, and nothing on screen explains why.
//
// Both are dropped outright rather than mapped to a space: unlike a control
// character they carry no separator meaning, and substituting a space would
// split one identifier into two.
func sanitiseForLog(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			return ' ' // whitespace, so the Fields collapse below absorbs it
		case r >= 0x202a && r <= 0x202e, // LRE RLE PDF LRO RLO
			r >= 0x2066 && r <= 0x2069, // LRI RLI FSI PDI
			r >= 0x200b && r <= 0x200d, // ZWSP ZWNJ ZWJ
			r == 0xfeff:                // BOM / ZWNBSP
			return -1 // dropped, never widened to a separator
		}
		return r
	}, s)
	return strings.Join(strings.Fields(cleaned), " ")
}

// truncateRunes caps LENGTH IN BYTES without splitting a rune. The budget is a
// byte budget because that is what bounds the wire and the log line, but a
// provider message is not obliged to be ASCII, and a byte slice through a
// multi-byte rune yields invalid UTF-8.
func truncateRunes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…(truncated)"
}

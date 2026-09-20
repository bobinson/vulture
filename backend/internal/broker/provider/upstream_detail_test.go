package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// §5/N6 SAYS THE ENVELOPE IS SECRET-FREE. THAT RULE IS RIGHT, AND IT IS ALSO
// WHY A RETIRED MODEL ID TOOK AN INVESTIGATION TO FIND.
//
// Google answers a bad model with a message naming the id and telling you to
// call ListModels. The broker logged it and returned a static "model not found
// or not routable", so the operator saw `InternalServerError` and advice to
// check a base URL that was correct. Measured: 33 upstream 404s for the
// retired `gemini-pro`, diagnosable only from broker stdout.
//
// The model id is not a secret — the CALLER SENT IT. But an upstream 400 can
// echo prompt content, which is secret-class, so the pass-through is an
// ALLOWLIST of one class, not a general relaxation. These tests pin the
// allowlist far harder than they pin the happy path: a leak here is worse than
// the diagnostic gap it closes.

const geminiNotFound = `{"error":{"code":404,"message":"models/gemini-pro is not found for API ` +
	`version v1beta, or is not supported for generateContent. Call ModelService.ListModels to ` +
	`see the list of available models and their supported methods.","status":"NOT_FOUND"}}`

func TestModelNotFoundCarriesTheProviderMessage(t *testing.T) {
	err := statusErrorWithBody("gemini", http.StatusNotFound, []byte(geminiNotFound))
	if !errors.Is(err, ErrModelNotFound) {
		t.Fatalf("classification must be unchanged: %v", err)
	}
	var ue *UpstreamError
	if !errors.As(err, &ue) {
		t.Fatal("a model_not_found must carry an UpstreamError the server can render")
	}
	if ue.Status != 404 || ue.Provider != "gemini" {
		t.Errorf("status/provider = %d/%q", ue.Status, ue.Provider)
	}
	if !strings.Contains(ue.Message, "gemini-pro") {
		t.Errorf("the model id is what the operator needs and the caller already sent it; got %q", ue.Message)
	}
	if !strings.Contains(ue.Message, "ListModels") {
		t.Errorf("the provider's own remedy must survive; got %q", ue.Message)
	}
}

// THE EXCLUSION. A 400 is where a provider echoes the request back.
func TestProviderBadRequestNeverCarriesUpstreamText(t *testing.T) {
	leaky := `{"error":{"message":"Invalid value at 'contents[0].parts[0].text': ` +
		`SECRET_TOKEN_abc123 and the user's prompt here","code":400}}`
	for _, status := range []int{400, 413, 422} {
		err := statusErrorWithBody("gemini", status, []byte(leaky))
		var ue *UpstreamError
		if errors.As(err, &ue) && ue.Message != "" {
			t.Fatalf("status %d must NOT carry upstream text (it can echo the prompt); got %q",
				status, ue.Message)
		}
		if strings.Contains(err.Error(), "SECRET_TOKEN") {
			t.Fatalf("status %d leaked request content into the error string: %v", status, err)
		}
	}
}

// Renamed from TestOnlyModelNotFoundIsAllowlisted: the sentinel is NOT the
// warrant. 404 and 409 share ErrModelNotFound and the allowlist deliberately
// splits them — see upstreamAllowed.
func TestOnlyStatus404IsAllowlisted(t *testing.T) {
	body := []byte(`{"error":{"message":"some upstream words"}}`)
	for _, tc := range []struct {
		status int
		allow  bool
	}{
		{404, true}, {409, false},
		{400, false}, {401, false}, {403, false}, {413, false}, {422, false},
		{429, false}, {408, false}, {500, false}, {502, false}, {503, false},
	} {
		err := statusErrorWithBody("openai", tc.status, body)
		var ue *UpstreamError
		got := errors.As(err, &ue) && ue.Message != ""
		if got != tc.allow {
			t.Errorf("status %d: carries upstream text = %v, want %v", tc.status, got, tc.allow)
		}
	}
}

func TestUpstreamMessageIsBounded(t *testing.T) {
	huge := `{"error":{"message":"` + strings.Repeat("A", 5000) + `"}}`
	err := statusErrorWithBody("gemini", 404, []byte(huge))
	var ue *UpstreamError
	if !errors.As(err, &ue) {
		t.Fatal("expected an UpstreamError")
	}
	if len(ue.Message) > upstreamMessageMax+len("…(truncated)") {
		t.Errorf("upstream message must be capped, got %d bytes", len(ue.Message))
	}
}

// Defence in depth: even on the allowlisted class, anything key-shaped goes.
func TestKeyShapedTextIsRedactedEvenWhenAllowlisted(t *testing.T) {
	for _, secret := range []string{
		"AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q", // Google API key shape
		"sk-proj-abcdefghijklmnopqrstuvwxyz012345",
		"Bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
	} {
		body := []byte(`{"error":{"message":"model x not found ` + secret + ` trailing"}}`)
		err := statusErrorWithBody("gemini", 404, []byte(body))
		var ue *UpstreamError
		if !errors.As(err, &ue) {
			t.Fatal("expected an UpstreamError")
		}
		if strings.Contains(ue.Message, secret) {
			t.Errorf("key-shaped text survived redaction: %q", ue.Message)
		}
	}
}

func TestAnUnparseableBodyDegradesToNoDetail(t *testing.T) {
	// `{"error":"bare"}` is NOT in this list: a string-valued error field is a
	// real provider shape (Ollama), and it is now read rather than dropped.
	// TestStringValuedErrorBodyIsUnderstood owns that case.
	for _, body := range [][]byte{nil, {}, []byte("not json"), []byte(`{"nope":1}`), []byte(`{"error":{}}`), []byte(`{"error":[1,2]}`)} {
		err := statusErrorWithBody("gemini", 404, body)
		if !errors.Is(err, ErrModelNotFound) {
			t.Fatalf("classification must survive a junk body: %v", err)
		}
		var ue *UpstreamError
		if errors.As(err, &ue) && ue.Message != "" {
			t.Errorf("no parseable message must mean no detail, got %q", ue.Message)
		}
	}
}

// The existing contract: statusError's classification is untouched.
func TestClassificationIsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{429, ErrRateLimited}, {408, ErrProviderUnavailable}, {401, ErrProviderAuth},
		{403, ErrProviderAuth}, {404, ErrModelNotFound}, {409, ErrModelNotFound},
		{400, ErrProviderBadRequest}, {500, ErrProviderUnavailable},
	} {
		if err := statusErrorWithBody("p", tc.status, nil); !errors.Is(err, tc.want) {
			t.Errorf("status %d -> %v, want %v", tc.status, err, tc.want)
		}
	}
	if statusErrorWithBody("p", 200, nil) != nil {
		t.Error("2xx must stay nil")
	}
}

// A provider's message lands in operator logs. Anything that can steer a
// terminal, or corrupt the JSON it is embedded in, must not survive.
func TestControlCharactersAreStripped(t *testing.T) {
	for name, raw := range map[string]string{
		"ansi colour": `model \u001b[31mRED\u001b[0m not found`,
		"bell":        `model \u0007 not found`,
		"nul":         `model \u0000 not found`,
		"backspace":   `model \u0008\u0008 not found`,
		"c1 escape":   `model \u009b31m not found`,
	} {
		m := upstreamMessage(404, []byte(`{"error":{"message":"`+raw+`"}}`))
		for _, r := range m {
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				t.Errorf("%s: control char %q survived in %q", name, r, m)
			}
		}
	}
}

// Truncation must not split a rune. 300 is a BYTE budget and a provider
// message is not obliged to be ASCII.
func TestTruncationIsRuneSafe(t *testing.T) {
	for _, filler := range []string{"\u00e9", "\u65e5", "\U0001f525"} { // 2-, 3- and 4-byte runes
		body := []byte(`{"error":{"message":"` + strings.Repeat(filler, 400) + `"}}`)
		m := upstreamMessage(404, body)
		if !utf8.ValidString(m) {
			t.Errorf("filler %q: truncation produced invalid UTF-8: %q", filler, m)
		}
	}
}

// Redaction must run BEFORE truncation, or a secret straddling the cap is only
// half-removed and the visible half is still a secret.
func TestRedactionPrecedesTruncation(t *testing.T) {
	secret := "AIzaSy" + strings.Repeat("Z", 34)
	body := `{"error":{"message":"` + strings.Repeat("x", upstreamMessageMax-10) + " " + secret + `"}}`
	m := upstreamMessage(404, []byte(body))
	if strings.Contains(m, "AIzaSy") {
		t.Errorf("a secret straddling the truncation boundary survived: %q", m)
	}
}

// ORDER MATTERS: normalise whitespace BEFORE redacting.
//
// RE2's \s is [\t\n\f\r ] only, while strings.Fields splits on unicode.IsSpace
// (U+00A0, U+2000-200A, U+3000, …). Redacting first therefore left the generic
// `Bearer <token>` rule unable to see its own separator: measured, an opaque
// token leaked verbatim behind NBSP, U+3000 and U+2000, and was caught only
// behind an ASCII space.
func TestGenericBearerRuleSurvivesUnicodeSeparators(t *testing.T) {
	const opaque = "Zx9Qw3Er7Ty1Ui5Op2As6Df0Gh4Jk8L" // matches no shape-specific rule
	for name, sep := range map[string]string{
		"ascii space":        " ",
		"NBSP U+00A0":        " ",
		"en quad U+2000":     " ",
		"ideographic U+3000": "　",
		"tab":                "\t",
	} {
		got := upstreamMessage(404, []byte(`{"error":{"message":"auth Bearer`+sep+opaque+` failed"}}`))
		if strings.Contains(got, opaque) {
			t.Errorf("%s: bearer token leaked: %q", name, got)
		}
	}
}

// ── narrowed to 404, derived not duplicated ──────────────────────────────────
//
// The warrant for the carve-out is specific: "a 404 names the model from the
// URL, and the caller supplied that model". 409 rode along because statusError
// happens to map it to the same sentinel, but Conflict is not "no such model" —
// its body is provider-defined and nothing says it is caller-derived.
func TestConflictIsNotAllowlisted(t *testing.T) {
	got := upstreamMessage(http.StatusConflict, []byte(`{"error":{"message":"some conflict detail"}}`))
	if got != "" {
		t.Errorf("409 must not carry upstream text: %q", got)
	}
}

// Bidi overrides and zero-width characters steer a renderer just as ANSI does,
// and survive a C0/C1-only filter.
func TestBidiAndZeroWidthAreStripped(t *testing.T) {
	for name, r := range map[string]rune{
		"RLO U+202E": '\u202e', "LRO U+202D": '\u202d', "LRI U+2066": '\u2066',
		"ZWSP U+200B": '\u200b', "BOM U+FEFF": '\ufeff', "ZWNJ U+200C": '\u200c',
	} {
		msg := upstreamMessage(404, []byte(`{"error":{"message":"model `+string(r)+`x not found"}}`))
		if strings.ContainsRune(msg, r) {
			t.Errorf("%s survived: %q", name, msg)
		}
	}
}

// Ollama and several OpenAI-compatible gateways answer with a STRING error.
// Binding `error` to a struct made the whole decode fail and silently yield "".
func TestStringValuedErrorBodyIsUnderstood(t *testing.T) {
	got := upstreamMessage(404, []byte(`{"error":"model 'llama9' not found, try pulling it first"}`))
	if !strings.Contains(got, "llama9") {
		t.Errorf("a string-valued error body must still yield its message, got %q", got)
	}
}

// statusError already formats "%w: upstream status %d"; Error() appended it a
// second time, so every broker egress log line carried the status twice.
func TestErrorStringStatesTheStatusOnce(t *testing.T) {
	err := statusErrorWithBody("gemini", 404, []byte(`{"error":{"message":"no such model"}}`))
	if n := strings.Count(err.Error(), "upstream status"); n != 1 {
		t.Errorf("status clause appears %d times: %q", n, err.Error())
	}
	plain := statusErrorWithBody("gemini", 500, nil)
	if n := strings.Count(plain.Error(), "upstream status"); n != 1 {
		t.Errorf("status clause appears %d times: %q", n, plain.Error())
	}
}

// ── the LOG line, which carries far more than the egress envelope ───────────
//
// upstreamMessage sanitises what LEAVES the broker, but drainErrBody logs the
// whole raw body on EVERY non-2xx — a wider surface than the carve-out by two
// dimensions: no status allowlist, and no field selection. A provider that can
// steer that string steers the operator's terminal on a 400 it was never
// allowed to speak on.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prevW, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevW); log.SetFlags(prevFlags) })
	fn()
	return buf.String()
}

func TestLoggedErrorBodyIsSanitisedOnEveryStatus(t *testing.T) {
	// 400 is deliberately NOT allowlisted for egress; the log still gets it.
	raw := "boom \x1b[31mRED\x07 ‮reversed​ zero " +
		"AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q\nsecond line"
	body, err := json.Marshal(map[string]any{"error": map[string]any{"message": raw}})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for _, status := range []int{400, 404, 500} {
		out := captureLog(t, func() {
			drainErrBody("gemini", status, nil, bytes.NewReader(body))
		})
		for _, bad := range []string{"\x1b", "\x07", "‮", "​", "\n" + "second"} {
			if strings.Contains(strings.TrimSuffix(out, "\n"), bad) {
				t.Errorf("status %d: log kept a steering/forging sequence %q: %q", status, bad, out)
			}
		}
		if strings.Contains(out, "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q") {
			t.Errorf("status %d: an API key reached the log verbatim: %q", status, out)
		}
		if !strings.Contains(out, "boom") {
			t.Errorf("status %d: sanitising must not destroy the diagnosis: %q", status, out)
		}
	}
}

// A body cut at the read cap yields invalid JSON, and "invalid JSON" is
// indistinguishable from "provider said nothing" — the operator is told there
// is no diagnosis when in fact there was one and we dropped it.
func TestAnOversizeBodySaysItWasTruncated(t *testing.T) {
	huge := `{"error":{"message":"` + strings.Repeat("A", 32<<10) + `"}}`
	out := captureLog(t, func() {
		drainErrBody("openai", 404, nil, strings.NewReader(huge))
	})
	if !strings.Contains(out, "body_truncated=true") {
		t.Errorf("an oversize body must be reported as truncated, not silently cut: %q",
			truncStr(out, 200))
	}
}

// UP-1, one sink over. The redaction runs on RE2, whose `\s` is [\t\n\f\r ],
// so a `Bearer <token>` separated by a unicode space is invisible to it unless
// sanitiseForLog has already normalised the space away. The envelope path got
// that order right; the log path was written the other way round in the same
// change, which is why the order now lives in one function (redactForLog).
func TestLoggedBodyRedactsBehindUnicodeWhitespace(t *testing.T) {
	const token = "eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop.qrstuv"
	for _, space := range []string{" ", " ", "　"} {
		out := captureLog(t, func() {
			drainErrBody("openai", 400, nil,
				strings.NewReader(`{"error":{"message":"auth Bearer`+space+token+`"}}`))
		})
		if strings.Contains(out, token) {
			t.Errorf("token leaked behind %q: %q", space, out)
		}
	}
}

// Control characters arrive as RAW BYTES off the wire, not as the \u escapes a
// Go-side json.Marshal would produce.
func TestLoggedBodySanitisesRawControlBytes(t *testing.T) {
	out := captureLog(t, func() {
		drainErrBody("gemini", 500, nil,
			strings.NewReader("\x1b[31mred\x07\x00 body\nforged: line"))
	})
	for _, bad := range []string{"\x1b", "\x07", "\x00", "\nforged"} {
		if strings.Contains(strings.TrimSuffix(out, "\n"), bad) {
			t.Errorf("raw control byte %q survived into the log: %q", bad, out)
		}
	}
}

// UP-2: the shapes the first cut missed. Each is a credential class that
// plausibly appears in a provider error body or a gateway's echo of a
// misconfigured header, and none matched the original five alternatives.
func TestSecretShapesBeyondTheFirstFive(t *testing.T) {
	for name, secret := range map[string]string{
		"AWS access key id":  "AKIAIOSFODNN7EXAMPLE",
		"AWS secret key":     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"Azure 32-hex key":   "0123456789abcdef0123456789abcdef",
		"sha256-shaped key":  "3b7c1d9e5f2a8b4c6d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e",
		"basic auth header":  "Basic dXNlcm5hbWU6c3VwZXJzZWNyZXRwYXNzd29yZA==",
		"url userinfo":       "https://admin:hunter2handshake@internal.example.com/v1",
		"private key header": "-----BEGIN RSA PRIVATE KEY-----",
		"slack token":        "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
	} {
		got := upstreamMessage(404, []byte(`{"error":{"message":"model x not found: `+secret+` here"}}`))
		if strings.Contains(got, secret) {
			t.Errorf("%s survived redaction: %q", name, got)
		}
		if !strings.Contains(got, "model x not found") {
			t.Errorf("%s: redaction destroyed the diagnosis: %q", name, got)
		}
	}
}

// The redaction must not eat the thing the carve-out exists to show. A model
// id is the expected content of an allowlisted 404 body.
func TestOrdinaryModelIdsAreNotRedacted(t *testing.T) {
	for _, id := range []string{
		"models/gemini-2.5-pro", "gpt-4o-2024-11-20", "claude-sonnet-4-5-20250929",
		"qwen3:1.7b", "ft:gpt-4o:acme::AbCd1234", "llama-3.1-8b-instruct-q4_K_M",
	} {
		got := upstreamMessage(404, []byte(`{"error":{"message":"`+id+` is not found for API version v1beta"}}`))
		if !strings.Contains(got, id) {
			t.Errorf("model id %q was redacted — the carve-out exists to show exactly this: %q", id, got)
		}
	}
}

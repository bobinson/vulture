package provider

// Feature 0074 #5 / contract C5: an upstream context overflow (a 413, or a
// 4xx whose body names the context/size limit) is its own permanent class,
// ErrContextOverflow, so the broker can answer provider_context_overflow and
// the agent can halve and retry instead of giving up on a "bad request".

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

var overflowCases = []struct {
	name   string
	status int
	body   string
	want   bool
}{
	{"413 no body", 413, "", true},
	{"413 request_too_large", 413, `{"error":{"type":"request_too_large","message":"Request exceeds the maximum size"}}`, true},
	{"400 context_length_exceeded", 400, `{"error":{"code":"context_length_exceeded","message":"This model's maximum context length is 8192 tokens."}}`, true},
	{"400 prompt too long", 400, `{"error":{"type":"invalid_request_error","message":"prompt is too long: 210000 tokens > 200000 maximum"}}`, true},
	{"400 llama n_ctx", 400, `{"error":"the request exceeds the available context size (n_keep 9000 >= n_ctx 8192)"}`, true},
	{"400 bare string context window", 400, `{"error":"input exceeds the context window"}`, true},
	{"422 payload too large", 422, `{"message":"payload too large"}`, true},
	{"400 unrelated schema fault", 400, `{"error":{"message":"Invalid schema for function 'f'"}}`, false},
	{"400 empty", 400, "", false},
	{"404 mentions context", 404, `{"error":"model context-7b not found"}`, false},
	{"500 overflow text", 500, `{"error":"maximum context length"}`, false},
}

func TestContextOverflowIsItsOwnPermanentClass_0074(t *testing.T) {
	for _, c := range overflowCases {
		err := statusErrorWithBody("openai", c.status, []byte(c.body))
		if got := errors.Is(err, ErrContextOverflow); got != c.want {
			t.Errorf("%s: errors.Is(ErrContextOverflow)=%v, want %v (err %v)", c.name, got, c.want, err)
		}
		if c.want && (!IsPermanent(err) || !errors.Is(err, ErrProviderBadRequest) || IsProviderHealthFailure(err)) {
			t.Errorf("%s: an overflow stays a permanent, breaker-neutral bad request: %v", c.name, err)
		}
	}
}

// Re-audit R6: the overflow vocabulary is size/overflow phrasing only, pinned
// by the message fixture the agent's _CTX_OVERFLOW_RE also reads.
func TestContextOverflowBodyMatchesTheSharedMessages_0074(t *testing.T) {
	for _, m := range overflowMessages(t) {
		if got := contextOverflowBody.MatchString(m.Text); got != m.Overflow {
			t.Errorf("contextOverflowBody.Match(%q) = %v, want %v", m.Text, got, m.Overflow)
		}
	}
}

type overflowMessage struct {
	Text     string `json:"text"`
	Overflow bool   `json:"overflow"`
}

func overflowMessages(t *testing.T) []overflowMessage {
	t.Helper()
	raw, err := os.ReadFile("testdata/ctx_overflow_messages_0074.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc struct {
		Messages []overflowMessage `json:"messages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Messages) == 0 {
		t.Fatalf("decode fixture: %v (%d messages)", err, len(doc.Messages))
	}
	return doc.Messages
}

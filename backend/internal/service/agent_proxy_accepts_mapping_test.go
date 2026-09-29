package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 §2.1 (H1): the OWASP mapping capability travels OUT OF BAND,
// as a top-level `accepts_mapping` field of the /run body the agent proxy
// writes, never inside the user-controllable `config`. A pre-0096 backend
// forwards arbitrary user config keys to agents, so a capability read from
// config would let a user POST {"accepts_mapping":1} to a pre-0096 backend and
// have it read a zero-finding OWASP result as "every OWASP issue was fixed".

// captureRunBody runs one proxied request and returns the decoded /run body.
func captureRunBody(t *testing.T, agentType string, cfg json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	ch := make(chan *model.AgUIEvent, 10)
	if err := NewAgentProxyService(nil).RunAgentWithContext(
		context.Background(), srv.URL, agentType, "run-h1", "/src", cfg, nil, nil, ch); err != nil {
		t.Fatalf("run %s: %v", agentType, err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode /run body %q: %v", raw, err)
	}
	return body
}

func TestAgentProxy_OwaspRunBodyCarriesAcceptsMappingTopLevel(t *testing.T) {
	body := captureRunBody(t, "owasp", json.RawMessage(`{"edition":"2025","cwe_stage_status":"completed"}`))
	got, ok := body["accepts_mapping"]
	if !ok {
		t.Fatalf("owasp /run body has no top-level accepts_mapping: %v", body)
	}
	// The JSON integer 1 — not true, not "1", not 1.0.
	if string(got) != "1" {
		t.Fatalf("owasp /run accepts_mapping = %s, want the JSON integer 1", got)
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(body["config"], &cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if _, present := cfg["accepts_mapping"]; present {
		t.Errorf("owasp config carries accepts_mapping; the capability is out of band only: %s", body["config"])
	}
	if string(cfg["edition"]) != `"2025"` || string(cfg["cwe_stage_status"]) != `"completed"` {
		t.Errorf("owasp config lost its keys: %s", body["config"])
	}
}

func TestAgentProxy_NonOwaspRunBodyNeverCarriesAcceptsMapping(t *testing.T) {
	for _, agent := range []string{"cwe", "chaos", "soc2", "xss", "asvs", "owasp2", "OWASP"} {
		body := captureRunBody(t, agent, json.RawMessage(`{}`))
		if v, present := body["accepts_mapping"]; present {
			t.Errorf("%s /run body carries accepts_mapping=%s; only the owasp request may", agent, v)
		}
	}
}

// Any user-supplied accepts_mapping is stripped from the config of EVERY
// agent, so no agent — this release's or an older one that still reads the
// config key — can be told the capability by a user.
func TestAgentProxy_StripsUserAcceptsMappingFromEveryConfig(t *testing.T) {
	for _, agent := range []string{"owasp", "cwe", "chaos"} {
		for _, in := range []string{
			`{"accepts_mapping":1}`,
			`{"accepts_mapping":2,"edition":"2021"}`,
			`{"accepts_mapping":0,"categories":["A07"]}`,
			`{"accepts_mapping":true,"validate":{"llm":true}}`,
			// A JSON-escaped key decodes to accepts_mapping on the agent side,
			// so it must be stripped too; so must a duplicate.
			`{"accepts\u005fmapping":1,"edition":"2021"}`,
			`{"accepts_mapping":1,"accepts_mapping":1}`,
		} {
			body := captureRunBody(t, agent, json.RawMessage(in))
			var cfg map[string]json.RawMessage
			if err := json.Unmarshal(body["config"], &cfg); err != nil {
				t.Fatalf("%s config %q: decode: %v", agent, in, err)
			}
			if v, present := cfg["accepts_mapping"]; present {
				t.Errorf("%s config %q: accepts_mapping=%s survived", agent, in, v)
			}
			var want map[string]json.RawMessage
			_ = json.Unmarshal([]byte(in), &want)
			delete(want, "accepts_mapping")
			if len(cfg) != len(want) {
				t.Errorf("%s config %q: got %s, want the other keys kept", agent, in, body["config"])
			}
			for k, v := range want {
				if !bytes.Equal(cfg[k], v) {
					t.Errorf("%s config %q: key %s = %s, want %s", agent, in, k, cfg[k], v)
				}
			}
		}
	}
}

// A config without the key is forwarded byte for byte; a non-object config
// (pre-0081 per-agent block) is forwarded unchanged rather than dropped.
func TestAgentProxy_ConfigWithoutAcceptsMappingIsUntouched(t *testing.T) {
	for _, in := range []string{`{"b":1,"a":[2,3]}`, `[1,2]`, `"x"`, `{}`} {
		body := captureRunBody(t, "cwe", json.RawMessage(in))
		if string(body["config"]) != in {
			t.Errorf("config %s forwarded as %s, want it verbatim", in, body["config"])
		}
	}
}

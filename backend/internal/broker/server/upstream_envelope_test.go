package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/broker/provider"
)

// The envelope gains an `upstream` block for the allowlisted class only.
//
// Existing consumers must not notice: the key is ABSENT (not null, not empty)
// when there is nothing to say, so a client that does not know the field sees
// byte-identical output for every error it already handles.

func decode(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v — %s", err, rr.Body.String())
	}
	e, _ := body["error"].(map[string]any)
	if e == nil {
		t.Fatalf("no error object: %s", rr.Body.String())
	}
	return e
}

func TestModelNotFoundEnvelopeCarriesUpstream(t *testing.T) {
	err := &provider.UpstreamError{
		Err: provider.ErrModelNotFound, Provider: "gemini", Status: 404,
		Message: "models/gemini-pro is not found for API version v1beta. Call ModelService.ListModels",
	}
	rr := httptest.NewRecorder()
	writeErr(rr, mapProviderErrWithUpstream(err))

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (unchanged)", rr.Code)
	}
	e := decode(t, rr)
	if e["code"] != "model_not_found" {
		t.Errorf("code = %v (must be unchanged)", e["code"])
	}
	if e["message"] != "model not found or not routable" {
		t.Errorf("the STATIC message must be unchanged: %v", e["message"])
	}
	up, _ := e["upstream"].(map[string]any)
	if up == nil {
		t.Fatal("model_not_found must carry an `upstream` block")
	}
	if up["provider"] != "gemini" {
		t.Errorf("provider = %v", up["provider"])
	}
	if int(up["status"].(float64)) != 404 {
		t.Errorf("status = %v", up["status"])
	}
	if !strings.Contains(up["message"].(string), "gemini-pro") {
		t.Errorf("the provider's own words must reach the caller: %v", up["message"])
	}
}

// THE COMPATIBILITY GUARANTEE.
func TestOtherErrorsHaveNoUpstreamKeyAtAll(t *testing.T) {
	for _, e := range []*apiError{
		errProviderBadRequest, errProviderAuth, errRateLimited,
		errProviderUnavailable, errBudgetExceeded, errUnauthorized,
	} {
		rr := httptest.NewRecorder()
		writeErr(rr, e)
		obj := decode(t, rr)
		if _, present := obj["upstream"]; present {
			t.Errorf("%s must not emit an `upstream` key at all, got %v", e.code, obj["upstream"])
		}
	}
}

// A bad-request UpstreamError carries no message (the provider layer refuses),
// so the server must not invent an empty block for it either.
func TestBadRequestUpstreamProducesNoBlock(t *testing.T) {
	err := &provider.UpstreamError{
		Err: provider.ErrProviderBadRequest, Provider: "gemini", Status: 400, Message: "",
	}
	rr := httptest.NewRecorder()
	writeErr(rr, mapProviderErrWithUpstream(err))
	if _, present := decode(t, rr)["upstream"]; present {
		t.Error("an empty upstream message must produce no block")
	}
}

func TestPlainSentinelStillMaps(t *testing.T) {
	got := mapProviderErrWithUpstream(errors.New("wrapped: " + provider.ErrModelNotFound.Error()))
	if got == nil {
		t.Fatal("must always return an apiError")
	}
	rr := httptest.NewRecorder()
	writeErr(rr, mapProviderErrWithUpstream(provider.ErrModelNotFound))
	if decode(t, rr)["code"] != "model_not_found" {
		t.Error("a bare sentinel must classify as before")
	}
}

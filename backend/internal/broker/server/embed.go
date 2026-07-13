package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
)

// HandleEmbed serves POST /internal/v1/llm/embed (§5): the same auth →
// egress-check → call pipeline as completions, returning embeddings + usage.
func (s *Server) HandleEmbed(w http.ResponseWriter, r *http.Request) {
	claims, apiErr := s.guardRequest(r)
	if apiErr != nil {
		writeErr(w, apiErr)
		return
	}
	var req embedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, errInvalidRequest)
		return
	}
	// N8: identity is authoritative from the VERIFIED token, never the client
	// body — mirrors runComplete so /embed carries the same tenant isolation.
	req.RunID = claims.Subject
	req.TenantID = claims.TenantID
	resp, apiErr := s.runEmbed(r.Context(), &req)
	if apiErr != nil {
		writeErr(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// runEmbed runs the egress-safe embeddings call under the resilience stack.
func (s *Server) runEmbed(ctx context.Context, req *embedRequest) (*provider.EmbeddingResponse, *apiError) {
	target, apiErr := s.egressCheck(egress.Candidate{Model: req.Model})
	if apiErr != nil {
		return nil, apiErr
	}
	adapter, creds, apiErr := s.adapterFor(target)
	if apiErr != nil {
		return nil, apiErr
	}
	resp, apiErr := s.callEmbed(ctx, adapter, creds, req)
	if apiErr != nil {
		return nil, apiErr
	}
	resp.RequestID = req.RequestID
	return resp, nil
}

// callEmbed runs the embeddings adapter under the resilience stack (§9).
func (s *Server) callEmbed(ctx context.Context, adapter provider.Adapter, creds provider.Credentials, req *embedRequest) (*provider.EmbeddingResponse, *apiError) {
	var resp *provider.EmbeddingResponse
	err := s.guard(ctx, creds.Provider, creds.Provider+":"+req.Model, func(c context.Context) error {
		r, e := adapter.Embed(c, creds, provider.EmbeddingRequest{
			RunID:     req.RunID,
			TenantID:  req.TenantID,
			Model:     req.Model,
			Inputs:    req.Inputs,
			RequestID: req.RequestID,
		})
		resp = r
		return e
	})
	if err != nil {
		return nil, mapProviderErr(err)
	}
	if resp == nil {
		return nil, errProviderUnavailable
	}
	return resp, nil
}

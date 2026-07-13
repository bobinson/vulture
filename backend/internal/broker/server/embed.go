package server

import (
	"context"
	"net/http"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/token"
)

// HandleEmbed serves POST /v1/embeddings (§5). It runs the SAME auth → scope →
// egress → reserve → call → reconcile pipeline as chat completions (§26/H5 —
// there is no unmetered path), returning an OpenAI-shaped embeddings response.
func (s *Server) HandleEmbed(w http.ResponseWriter, r *http.Request) {
	claims, apiErr := s.guardRequest(r)
	if apiErr != nil {
		writeErr(w, apiErr)
		return
	}
	req, apiErr := decodeEmbedRequest(w, r)
	if apiErr != nil {
		writeErr(w, apiErr)
		return
	}
	resp, apiErr := s.runEmbed(r.Context(), claims, req)
	if apiErr != nil {
		writeErr(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, renderEmbeddings(resp))
}

// runEmbed enforces scope, gates+pins egress, reserves budget, runs the
// embeddings call under the resilience stack, then reconciles actual usage.
func (s *Server) runEmbed(ctx context.Context, claims *token.Claims, req *embedRequest) (*provider.EmbeddingResponse, *apiError) {
	// N8: identity is authoritative from the VERIFIED token, never the wire.
	req.RunID = claims.Subject
	req.TenantID = claims.TenantID

	// §26/H5: embeddings are scoped + budgeted exactly like chat. The scope
	// entry for an embeddings run is "embed:<model>".
	if apiErr := checkScope(claims, "embed", req.Model); apiErr != nil {
		return nil, apiErr
	}
	target, apiErr := s.egressCheck(egress.Candidate{Model: req.Model})
	if apiErr != nil {
		return nil, apiErr
	}
	if apiErr := s.reserveEmbed(ctx, req); apiErr != nil {
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
	s.reconcileEmbed(ctx, req, resp)
	resp.RequestID = req.RequestID
	return resp, nil
}

// reserveEmbed CAS-reserves budget for one embeddings call (§8).
func (s *Server) reserveEmbed(ctx context.Context, req *embedRequest) *apiError {
	_, err := s.deps.Budget.Reserve(ctx, budget.ReserveRequest{
		RunID:         req.RunID,
		RequestID:     req.RequestID,
		TenantID:      req.TenantID,
		EstimatedUSD:  provider.EstimateUSD(req.Model, 0),
		ModelSnapshot: req.Model,
		LeaseTTL:      reserveTTL,
	})
	if err != nil {
		return mapBudgetErr(err)
	}
	return nil
}

// reconcileEmbed charges the actual embeddings usage and releases the lease
// (§8/M1). Reconcile failure is logged, never surfaced (the call succeeded).
func (s *Server) reconcileEmbed(ctx context.Context, req *embedRequest, resp *provider.EmbeddingResponse) {
	entry := budget.LedgerEntry{
		RunID:        req.RunID,
		RequestID:    req.RequestID,
		TenantID:     req.TenantID,
		Model:        resp.Model,
		Provider:     resp.Provider,
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		CostUSD:      resp.Usage.CostUSD,
		Estimated:    resp.Usage.Estimated,
	}
	if err := s.deps.Budget.Reconcile(ctx, entry); err != nil {
		s.logReconcileFailure(req.RunID, req.RequestID, err)
	}
	s.auditLog(ctx, entry, false)
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

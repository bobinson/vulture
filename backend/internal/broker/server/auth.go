package server

import (
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/broker/token"
)

const bearerPrefix = "Bearer "

// guardRequest enforces POST + authenticates, the shared front half of both
// §5 endpoints. It returns the verified claims or a typed error (DRY).
func (s *Server) guardRequest(r *http.Request) (*token.Claims, *apiError) {
	if r.Method != http.MethodPost {
		return nil, errMethodNotAllowed
	}
	return s.authenticate(r)
}

// authenticate verifies the per-run token then applies the kid denylist and
// per-run jti revocation kill switches (§6/M3), failing CLOSED on an
// unresolvable revocation state (§12). Returns the claims or a typed error.
func (s *Server) authenticate(r *http.Request) (*token.Claims, *apiError) {
	raw, apiErr := bearerToken(r)
	if apiErr != nil {
		return nil, apiErr
	}
	claims, err := s.deps.Verifier.Verify(raw)
	if err != nil {
		return nil, mapTokenErr(err)
	}
	if apiErr := s.checkKillSwitches(claims); apiErr != nil {
		return nil, apiErr
	}
	return claims, nil
}

// checkKillSwitches applies the kid denylist (§6/H3) then the per-run jti
// revocation (M3), both fail-CLOSED on an unresolvable store (§12).
func (s *Server) checkKillSwitches(claims *token.Claims) *apiError {
	if apiErr := s.checkDenylist(claims.KID); apiErr != nil {
		return apiErr
	}
	return s.checkRevocation(claims.JTI)
}

// bearerToken extracts the raw token from the Authorization header.
func bearerToken(r *http.Request) (string, *apiError) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, bearerPrefix) {
		return "", errUnauthorized
	}
	raw := strings.TrimSpace(strings.TrimPrefix(h, bearerPrefix))
	if raw == "" {
		return "", errUnauthorized
	}
	return raw, nil
}

// checkDenylist rejects a token whose signing-key id is revoked (§6/H3),
// failing CLOSED when the denylist store cannot answer.
func (s *Server) checkDenylist(kid string) *apiError {
	denied, err := s.deps.Denylist.IsDenied(kid)
	if err != nil {
		return errRevocationUnavail
	}
	if denied {
		return errUnauthorized
	}
	return nil
}

// checkRevocation rejects a revoked run jti at the turn boundary (M3),
// failing CLOSED when the revocation store cannot answer (§12).
func (s *Server) checkRevocation(jti string) *apiError {
	revoked, err := s.deps.Revocation.IsRevoked(jti)
	if err != nil {
		return errRevocationUnavail
	}
	if revoked {
		return errTokenRevoked
	}
	return nil
}

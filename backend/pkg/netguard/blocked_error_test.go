package netguard

import (
	"context"
	"errors"
	"net"
	"testing"
)

// TestValidateHostPublic_ReturnsBlockedError is the RED baseline for the
// actionable-alert feature (0065): an egress refusal must be a typed
// *BlockedError carrying the host + offending IP, so callers can detect a
// policy block (vs a transient failure) and build a decision-enabling message.
func TestValidateHostPublic_ReturnsBlockedError(t *testing.T) {
	ctx := context.Background()

	// Literal internal IP: Host and IP both name the address.
	err := ValidateHostPublic(ctx, "169.254.169.254", nil)
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("literal internal IP: want *BlockedError, got %T: %v", err, err)
	}
	if be.Host != "169.254.169.254" || be.IP == "" {
		t.Errorf("literal: fields not populated: %+v", be)
	}

	// Resolved-internal host: IP names the resolved offending address.
	err = ValidateHostPublic(ctx, "metadata.example", fixedResolver(net.ParseIP("10.0.0.5")))
	if !errors.As(err, &be) {
		t.Fatalf("resolved internal: want *BlockedError, got %T: %v", err, err)
	}
	if be.Host != "metadata.example" || be.IP != "10.0.0.5" {
		t.Errorf("resolved: fields wrong: %+v", be)
	}

	// A public host must NOT produce a BlockedError.
	if err := ValidateHostPublic(ctx, "example.com", fixedResolver(net.ParseIP("93.184.216.34"))); err != nil {
		t.Errorf("public host should pass, got %v", err)
	}
}

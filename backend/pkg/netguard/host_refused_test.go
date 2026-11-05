package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

// dnsFailure is a resolver error whose text names the resolver server, as a
// real *net.DNSError does.
var dnsFailure = &net.DNSError{Err: "no such host", Name: "nx.example", Server: "10.0.0.53:53", IsNotFound: true}

func dnsFailResolver(context.Context, string) ([]net.IP, error) { return nil, dnsFailure }

// Every refusal is classifiable as ErrHostRefused, whatever its cause, and the
// mark changes neither the text nor what errors.As finds.
func TestValidateHostPublic_MarksErrHostRefused(t *testing.T) {
	pub, internal := net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.5")
	cases := []struct {
		name, host string
		resolver   Resolver
		text       string
		blocked    bool
	}{
		{"literal internal IP", "127.0.0.1", fixedResolver(pub), "egress blocked: 127.0.0.1 is a non-public IP", true},
		{"resolves internal", "intranet.example", fixedResolver(internal), `egress blocked: host "intranet.example" resolves to non-public IP 10.0.0.5`, true},
		{"public then internal", "rebind.example", fixedResolver(pub, internal), `egress blocked: host "rebind.example" resolves to non-public IP 10.0.0.5`, true},
		{"resolver failure", "nx.example", dnsFailResolver, fmt.Sprintf("resolve %q: %v", "nx.example", dnsFailure), false},
		{"no addresses", "empty.example", fixedResolver(), `no IPs for "empty.example"`, false},
		{"empty host", "", fixedResolver(pub), "empty host", false},
	}
	for _, tc := range cases {
		err := ValidateHostPublic(context.Background(), tc.host, tc.resolver)
		wantHostRefused(t, tc.name, err, tc.text, tc.blocked)
	}
}

// The resolver's own error stays reachable for the log.
func TestValidateHostPublic_RefusalKeepsDNSCause(t *testing.T) {
	err := ValidateHostPublic(context.Background(), "nx.example", dnsFailResolver)
	var de *net.DNSError
	if !errors.As(err, &de) || de != dnsFailure {
		t.Errorf("errors.As(*net.DNSError) through the refusal: got %v from %v", de, err)
	}
}

func TestValidateHostPublic_PublicHostNotRefused(t *testing.T) {
	for _, host := range []string{"example.com", "8.8.8.8"} {
		if err := ValidateHostPublic(context.Background(), host, fixedResolver(net.ParseIP("8.8.8.8"))); err != nil {
			t.Errorf("ValidateHostPublic(%q) = %v, want nil", host, err)
		}
	}
}

func wantHostRefused(t *testing.T, name string, err error, text string, blocked bool) {
	t.Helper()
	if !errors.Is(err, ErrHostRefused) {
		t.Errorf("%s: errors.Is(%v, ErrHostRefused) = false, want true", name, err)
	}
	if got := fmt.Sprint(err); got != text {
		t.Errorf("%s: text = %q, want the unchanged %q", name, got, text)
	}
	var be *BlockedError
	if errors.As(err, &be) != blocked {
		t.Errorf("%s: errors.As(*BlockedError) = %v, want %v", name, !blocked, blocked)
	}
}

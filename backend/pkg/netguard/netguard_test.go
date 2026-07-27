package netguard

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestIsInternalIP is the truth table for the internal-IP classifier (0065).
// nil is fail-closed (internal); IPv4-mapped loopback and link-local (incl. the
// 169.254.169.254 cloud-metadata address) must classify internal; genuinely
// public addresses must classify public.
func TestIsInternalIP(t *testing.T) {
	cases := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{"nil fail-closed", nil, true},
		{"loopback v4", net.ParseIP("127.0.0.1"), true},
		{"ipv4-mapped loopback", net.ParseIP("::ffff:127.0.0.1"), true},
		{"loopback v6", net.ParseIP("::1"), true},
		{"private 10", net.ParseIP("10.0.0.1"), true},
		{"private 192.168", net.ParseIP("192.168.1.1"), true},
		{"private 172.16", net.ParseIP("172.16.0.1"), true},
		{"link-local metadata 169.254.169.254", net.ParseIP("169.254.169.254"), true},
		{"link-local v6", net.ParseIP("fe80::1"), true},
		{"unspecified v4", net.ParseIP("0.0.0.0"), true},
		{"unspecified v6", net.ParseIP("::"), true},
		{"multicast v4", net.ParseIP("224.0.0.1"), true},
		{"public v4 8.8.8.8", net.ParseIP("8.8.8.8"), false},
		{"public v4 1.1.1.1", net.ParseIP("1.1.1.1"), false},
		{"public v6", net.ParseIP("2606:4700:4700::1111"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsInternalIP(tc.ip); got != tc.want {
				t.Fatalf("IsInternalIP(%v) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// fixedResolver returns a canned set of IPs regardless of host.
func fixedResolver(ips ...net.IP) Resolver {
	return func(ctx context.Context, host string) ([]net.IP, error) {
		return ips, nil
	}
}

func TestValidateHostPublic(t *testing.T) {
	pub := net.ParseIP("8.8.8.8")
	internal := net.ParseIP("127.0.0.1")
	ctx := context.Background()

	t.Run("public host passes", func(t *testing.T) {
		if err := ValidateHostPublic(ctx, "example.com", fixedResolver(pub)); err != nil {
			t.Fatalf("expected public host to pass, got %v", err)
		}
	})

	t.Run("public then internal rejected (rebind)", func(t *testing.T) {
		if err := ValidateHostPublic(ctx, "rebind.example.com", fixedResolver(pub, internal)); err == nil {
			t.Fatal("expected [public,internal] resolution to be rejected")
		}
	})

	t.Run("literal internal IP rejected", func(t *testing.T) {
		if err := ValidateHostPublic(ctx, "127.0.0.1", fixedResolver(pub)); err == nil {
			t.Fatal("expected literal internal IP to be rejected")
		}
	})

	t.Run("literal public IP passes", func(t *testing.T) {
		if err := ValidateHostPublic(ctx, "8.8.8.8", fixedResolver(internal)); err != nil {
			t.Fatalf("expected literal public IP to pass, got %v", err)
		}
	})

	t.Run("empty host rejected", func(t *testing.T) {
		if err := ValidateHostPublic(ctx, "", fixedResolver(pub)); err == nil {
			t.Fatal("expected empty host to be rejected")
		}
	})
}

func TestValidatePublicURL(t *testing.T) {
	pub := net.ParseIP("8.8.8.8")
	internal := net.ParseIP("127.0.0.1")
	ctx := context.Background()

	t.Run("https public passes", func(t *testing.T) {
		if err := ValidatePublicURL(ctx, "https://example.com/hook", fixedResolver(pub)); err != nil {
			t.Fatalf("expected https public URL to pass, got %v", err)
		}
	})

	t.Run("non-http scheme rejected", func(t *testing.T) {
		if err := ValidatePublicURL(ctx, "file:///etc/passwd", fixedResolver(pub)); err == nil {
			t.Fatal("expected non-http scheme to be rejected")
		}
		if err := ValidatePublicURL(ctx, "gopher://example.com", fixedResolver(pub)); err == nil {
			t.Fatal("expected gopher scheme to be rejected")
		}
	})

	t.Run("http internal host rejected", func(t *testing.T) {
		if err := ValidatePublicURL(ctx, "http://metadata.internal", fixedResolver(internal)); err == nil {
			t.Fatal("expected internal-resolving URL to be rejected")
		}
	})
}

// TestValidateHostPublicDeadline is the H4 deadline test: a resolver that blocks
// forever must not stall the caller past ~resolveTimeout.
func TestValidateHostPublicDeadline(t *testing.T) {
	blockForever := func(ctx context.Context, host string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- ValidateHostPublic(context.Background(), "slow.example.com", blockForever)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error from a forever-blocking resolver")
		}
		if elapsed := time.Since(start); elapsed > resolveTimeout+2*time.Second {
			t.Fatalf("resolution took %v, expected to be bounded by ~resolveTimeout (%v)", elapsed, resolveTimeout)
		}
	case <-time.After(resolveTimeout + 3*time.Second):
		t.Fatalf("ValidateHostPublic did not return within resolveTimeout+slack; unbounded resolution (H4)")
	}
}

// TestGuardedDialContextRefusesLoopback is the R3 TOCTOU-close test: dialing a
// literal loopback target must error before any connection is attempted.
func TestGuardedDialContextRefusesLoopback(t *testing.T) {
	dial := GuardedDialContext(&net.Dialer{Timeout: time.Second})
	conn, err := dial(context.Background(), "tcp", "127.0.0.1:1")
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("expected GuardedDialContext to refuse dialing loopback 127.0.0.1:1")
	}
	if !strings.Contains(err.Error(), "non-public IP") {
		t.Fatalf("expected non-public-IP refusal error, got %v", err)
	}
}

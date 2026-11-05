package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/pkg/errkind"
	"github.com/vulture/backend/pkg/gitutil"
	"github.com/vulture/backend/pkg/netguard"
)

// The curated caller messages: a fixed text for a refusal whose cause names
// something of the server's (a resolved address, the resolver, git stderr).
const (
	curatedCloneHost = "clone: git host is not permitted or cannot be resolved"
	curatedCloneRun  = "clone: git clone failed: the repository is unreachable or the credentials were rejected"
	curatedHookHost  = "invalid webhook_url: host is not permitted or cannot be resolved"
)

// callerMsg is what CallerMessage answers.
type callerMsg struct {
	msg         string
	curated, ok bool
}

func callerMessageOf(err error) callerMsg {
	msg, curated, ok := CallerMessage(err)
	return callerMsg{msg: msg, curated: curated, ok: ok}
}

func resolveToIP(ip string) netguard.Resolver {
	return func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP(ip)}, nil }
}

func resolveFails(_ context.Context, host string) ([]net.IP, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, Server: "10.0.0.53:53", IsNotFound: true}
}

func TestInvalidInput_NilPassthrough(t *testing.T) {
	if err := InvalidInput(nil); err != nil {
		t.Errorf("InvalidInput(nil) = %v, want nil", err)
	}
}

// The mark changes no text and hides nothing from errors.Is, and an outer
// wrapper keeps it.
func TestInvalidInput_IsAndUnwrap(t *testing.T) {
	cause := errors.New("path is required for local source")
	err := InvalidInput(cause)
	if err.Error() != cause.Error() {
		t.Errorf("Error() = %q, want the unchanged %q", err.Error(), cause.Error())
	}
	wantErrsIs(t, err, ErrInvalidInput, cause)
	wantErrsIs(t, fmt.Errorf("ingest: %w", err), ErrInvalidInput, cause)
}

// Only the marked error's OWN text reaches the caller, never an outer
// wrapper's; a curated mark gives its literal; anything unmarked (even one
// that wraps the ErrInvalidInput sentinel by hand) gives nothing.
func TestCallerMessage_OwnTextOnly(t *testing.T) {
	own := InvalidInput(errors.New("path is required for local source"))
	curated := InvalidInputMsg(errors.New("egress blocked: host \"h\" resolves to non-public IP 10.0.0.5"), curatedCloneHost)
	cases := []struct {
		name string
		err  error
		want callerMsg
	}{
		{"nil", nil, callerMsg{}},
		{"unmarked", errors.New("create source: no such table: sources"), callerMsg{}},
		{"sentinel wrapped by hand", fmt.Errorf("insert: %w: %w", ErrInvalidInput, errors.New("no such table: sources")), callerMsg{}},
		{"own text", own, callerMsg{"path is required for local source", false, true}},
		{"own text under a wrapper", fmt.Errorf("ingest %s: %w", "/srv/x", own), callerMsg{"path is required for local source", false, true}},
		{"own text of a chain", InvalidInput(fmt.Errorf("invalid run_id: %w", errors.New("bad"))), callerMsg{"invalid run_id: bad", false, true}},
		{"curated", curated, callerMsg{curatedCloneHost, true, true}},
		{"curated under a wrapper", fmt.Errorf("ingest: %w", curated), callerMsg{curatedCloneHost, true, true}},
	}
	for _, tc := range cases {
		if got := callerMessageOf(tc.err); got != tc.want {
			t.Errorf("%s: CallerMessage = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// A curated mark answers the caller with its literal and keeps the full cause
// (text, errors.Is, errors.As) for the log.
func TestInvalidInputMsg_CuratedAndCauseKept(t *testing.T) {
	cause := &netguard.BlockedError{Host: "localhost", IP: "127.0.0.1", Reason: "non-public IP"}
	err := InvalidInputMsg(cause, curatedCloneHost)
	if err.Error() != cause.Error() {
		t.Errorf("Error() = %q, want the cause's text %q for the log", err.Error(), cause.Error())
	}
	wantErrsIs(t, err, ErrInvalidInput, cause)
	wantBlocked(t, err)
	if got := callerMessageOf(err); got != (callerMsg{curatedCloneHost, true, true}) {
		t.Errorf("CallerMessage = %+v, want the curated literal", got)
	}
}

// classifyCloneErr: a URL-shape refusal keeps its own text; a host refusal
// and a failed git run get a curated literal; anything else is unmarked, so
// the handler answers a generic 500. The cause is always kept for the log.
func TestClassifyCloneErr_AllowList(t *testing.T) {
	ctx := context.Background()
	shape := gitutil.ValidateCloneURL(ctx, "file:///etc/passwd", nil, gitutil.CloneURLPolicy{Resolver: dummyResolver})
	internal := gitutil.ValidateCloneURL(ctx, "https://internal.example/r.git", nil, gitutil.CloneURLPolicy{Resolver: resolveToIP("10.0.0.5")})
	unresolvable := gitutil.ValidateCloneURL(ctx, "https://nx.example/r.git", nil, gitutil.CloneURLPolicy{Resolver: resolveFails})
	gitRun := errkind.Mark(gitutil.ErrCloneFailed, fmt.Errorf("git clone failed: exit status 128: Cloning into '%s'...\nfatal: repository not found",
		filepath.Join(os.TempDir(), "vulture-sources", "x")))
	askpass := fmt.Errorf("write askpass: %w", errors.New("tmp dir: permission denied"))
	cases := []struct {
		name string
		in   error
		want callerMsg
	}{
		{"url shape", shape, callerMsg{"clone: " + fmt.Sprint(shape), false, true}},
		{"internal host", internal, callerMsg{curatedCloneHost, true, true}},
		{"unresolvable host", unresolvable, callerMsg{curatedCloneHost, true, true}},
		{"git run failed", gitRun, callerMsg{curatedCloneRun, true, true}},
		{"anything else", askpass, callerMsg{}},
	}
	for _, tc := range cases {
		wantClassified(t, tc.name, tc.in, classifyCloneErr(tc.in), tc.want)
	}
	wantUnmarkedClone(t, askpass, classifyCloneErr(askpass))
}

// classifyWebhookErr: a host refusal gets the curated literal, the same for an
// internal host and an unresolvable one; a parse or scheme error keeps its own
// text under the invalid webhook_url prefix.
func TestClassifyWebhookErr_Table(t *testing.T) {
	ctx := context.Background()
	scheme := validateWebhookURL(ctx, "ftp://example.invalid/hook", dummyResolver, nil)
	parse := validateWebhookURL(ctx, "http://[::1", dummyResolver, nil)
	cases := []struct {
		name string
		in   error
		want callerMsg
	}{
		{"scheme", scheme, callerMsg{"invalid webhook_url: " + fmt.Sprint(scheme), false, true}},
		{"parse", parse, callerMsg{"invalid webhook_url: " + fmt.Sprint(parse), false, true}},
		{"internal host", validateWebhookURL(ctx, "http://localhost:9/h", resolveToIP("127.0.0.1"), nil), callerMsg{curatedHookHost, true, true}},
		{"internal literal", validateWebhookURL(ctx, "http://10.0.0.5/h", dummyResolver, nil), callerMsg{curatedHookHost, true, true}},
		{"unresolvable host", validateWebhookURL(ctx, "https://nx.example/h", resolveFails, nil), callerMsg{curatedHookHost, true, true}},
	}
	for _, tc := range cases {
		wantClassified(t, tc.name, tc.in, classifyWebhookErr(tc.in), tc.want)
	}
}

// wantClassified checks the caller's view of a classified error and that the
// cause stays whole for the log.
func wantClassified(t *testing.T, name string, in, out error, want callerMsg) {
	t.Helper()
	wantCauseKept(t, name, in, out)
	if got := callerMessageOf(out); got != want {
		t.Errorf("%s: CallerMessage = %+v, want %+v", name, got, want)
	}
}

func wantCauseKept(t *testing.T, name string, in, out error) {
	t.Helper()
	if in == nil || !errors.Is(out, in) || !strings.Contains(fmt.Sprint(out), in.Error()) {
		t.Errorf("%s: %v must keep the cause %v (errors.Is and its text) for the log", name, out, in)
	}
}

// An unclassified clone error is the cause under the clone: prefix, with no
// caller mark, so the handler answers a generic 500.
func wantUnmarkedClone(t *testing.T, in, out error) {
	t.Helper()
	if errors.Is(out, ErrInvalidInput) || fmt.Sprint(out) != "clone: "+in.Error() {
		t.Errorf("unclassified clone error = %q (invalid input: %v), want the unmarked %q", out, errors.Is(out, ErrInvalidInput), "clone: "+in.Error())
	}
}

func wantErrsIs(t *testing.T, err error, targets ...error) {
	t.Helper()
	for _, target := range targets {
		if !errors.Is(err, target) {
			t.Errorf("errors.Is(%q, %q) = false, want true", err, target)
		}
	}
}

func wantBlocked(t *testing.T, err error) {
	t.Helper()
	var be *netguard.BlockedError
	if !errors.As(err, &be) {
		t.Errorf("errors.As(*netguard.BlockedError) through %q = false, want true", err)
	}
}

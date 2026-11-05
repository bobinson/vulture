package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
	"github.com/vulture/backend/internal/textutil"
)

// Local ingest when the source root itself is unavailable (feature 0102), and
// the size of a refusal's log line.

const sourceRootUnavailableText = "source root unavailable"

// captureLog sends the standard logger (and so slog's default handler) to a
// buffer until the returned func is called. That func restores the previous
// writer before it reads, so a goroutine of another test that logs meanwhile
// cannot race the read.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	restore := func() { log.SetOutput(prev) }
	t.Cleanup(restore)
	return func() string { restore(); return buf.String() }
}

// ingestLocal runs a local ingest of path under the given root and mode.
func ingestLocal(root string, localMode bool, path string) error {
	svc := NewSourceService(nil, root, localMode)
	_, err := svc.Ingest(context.Background(), &model.SourceRequest{Type: string(model.SourceTypeLocal), Path: path})
	return err
}

// unavailableRoots returns a missing root and, unless the test runs as root
// (which ignores the mode), a root the server can only traverse (mode 0100):
// confinement opens the root, so it cannot confine anything.
func unavailableRoots(t *testing.T) map[string]string {
	t.Helper()
	base := t.TempDir()
	roots := map[string]string{"missing": filepath.Join(base, "unmounted")}
	if os.Geteuid() == 0 {
		return roots
	}
	searchOnly := filepath.Join(base, "search-only")
	if err := os.MkdirAll(filepath.Join(searchOnly, "project"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(searchOnly, 0o100); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(searchOnly, 0o755) })
	roots["search-only (0100)"] = searchOnly
	return roots
}

// TestIngestLocal_RootUnavailable_IsTheServersFault: under a root that is
// missing or that the server can only traverse, ingest of any path is
// refused with the root-fault text, not the uniform refusal a caller's own
// path gets, naming neither the root nor the path; the cause is logged at
// ERROR for the operator.
func TestIngestLocal_RootUnavailable_IsTheServersFault(t *testing.T) {
	outside := t.TempDir()
	for name, root := range unavailableRoots(t) {
		for _, p := range []string{filepath.Join(root, "project"), outside} {
			wantIngestRootFault(t, name, root, p)
		}
	}
}

// wantIngestRootFault fails unless ingest of p under the unavailable root is
// refused with exactly the root-fault text and logs the cause at ERROR.
func wantIngestRootFault(t *testing.T, name, root, p string) {
	t.Helper()
	logged := captureLog(t)
	err := ingestLocal(root, false, p)
	if !isRootFaultRefusal(err) {
		t.Errorf("%s: ingest %q = %v; want exactly %q", name, p, err, sourceRootUnavailableText)
	}
	if out := logged(); !loggedRootFault(out, root) {
		t.Errorf("%s: ingest %q logged %q; want an ERROR source_root_unavailable line with the cause", name, p, out)
	}
}

// isRootFaultRefusal reports whether err is ErrRootUnavailable with exactly
// the root-fault text.
func isRootFaultRefusal(err error) bool {
	return errors.Is(err, pathutil.ErrRootUnavailable) && err.Error() == sourceRootUnavailableText
}

// loggedRootFault reports whether out holds an ERROR source_root_unavailable
// line and the cause, which names root.
func loggedRootFault(out, root string) bool {
	return strings.Contains(out, "ERROR source_root_unavailable") && strings.Contains(out, root)
}

// TestIngestLocal_RootUnavailable_NotTheCallers: the root fault is left
// unmarked, so no handler can answer it as a 400 the caller could fix.
func TestIngestLocal_RootUnavailable_NotTheCallers(t *testing.T) {
	captureLog(t)
	for name, root := range unavailableRoots(t) {
		err := ingestLocal(root, false, filepath.Join(root, "project"))
		if msg, _, ok := CallerMessage(err); ok || err == nil {
			t.Errorf("%s: ingest = %v, caller message %q; want an unmarked server fault", name, err, msg)
		}
	}
}

// refusalLogBound is the most a local_path_refused line may take: the path
// field is cut at 256 runes, the err field at textutil.MaxLogBytes, and the
// rest is the time stamp and the attribute names.
const refusalLogBound = 256*4 + textutil.MaxLogBytes + 512

// TestCheckLocalPath_RefusalLogBounded: a refused path is logged with both
// fields bounded, though the cause repeats the path (os.Stat's error in local
// mode, os.Root's in-root name when confined); err_bytes keeps the cause's
// full length, and the cut cause still starts with the operation.
func TestCheckLocalPath_RefusalLogBounded(t *testing.T) {
	root := t.TempDir()
	for _, c := range []struct {
		name, root, path string
	}{
		{"local mode, 1 MiB path", "", "/" + strings.Repeat("a", 1<<20-100)},
		{"confined, 4 KB in-root path", root, root + "/" + strings.Repeat("abcdefgh/", (pathutil.MaxConfinedPathBytes-len(root))/9-1)},
	} {
		t.Run(c.name, func(t *testing.T) { wantRefusalLogBounded(t, c.root, c.path) })
	}
}

func wantRefusalLogBounded(t *testing.T, root, path string) {
	t.Helper()
	cause := pathutil.ResolveDirWithinRoot(root, path)
	if cause == nil {
		t.Fatalf("ResolveDirWithinRoot(%.80q) = nil; the fixture must be refused", path)
	}
	logged := captureLog(t)
	if err := ingestLocal(root, root == "", path); err == nil {
		t.Fatalf("ingest of %.80q = nil; want a refusal", path)
	}
	wantBoundedRefusalLine(t, refusalLine(logged()), len(path), cause)
}

// wantBoundedRefusalLine fails unless the local_path_refused line out, for a
// pathLen-byte path refused with cause, fits refusalLogBound, gives the
// cause's full length as err_bytes, and starts its cut cause with the
// operation.
func wantBoundedRefusalLine(t *testing.T, out string, pathLen int, cause error) {
	t.Helper()
	if len(out) > refusalLogBound {
		t.Errorf("local_path_refused line is %d bytes for a %d-byte path; want at most %d", len(out), pathLen, refusalLogBound)
	}
	if want := fmt.Sprintf("err_bytes=%d", len(cause.Error())); !strings.Contains(out, want) {
		t.Errorf("local_path_refused line %.300q; want %s", out, want)
	}
	if op := strings.Fields(cause.Error())[0]; !strings.Contains(out, "err=\""+op) {
		t.Errorf("local_path_refused line %.300q; want the cut cause to start with %q", out, op)
	}
}

// refusalLine is the local_path_refused line of a captured log, or "" (a
// goroutine of another test may have logged lines of its own).
func refusalLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "WARN local_path_refused ") {
			return line
		}
	}
	return ""
}

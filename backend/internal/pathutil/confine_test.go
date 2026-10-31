package pathutil

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Confinement of a caller-supplied path to a source root (feature 0102,
// CWE-22/59). A confined path must be absolute, at most MaxConfinedPathBytes
// and free of "..", and spelled under the root; it is then resolved with an
// O(log n) ancestor search, and a link that does not resolve is refused
// rather than treated as absent. Every refusal is ErrNotPermitted.

// confineTree is a fixture: a dedicated root, a directory outside it, and a
// symlinked spelling of the root.
type confineTree struct {
	root, outside, rootLink string
}

func newConfineTree(t *testing.T) confineTree {
	t.Helper()
	base := t.TempDir()
	tr := confineTree{
		root:     confineMkdir(t, filepath.Join(base, "root")),
		outside:  confineMkdir(t, filepath.Join(base, "outside")),
		rootLink: filepath.Join(base, "root-link"),
	}
	confineSymlink(t, tr.root, tr.rootLink)
	return tr
}

// confineMkdir creates each directory with its parents and returns the last.
func confineMkdir(t *testing.T, dirs ...string) string {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	return dirs[len(dirs)-1]
}

// confineFile creates a small regular file and returns its path.
func confineFile(t *testing.T, path string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// confineSymlink creates link -> target and returns link.
func confineSymlink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}
	return link
}

// confineLockedChild creates parent/locked/inner, sets parent/locked to mode
// 000 (restored at cleanup) and returns parent/locked/inner. It returns ""
// when the test runs as root, which ignores the mode.
func confineLockedChild(t *testing.T, parent string) string {
	t.Helper()
	if os.Geteuid() == 0 {
		return ""
	}
	locked := filepath.Join(parent, "locked")
	inner := confineMkdir(t, filepath.Join(locked, "inner"))
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatalf("chmod %s: %v", locked, err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	return inner
}

// confinePathOfLen returns prefix extended with "/d" components to exactly n
// bytes (n > len(prefix)).
func confinePathOfLen(prefix string, n int) string {
	p := prefix + strings.Repeat("/d", (n-len(prefix))/2)
	return p + strings.Repeat("d", n-len(p))
}

// wantErrIs fails unless errors.Is(err, want); a nil want requires a nil err.
func wantErrIs(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s = %v; want %v", what, err, want)
	}
}

// wantNotPermitted fails unless err is a confinement refusal.
func wantNotPermitted(t *testing.T, what string, err error) {
	t.Helper()
	wantErrIs(t, what, err, ErrNotPermitted)
}

// wantRefusedByBoth fails unless EnsureWithinRoot and ResolveDirWithinRoot
// both refuse p under root.
func wantRefusedByBoth(t *testing.T, root, p string) {
	t.Helper()
	_, err := EnsureWithinRoot(root, p)
	wantNotPermitted(t, "EnsureWithinRoot("+root+", "+p+")", err)
	wantNotPermitted(t, "ResolveDirWithinRoot("+root+", "+p+")", ResolveDirWithinRoot(root, p))
}

func TestConfine_ShapeRulesOnlyWithRoot(t *testing.T) {
	tr := newConfineTree(t)
	confineMkdir(t, filepath.Join(tr.root, "a"), filepath.Join(tr.root, "b"))
	for name, p := range map[string]string{
		"relative":     "rel/dir",
		"dot-dot":      tr.root + "/a/../b",
		"over the cap": confinePathOfLen(tr.root, MaxConfinedPathBytes+1),
	} {
		t.Run(name, func(t *testing.T) { wantShapeRefusedOnlyWithRoot(t, tr.root, p) })
	}
	if _, err := EnsureWithinRoot(tr.root, confinePathOfLen(tr.root, MaxConfinedPathBytes)); err != nil {
		t.Errorf("EnsureWithinRoot of a path of exactly MaxConfinedPathBytes under the root = %v; want nil", err)
	}
}

// wantShapeRefusedOnlyWithRoot: under a root the shape is refused; with no
// root (local mode) the same path is not judged by its shape.
func wantShapeRefusedOnlyWithRoot(t *testing.T, root, p string) {
	t.Helper()
	wantRefusedByBoth(t, root, p)
	if got, err := EnsureWithinRoot("", p); got != p || err != nil {
		t.Errorf("EnsureWithinRoot(\"\", %.80q) = (%.80q, %v); want the path unchanged", p, got, err)
	}
	if err := ResolveDirWithinRoot("", p); errors.Is(err, ErrNotPermitted) {
		t.Errorf("ResolveDirWithinRoot(\"\", %.80q) = %v; shape rules apply only with a root", p, err)
	}
}

// TestConfine_LexicalPreCheckRefusesOutsideSpelling: a path spelled outside
// the root is refused even when it resolves INTO the root. Both spellings of
// a symlinked root, and the absolute spelling of a relative root, are inside.
func TestConfine_LexicalPreCheckRefusesOutsideSpelling(t *testing.T) {
	tr := newConfineTree(t)
	sub := confineMkdir(t, filepath.Join(tr.root, "project", "sub"))
	into := confineSymlink(t, filepath.Dir(sub), filepath.Join(tr.outside, "into"))
	for _, p := range []string{into, filepath.Join(into, "sub"), filepath.Join(into, "missing")} {
		wantRefusedByBoth(t, tr.root, p)
	}

	t.Chdir(filepath.Dir(tr.root))
	for _, c := range []struct{ root, p string }{
		{tr.rootLink, filepath.Join(tr.rootLink, "project")},
		{tr.rootLink, filepath.Join(tr.root, "project")},
		{filepath.Base(tr.root), filepath.Join(tr.root, "project")},
	} {
		wantConfinedDir(t, c.root, c.p)
	}
}

// wantConfinedDir fails unless both entry points accept the directory p.
func wantConfinedDir(t *testing.T, root, p string) {
	t.Helper()
	if _, err := EnsureWithinRoot(root, p); err != nil {
		t.Errorf("EnsureWithinRoot(%q, %q) = %v; want nil", root, p, err)
	}
	if err := ResolveDirWithinRoot(root, p); err != nil {
		t.Errorf("ResolveDirWithinRoot(%q, %q) = %v; want nil", root, p, err)
	}
}

// TestResolveExistingAncestor_DanglingLinkRefused: a link that does not
// resolve (dangling, or a loop) is an existing entry. It is refused, never
// treated as absent, so a planted link cannot report on its target.
func TestResolveExistingAncestor_DanglingLinkRefused(t *testing.T) {
	tr := newConfineTree(t)
	dangling := confineSymlink(t, filepath.Join(tr.root, "nowhere"), filepath.Join(tr.root, "dangling"))
	loop := confineSymlink(t, "loop", filepath.Join(tr.root, "loop"))
	for _, p := range []string{dangling, filepath.Join(dangling, "x"), loop, filepath.Join(loop, "x")} {
		_, err := resolveExistingAncestor(p)
		wantNotPermitted(t, "resolveExistingAncestor("+p+")", err)
		_, err = EnsureWithinRoot(tr.root, p)
		wantNotPermitted(t, "EnsureWithinRoot("+p+")", err)
	}
}

// linearAncestor is the reference for resolveExistingAncestor: scan every
// component for the deepest prefix Lstat finds, resolve that prefix, and
// re-append the rest. A prefix that does not resolve is refused.
func linearAncestor(abs string) (string, error) {
	parts := strings.Split(abs, "/")[1:]
	k := 0
	for k < len(parts) && lstatOK("/"+filepath.Join(parts[:k+1]...)) {
		k++
	}
	resolved, err := filepath.EvalSymlinks("/" + filepath.Join(parts[:k]...))
	if err != nil {
		return "", ErrNotPermitted
	}
	return filepath.Join(append([]string{resolved}, parts[k:]...)...), nil
}

func lstatOK(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// treeNames is the name pool for random trees and for the queries into them,
// so queries hit existing entries often.
var treeNames = []string{"a", "b", "c", "d"}

// treeMaker creates one entry at p and returns the tree's directories.
type treeMaker func(t *testing.T, rng *rand.Rand, p string, dirs []string) []string

var treeMakers = []treeMaker{
	func(t *testing.T, _ *rand.Rand, p string, dirs []string) []string {
		return append(dirs, confineMkdir(t, p))
	},
	func(t *testing.T, _ *rand.Rand, p string, dirs []string) []string {
		confineFile(t, p)
		return dirs
	},
	func(t *testing.T, rng *rand.Rand, p string, dirs []string) []string {
		confineSymlink(t, dirs[rng.IntN(len(dirs))], p)
		return dirs
	},
	func(t *testing.T, rng *rand.Rand, p string, dirs []string) []string {
		rel, _ := filepath.Rel(filepath.Dir(p), dirs[rng.IntN(len(dirs))])
		confineSymlink(t, rel, p)
		return dirs
	},
	func(t *testing.T, _ *rand.Rand, p string, dirs []string) []string {
		confineSymlink(t, filepath.Join(dirs[0], "nowhere"), p)
		return dirs
	},
	func(t *testing.T, _ *rand.Rand, p string, dirs []string) []string {
		confineSymlink(t, filepath.Base(p), p)
		return dirs
	},
}

// randomTree plants up to n entries (directories, files, absolute and
// relative links to directories, dangling links, self links) under root.
func randomTree(t *testing.T, rng *rand.Rand, root string, n int) {
	t.Helper()
	dirs := []string{root}
	for range n {
		p := filepath.Join(dirs[rng.IntN(len(dirs))], treeNames[rng.IntN(len(treeNames))])
		if !lstatOK(p) {
			dirs = treeMakers[rng.IntN(len(treeMakers))](t, rng, p, dirs)
		}
	}
}

// randomQuery is root followed by one to six pool names.
func randomQuery(rng *rand.Rand, root string) string {
	parts := []string{root}
	for range 1 + rng.IntN(6) {
		parts = append(parts, treeNames[rng.IntN(len(treeNames))])
	}
	return filepath.Join(parts...)
}

// TestResolveExistingAncestor_BinarySearchMatchesLinear: the ancestor search
// returns what a component-by-component scan returns, on random trees.
func TestResolveExistingAncestor_BinarySearchMatchesLinear(t *testing.T) {
	rng := rand.New(rand.NewPCG(102, 1))
	for range 20 {
		root := confineMkdir(t, filepath.Join(t.TempDir(), "root"))
		randomTree(t, rng, root, 30)
		for range 50 {
			wantAncestorAgrees(t, randomQuery(rng, root))
		}
	}
}

func wantAncestorAgrees(t *testing.T, q string) {
	t.Helper()
	got, gotErr := resolveExistingAncestor(q)
	want, wantErr := linearAncestor(q)
	if got != want || !errors.Is(gotErr, wantErr) {
		t.Errorf("resolveExistingAncestor(%q) = (%q, %v); linear scan gives (%q, %v)", q, got, gotErr, want, wantErr)
	}
}

// TestResolveDirWithinRoot_SwappedOutboundLinkRefused: the final stat goes
// through os.Root, so a directory swapped for an outbound link AFTER the
// ancestor walk fails the stat instead of describing the link's target.
func TestResolveDirWithinRoot_SwappedOutboundLinkRefused(t *testing.T) {
	for name, target := range map[string]func(confineTree) string{
		"absolute link to an outside dir":     func(tr confineTree) string { return tr.outside },
		"absolute link to an outside missing": func(tr confineTree) string { return filepath.Join(tr.outside, "missing") },
		"relative link to an outside dir":     func(confineTree) string { return filepath.Join("..", "outside") },
		"relative link to an outside missing": func(confineTree) string { return filepath.Join("..", "outside", "missing") },
	} {
		t.Run(name, func(t *testing.T) { wantSwapRefused(t, target) })
	}
}

// wantSwapRefused confines root/proj while it is a directory, swaps it for a
// link to target, and stats the path confinement accepted. The stat must fail
// without describing the target (never nil, never "does not exist"), and a
// fresh ResolveDirWithinRoot must refuse the link.
func wantSwapRefused(t *testing.T, target func(confineTree) string) {
	t.Helper()
	tr := newConfineTree(t)
	proj := confineMkdir(t, filepath.Join(tr.root, "proj"))
	resolved, err := EnsureWithinRoot(tr.root, proj)
	if err != nil {
		t.Fatalf("EnsureWithinRoot(%q) before the swap = %v; want nil", proj, err)
	}
	confineSwapForLink(t, proj, target(tr))
	if err := statInRoot(confineRealRoot(t, tr.root), resolved); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("statInRoot of %q after the swap = %v; want a refusal that does not describe the target", resolved, err)
	}
	wantNotPermitted(t, "ResolveDirWithinRoot after the swap", ResolveDirWithinRoot(tr.root, proj))
}

// confineSwapForLink replaces the directory dir with a link to target.
func confineSwapForLink(t *testing.T, dir, target string) {
	t.Helper()
	if err := os.Remove(dir); err != nil {
		t.Fatalf("remove %s: %v", dir, err)
	}
	confineSymlink(t, target, dir)
}

// confineRealRoot is root with every symlink resolved.
func confineRealRoot(t *testing.T, root string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve %s: %v", root, err)
	}
	return resolved
}

// TestResolveDirWithinRoot_AbsoluteInRootSymlinkAccepted: an absolute link
// inside the root to a directory inside it (current -> releases/v2) is
// accepted, also through a symlinked spelling of the root. os.Root alone
// refuses an absolute link, so the stat must use the resolved path.
func TestResolveDirWithinRoot_AbsoluteInRootSymlinkAccepted(t *testing.T) {
	tr := newConfineTree(t)
	release := filepath.Dir(confineMkdir(t, filepath.Join(tr.root, "releases", "v2", "sub")))
	current := confineSymlink(t, release, filepath.Join(tr.root, "current"))
	for _, c := range []struct{ root, p string }{
		{tr.root, current},
		{tr.root, filepath.Join(current, "sub")},
		{tr.rootLink, filepath.Join(tr.rootLink, "current")},
	} {
		if err := ResolveDirWithinRoot(c.root, c.p); err != nil {
			t.Errorf("ResolveDirWithinRoot(%q, %q) = %v; want nil", c.root, c.p, err)
		}
	}
}

// TestResolveDirWithinRoot_EmptyRootStats: with no root the path is stat'd
// as given: no confinement and no shape rules, and the stat's error class
// is kept so the caller can name it.
func TestResolveDirWithinRoot_EmptyRootStats(t *testing.T) {
	dir := t.TempDir()
	confineMkdir(t, filepath.Join(dir, "a"), filepath.Join(dir, "b"))
	file := confineFile(t, filepath.Join(dir, "f.txt"))
	for _, c := range []struct {
		p    string
		want error
	}{
		{dir, nil},
		{dir + "/a/../b", nil},
		{".", nil},
		{file, ErrNotDir},
		{filepath.Join(dir, "missing"), fs.ErrNotExist},
	} {
		wantErrIs(t, "ResolveDirWithinRoot(\"\", "+c.p+")", ResolveDirWithinRoot("", c.p), c.want)
	}
	if inner := confineLockedChild(t, dir); inner != "" {
		wantErrIs(t, "ResolveDirWithinRoot(\"\", "+inner+")", ResolveDirWithinRoot("", inner), fs.ErrPermission)
	}
}

// TestConfine_DotDotThroughSymlinkRefusedThoughWithinIsTrue: with
// R/repo/lnk -> <outside>/a, the kernel resolves R/repo/lnk/../secret to
// <outside>/secret while Within, being lexical, calls it inside. Confinement
// refuses the spelling, also through a symlinked root.
func TestConfine_DotDotThroughSymlinkRefusedThoughWithinIsTrue(t *testing.T) {
	tr := newConfineTree(t)
	confineMkdir(t, filepath.Join(tr.outside, "a"), filepath.Join(tr.outside, "secret"), filepath.Join(tr.root, "repo"))
	confineSymlink(t, filepath.Join(tr.outside, "a"), filepath.Join(tr.root, "repo", "lnk"))
	for _, root := range []string{tr.root, tr.rootLink} {
		// Concatenated: filepath.Join would clean the ".." away.
		p := root + "/repo/lnk/../secret"
		if !Within(root, p) {
			t.Errorf("Within(%q, %q) = false; want true (lexical)", root, p)
		}
		wantRefusedByBoth(t, root, p)
	}
}

// TestEnsureWithinRoot_UsesWithin: EnsureWithinRoot has no containment check
// of its own; Within is the package's one rule. Outside paths and a sibling
// that shares the root's prefix are still refused.
func TestEnsureWithinRoot_UsesWithin(t *testing.T) {
	tr := newConfineTree(t)
	sibling := confineMkdir(t, tr.root+"-backup")
	for _, p := range []string{tr.outside, sibling, filepath.Join(sibling, "a")} {
		_, err := EnsureWithinRoot(tr.root, p)
		wantNotPermitted(t, "EnsureWithinRoot("+p+")", err)
	}
	allowed := map[string]bool{"Within": true, "statInRoot": true}
	for _, fn := range relCallers(t) {
		if !allowed[fn] {
			t.Errorf("%s calls filepath.Rel; containment goes through Within, and only statInRoot needs a relative path", fn)
		}
	}
}

// relCallers lists the package's non-test functions that call filepath.Rel.
func relCallers(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list package files: %v", err)
	}
	var names []string
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			names = append(names, relCallersIn(t, f)...)
		}
	}
	return names
}

func relCallersIn(t *testing.T, file string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var names []string
	for _, d := range f.Decls {
		if name := relCallerName(d); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// relCallerName is the name of a function declaration that calls
// filepath.Rel, or "".
func relCallerName(d ast.Decl) string {
	fn, ok := d.(*ast.FuncDecl)
	if !ok || !callsRel(fn) {
		return ""
	}
	return fn.Name.Name
}

func callsRel(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && types.ExprString(call.Fun) == "filepath.Rel" {
			found = true
		}
		return !found
	})
	return found
}

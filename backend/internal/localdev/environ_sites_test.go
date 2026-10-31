package localdev

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Feature 0102: package localdev reads the process environment for a child
// in exactly two places. hostEnv is the one sanctioned reader for every
// filtered spawn (agents and the plugin docker CLI); (*Manager).start is the
// deliberate full inheritance for non-agent children. A third os.Environ call
// is a new unfiltered path, whatever lint comment it carries.
func TestHostEnv_SingleSanctionedReader(t *testing.T) {
	want := []string{"agentenv.go:hostEnv", "process.go:(*Manager).start"}
	if got := environCallSites(t); !slices.Equal(got, want) {
		t.Errorf("os.Environ() call sites in package localdev = %v, want %v", got, want)
	}
}

// environCallSites lists "<file>:<enclosing declaration>" once per
// os.Environ() call in the package's non-test files, sorted.
func environCallSites(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	var sites []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			ast.Inspect(decl, func(n ast.Node) bool {
				if isOSEnvironCall(n) {
					sites = append(sites, name+":"+declName(decl))
				}
				return true
			})
		}
	}
	sort.Strings(sites)
	return sites
}

func isOSEnvironCall(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "os" && sel.Sel.Name == "Environ"
}

// declName names a top-level declaration: a function, "(*T).method", or
// "<package scope>" for a var/const initialiser.
func declName(d ast.Decl) string {
	fn, ok := d.(*ast.FuncDecl)
	if !ok {
		return "<package scope>"
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(" + types.ExprString(fn.Recv.List[0].Type) + ")." + fn.Name.Name
}

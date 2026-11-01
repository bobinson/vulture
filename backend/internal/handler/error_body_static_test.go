package handler

// CWE-209 static guard (0102 item 1). An error response body may carry only
// text written for the caller, so every writeError / http.Error message in
// the packages that serve the API must be a string literal, whatever the
// expression would otherwise be (err.Error(), fmt.Sprintf("...%v", err), a
// variable holding either), unless the call is a reviewed exception below.
// A literal-only allow rule needs no data flow and no type checker, and an
// intermediate variable cannot evade it.
//
// Three more rules keep every 500 on one path: outside response.go no call
// writes a 500 directly (writeInternalError logs the cause and quotes the
// request id), and writeJSON's status is a 2xx.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// errorBodyDirs are the packages that write API responses, relative to this one.
var errorBodyDirs = []string{".", "../server"}

// errorBodyResponseFile is the one file that may write a 500 or a non-2xx
// writeJSON: it holds the helpers every other file goes through.
const errorBodyResponseFile = "response.go"

// errorBodySink locates the status and message arguments of a call.
type errorBodySink struct{ status, message int }

var errorBodySinks = map[string]errorBodySink{
	"writeError": {status: 1, message: 2}, // writeError(w, status, message)
	"http.Error": {status: 2, message: 1}, // http.Error(w, message, status)
	"writeJSON":  {status: 1, message: -1},
}

// errorBodyExceptions are the reviewed calls whose message is not a literal,
// keyed "file:function | status | message" exactly as the source spells
// them, so a NEW non-literal message in the same function, or the same
// message under another status, is still caught. An entry that matches no
// call fails TestErrorBodies_NoStaleExceptions, so the list cannot rot.
var errorBodyExceptions = map[string]string{
	"response.go:writeInvalidOrInternal | http.StatusBadRequest | msg":                                              "caller-input text or a curated literal (service.CallerMessage)",
	"audit_handler.go:Create | http.StatusBadRequest | err.Error()":                                                 "validateAuditTypes names the caller's own types",
	"audit_handler.go:CachedAudit | http.StatusBadRequest | err.Error()":                                            "validateAuditTypes names the caller's own types",
	"target_handler.go:aggregate | http.StatusBadRequest | err.Error()":                                             "parseComplianceFilter names the offending parameter",
	"audit_handler.go:Create | http.StatusServiceUnavailable | hr.Message":                                          "the LLM-health message; the CLI prints it and exits 75",
	"llm_health_handler.go:ServeHTTP | http.StatusBadGateway | fmt.Sprintf(\"could not reach any agent: %v\", err)": "diagnostic endpoint: why the agents are unreachable",
	"filesystem_handler.go:writeBrowseRefusal | code | msg":                                                         "a 4xx from resolve: the fixed ErrLocalSourcesDisabled text of LocalSources.Allow (403), or a literal message of validateBrowsePathWithRoot; its one 5xx, a root fault, goes through writeInternalError before this call",
	"auth_middleware.go:requireRoleWhere | http.StatusForbidden | msg":                                              "role-gate text comes from route wiring, never from input or an error",
}

// errorBodyCall is one call to a response writer, as the source spells it.
type errorBodyCall struct {
	file, fn, callee string
	status, message  string // types.ExprString; message is "" for writeJSON
	literal          bool   // the message is a string literal
	line             int
}

func (c errorBodyCall) key() string {
	return c.file + ":" + c.fn + " | " + c.status + " | " + c.message
}

func TestErrorBodies_MessagesAreLiteral(t *testing.T) {
	for _, c := range errorBodyNonLiteral(errorBodyCallsIn(t, errorBodyDirs)) {
		if _, ok := errorBodyExceptions[c.key()]; !ok {
			t.Errorf("%s (line %d): an error value must not reach a response body (CWE-209); use writeInternalError, writeInvalidOrInternal or a literal", c.key(), c.line)
		}
	}
}

func TestErrorBodies_NoStaleExceptions(t *testing.T) {
	used := map[string]bool{}
	for _, c := range errorBodyNonLiteral(errorBodyCallsIn(t, errorBodyDirs)) {
		used[c.key()] = true
	}
	for _, key := range staleErrorBodyKeys(used) {
		t.Errorf("stale exception %q: no such non-literal message any more; delete the entry", key)
	}
}

func TestErrorBodies_No500OutsideResponseGo(t *testing.T) {
	for _, c := range errorBodyDirect500s(errorBodyCallsIn(t, errorBodyDirs)) {
		t.Errorf("%s (line %d): a 500 goes through writeInternalError, which logs the cause under the request id", c.key(), c.line)
	}
}

func TestErrorBodies_WriteJSONStatusIs2xx(t *testing.T) {
	for _, c := range errorBodyNon2xxJSON(errorBodyCallsIn(t, errorBodyDirs)) {
		t.Errorf("%s (line %d): writeJSON outside %s must write http.StatusOK, StatusCreated or StatusAccepted; an error goes through writeError or writeInternalError", c.key(), c.line, errorBodyResponseFile)
	}
}

// The check must be able to fail: each planted leak is caught, and the safe
// shapes are not.
func TestErrorBodies_StaticCheckCatchesPlantedLeaks(t *testing.T) {
	calls := append(errorBodyCallsInFile(t, "planted.go", errorBodyPlanted),
		errorBodyCallsInFile(t, errorBodyResponseFile, errorBodyPlantedResponseGo)...)
	wantErrorBodyFlagged(t, "non-literal message", errorBodyNonLiteral(calls),
		"planted.go:leakErr", "planted.go:leakSprintf", "planted.go:leakVar", "planted.go:leakConcat",
		"planted.go:leakHTTPError", "planted.go:leakClosure", "planted.go:leakPkgVar", "response.go:respLeak")
	wantErrorBodyFlagged(t, "direct 500", errorBodyDirect500s(calls),
		"planted.go:leakErr", "planted.go:leakSprintf", "planted.go:leakHTTPError",
		"planted.go:literal500", "planted.go:literalHTTP500")
	wantErrorBodyFlagged(t, "non-2xx writeJSON", errorBodyNon2xxJSON(calls),
		"planted.go:json500", "planted.go:json409", "planted.go:jsonStatusVar")
	wantErrorBodyKey(t, calls, `planted.go:leakSprintf | 500 | fmt.Sprintf("op: %v", err)`)
}

const errorBodyPlanted = `package p

var leakPkgVar = func(w W, err error) { writeError(w, http.StatusBadRequest, err.Error()) }

func leakErr(w W, err error)       { writeError(w, http.StatusInternalServerError, err.Error()) }
func leakSprintf(w W, err error)   { writeError(w, 500, fmt.Sprintf("op: %v", err)) }
func leakVar(w W, err error)       { msg := err.Error(); writeError(w, http.StatusBadGateway, msg) }
func leakConcat(w W, err error)    { writeError(w, http.StatusBadRequest, "bad: "+err.Error()) }
func leakHTTPError(w W, err error) { http.Error(w, err.Error(), http.StatusInternalServerError) }
func leakClosure(w W, err error) H {
	return func() { writeError(w, http.StatusConflict, err.Error()) }
}
func literal500(w W)                    { writeError(w, http.StatusInternalServerError, "failed") }
func literalHTTP500(w W)                { http.Error(w, "failed", 500) }
func literal400(w W)                    { writeError(w, http.StatusBadRequest, "bad request") }
func viaHelper(w W, r R, err error)     { writeInternalError(w, r, "op", err) }
func viaInvalid(w W, r R, err error)    { writeInvalidOrInternal(w, r, "op", err) }
func json500(w W, v V)                  { writeJSON(w, http.StatusInternalServerError, v) }
func json409(w W, v V)                  { writeJSON(w, http.StatusConflict, v) }
func jsonStatusVar(w W, s int, v V)     { writeJSON(w, s, v) }
func json2xx(w W, v V) {
	writeJSON(w, http.StatusOK, v)
	writeJSON(w, http.StatusCreated, v)
	writeJSON(w, http.StatusAccepted, v)
}
`

// errorBodyPlantedResponseGo stands for response.go: it may write the 500 and the
// non-2xx writeJSON, but its messages are still checked.
const errorBodyPlantedResponseGo = `package p

func writeInternalError(w W, r R, op string, err error) { writeJSON(w, http.StatusInternalServerError, v) }
func writeError(w W, status int, message string)        { writeJSON(w, status, map[string]string{"error": message}) }
func literal500Here(w W)                                { writeError(w, http.StatusInternalServerError, "failed") }
func respLeak(w W, err error)                           { writeError(w, http.StatusBadRequest, err.Error()) }
`

// wantErrorBodyFlagged requires the flagged calls to come from exactly the named
// file:function places.
func wantErrorBodyFlagged(t *testing.T, rule string, got []errorBodyCall, want ...string) {
	t.Helper()
	places := make([]string, 0, len(got))
	for _, c := range got {
		places = append(places, c.file+":"+c.fn)
	}
	sort.Strings(places)
	sort.Strings(want)
	if strings.Join(places, ",") != strings.Join(want, ",") {
		t.Errorf("%s flagged %v, want %v", rule, places, want)
	}
}

func wantErrorBodyKey(t *testing.T, calls []errorBodyCall, key string) {
	t.Helper()
	for _, c := range calls {
		if c.key() == key {
			return
		}
	}
	t.Errorf("no call keyed %q; exception keys must keep this spelling", key)
}

func errorBodyNonLiteral(calls []errorBodyCall) []errorBodyCall {
	return filterErrorBodyCalls(calls, func(c errorBodyCall) bool {
		return c.callee != "writeJSON" && !c.literal
	})
}

func errorBodyDirect500s(calls []errorBodyCall) []errorBodyCall {
	return filterErrorBodyCalls(calls, func(c errorBodyCall) bool {
		return c.callee != "writeJSON" && c.file != errorBodyResponseFile && errorBodyIs500(c.status)
	})
}

func errorBodyNon2xxJSON(calls []errorBodyCall) []errorBodyCall {
	return filterErrorBodyCalls(calls, func(c errorBodyCall) bool {
		return c.callee == "writeJSON" && c.file != errorBodyResponseFile && !errorBodyJSON2xx[c.status]
	})
}

var errorBodyJSON2xx = map[string]bool{"http.StatusOK": true, "http.StatusCreated": true, "http.StatusAccepted": true}

func errorBodyIs500(status string) bool {
	return status == "http.StatusInternalServerError" || status == "500"
}

func filterErrorBodyCalls(calls []errorBodyCall, keep func(errorBodyCall) bool) []errorBodyCall {
	var out []errorBodyCall
	for _, c := range calls {
		if keep(c) {
			out = append(out, c)
		}
	}
	return out
}

func staleErrorBodyKeys(used map[string]bool) []string {
	var out []string
	for key := range errorBodyExceptions {
		if !used[key] {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// errorBodyCallsIn parses the non-test Go files of each dir. A dir with no
// such file, or no call at all, fails: the check must not pass vacuously.
func errorBodyCallsIn(t *testing.T, dirs []string) []errorBodyCall {
	t.Helper()
	var out []errorBodyCall
	for _, dir := range dirs {
		calls := errorBodyCallsInDir(t, dir)
		if len(calls) == 0 {
			t.Fatalf("no response-writing call found in %s", dir)
		}
		out = append(out, calls...)
	}
	return out
}

func errorBodyCallsInDir(t *testing.T, dir string) []errorBodyCall {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []errorBodyCall
	for _, e := range entries {
		if errorBodyIsSourceFile(e.Name()) {
			out = append(out, errorBodyCallsInFile(t, filepath.Join(dir, e.Name()), nil)...)
		}
	}
	return out
}

// errorBodyCallsInFile parses path (or src, when non-nil) and returns its
// response-writing calls, each keyed by its base name and enclosing
// top-level declaration.
func errorBodyCallsInFile(t *testing.T, path string, src interface{}) []errorBodyCall {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []errorBodyCall
	for _, decl := range f.Decls {
		out = append(out, errorBodyCallsInDecl(fset, filepath.Base(path), errorBodyDeclName(decl), decl)...)
	}
	return out
}

func errorBodyIsSourceFile(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// errorBodyDeclName names a top-level declaration: a function's name, or the first
// name a var or const declaration binds (a package-level func literal).
func errorBodyDeclName(decl ast.Decl) string {
	if fn, ok := decl.(*ast.FuncDecl); ok {
		return fn.Name.Name
	}
	if vs := errorBodyFirstValueSpec(decl); vs != nil && len(vs.Names) > 0 {
		return vs.Names[0].Name
	}
	return ""
}

func errorBodyFirstValueSpec(decl ast.Decl) *ast.ValueSpec {
	gd, ok := decl.(*ast.GenDecl)
	if !ok || len(gd.Specs) == 0 {
		return nil
	}
	vs, _ := gd.Specs[0].(*ast.ValueSpec)
	return vs
}

func errorBodyCallsInDecl(fset *token.FileSet, file, fn string, decl ast.Decl) []errorBodyCall {
	var out []errorBodyCall
	ast.Inspect(decl, func(n ast.Node) bool {
		if call, sink := errorBodySinkCall(n); call != nil {
			out = append(out, newErrorBodyCall(fset, file, fn, call, sink))
		}
		return true
	})
	return out
}

func newErrorBodyCall(fset *token.FileSet, file, fn string, call *ast.CallExpr, sink errorBodySink) errorBodyCall {
	c := errorBodyCall{
		file: file, fn: fn, callee: errorBodyCallee(call.Fun),
		status: types.ExprString(call.Args[sink.status]),
		line:   fset.Position(call.Pos()).Line,
	}
	if sink.message >= 0 {
		c.message = types.ExprString(call.Args[sink.message])
		c.literal = errorBodyIsLiteral(call.Args[sink.message])
	}
	return c
}

// errorBodySinkCall returns n as a response-writing call with its argument
// layout, or nil.
func errorBodySinkCall(n ast.Node) (*ast.CallExpr, errorBodySink) {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, errorBodySink{}
	}
	sink, ok := errorBodySinks[errorBodyCallee(call.Fun)]
	if !ok || len(call.Args) <= max(sink.status, sink.message) {
		return nil, errorBodySink{}
	}
	return call, sink
}

func errorBodyIsLiteral(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

func errorBodyCallee(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
	}
	return ""
}

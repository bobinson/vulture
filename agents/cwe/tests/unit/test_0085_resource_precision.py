"""CWE-476 / CWE-770 precision (feature 0085).

Measured on the Vulture tree itself: CWE-476 produced 345 findings at HIGH
severity of which 345 were Go `:=` value assignments with no pointer to
dereference, and CWE-770 produced 469 of which 466 were bare `.append()` calls
(114 appending a string literal). Together 45% of that scan.

Every suppression below is paired with a true positive that MUST keep firing,
including the two the protected E2E fixture depends on
(tests/e2e/test_cwe_audit.py::test_resource_detects_null_deref and
::test_resource_detects_unbounded_alloc). Those E2E tests are NOT modified.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from cwe_agent.skills.resource_check import check_resource_management


def _scan(tmp_path, name, body, cat):
    (tmp_path / name).write_text(body)
    res = check_resource_management(str(tmp_path))
    return [f for f in res.get("findings", []) if f.get("category") == cat]


# ============ CWE-476: a value assignment is not a nil dereference ==========

def test_TP_protected_e2e_fixture_still_fires(tmp_path):
    """THE non-vacuity guard. This is verbatim the fixture that
    tests/e2e/test_cwe_audit.py:442 depends on. If the narrowing kills it, the
    narrowing is wrong — the E2E test is the business contract."""
    fs = _scan(tmp_path, "null_deref.go",
               "package main\n\nfunc process() {\n    val := obj.GetItem()\n    val.Use()\n}\n",
               "CWE-476")
    assert fs, "the protected E2E fixture must still produce a CWE-476"


def test_TP_dereference_after_discarded_error_still_fires(tmp_path):
    """The classic real bug: error thrown away, value dereferenced anyway."""
    fs = _scan(tmp_path, "req.go",
               'package main\n\nfunc f() {\n    req, _ := http.NewRequest("GET", url, nil)\n'
               '    req.Header.Set("X", "y")\n}\n',
               "CWE-476")
    assert fs, "discarded error + dereference must still be reported"


def test_FP_value_assignment_never_dereferenced(tmp_path):
    """os.Getenv returns a string. There is no pointer here at all."""
    fs = _scan(tmp_path, "env.go",
               'package main\n\nfunc f() {\n    key := os.Getenv("OPENAI_API_KEY")\n'
               '    use(key)\n}\n',
               "CWE-476")
    assert not fs, f"a string value assignment reported as a nil deref: {[f['title'] for f in fs]}"


def test_FP_constructor_result_passed_along(tmp_path):
    fs = _scan(tmp_path, "ctor.go",
               "package main\n\nfunc f() {\n    svc := service.NewProveService(repo)\n"
               "    register(svc)\n}\n",
               "CWE-476")
    assert not fs, "a constructor result that is never dereferenced is not a nil deref"


def test_FP_python_walrus_is_not_go(tmp_path):
    """Python's walrus operator is also `:=`. Without a language gate the Go
    rule fires on Python."""
    fs = _scan(tmp_path, "w.py",
               "def f(obj):\n    if (val := obj.get_item()) is not None:\n        val.use()\n",
               "CWE-476")
    assert not fs, "the Go nil-deref rule fired on Python walrus syntax"


def test_FP_nil_checked_assignment_still_suppressed(tmp_path):
    """Pre-existing behaviour that must survive."""
    fs = _scan(tmp_path, "checked.go",
               "package main\n\nfunc f() {\n    val := obj.GetItem()\n"
               "    if val == nil {\n        return\n    }\n    val.Use()\n}\n",
               "CWE-476")
    assert not fs, "a nil-checked value must stay suppressed"


# ============ CWE-770: an append is not unbounded growth ====================

def test_TP_protected_e2e_go_arm_still_fires(tmp_path):
    """THE non-vacuity guard for CWE-770. tests/e2e/test_cwe_audit.py:448
    depends on the GO arm (`make([]string, 0)`), which this change does not
    touch at all."""
    fs = _scan(tmp_path, "alloc.go",
               "package main\n\nfunc collect() {\n    items := make([]string, 0)\n}\n",
               "CWE-770")
    assert fs, "the protected E2E fixture must still produce a CWE-770"


def test_TP_unbounded_accumulation_in_a_loop_still_fires(tmp_path):
    """The real weakness: growth driven by input the process does not control."""
    fs = _scan(tmp_path, "drain.py",
               "def drain(sock):\n    out = []\n    while True:\n"
               "        frame = sock.recv()\n        out.append(frame)\n    return out\n",
               "CWE-770")
    assert fs, "unbounded accumulation from a socket must still be reported"


def test_FP_append_of_a_literal_outside_a_loop(tmp_path):
    """`result.technologies.append("Apache")` — 114 of these on the real tree."""
    fs = _scan(tmp_path, "detect.py",
               "def detect(result):\n    if has_apache():\n        result.technologies.append(\"Apache\")\n",
               "CWE-770")
    assert not fs, f"appending a constant reported as unbounded allocation: {[f['title'] for f in fs]}"


def test_FP_single_append_building_a_small_result(tmp_path):
    fs = _scan(tmp_path, "parts.py",
               "def describe(proto):\n    parts = []\n    parts.append(\"WebSocket\")\n"
               "    return \" \".join(parts)\n",
               "CWE-770")
    assert not fs, "a bounded two-element build is not unbounded allocation"


def test_FP_js_dom_append_is_not_allocation(tmp_path):
    """In JS `.append()` is DOM/FormData and allocates nothing."""
    fs = _scan(tmp_path, "ui.js",
               "function render(el, node) {\n  el.append(node);\n  form.append('k', 'v');\n}\n",
               "CWE-770")
    assert not fs, "a DOM append reported as unbounded allocation"


# ---- CWE-476 round 2: nil-ability and non-nil-check guards ------------------
# The first narrowing took 345 -> 100 on the Vulture tree. Sampling the 100
# showed two remaining classes, both cheap and safe to close.

def test_FP_go_constructors_that_never_return_nil(tmp_path):
    """bufio.NewScanner, hmac.New, flag.NewFlagSet and friends are documented
    to always return a usable non-nil value. Dereferencing them is correct Go."""
    for name, code in {
        "sc.go":   "package main\n\nfunc f() {\n    sc := bufio.NewScanner(os.Stdin)\n    sc.Scan()\n}\n",
        "mac.go":  "package main\n\nfunc f() {\n    mac := hmac.New(sha256.New, key)\n    mac.Write(b)\n}\n",
        "flag.go": 'package main\n\nfunc f() {\n    fs := flag.NewFlagSet("x", flag.ContinueOnError)\n    fs.SetOutput(w)\n}\n',
    }.items():
        fs = _scan(tmp_path, name, code, "CWE-476")
        assert not fs, f"{name}: a never-nil constructor reported as a nil deref"


def test_FP_len_guard_counts_as_a_check(tmp_path):
    """`if len(sm) != 3 { return }` guards a nil slice just as well as an
    explicit nil comparison — a nil slice has len 0."""
    fs = _scan(tmp_path, "re.go",
               "package main\n\nfunc f() {\n    sm := re.FindStringSubmatch(s)\n"
               "    if len(sm) != 3 {\n        return\n    }\n    use(sm[1])\n}\n",
               "CWE-476")
    assert not fs, "a len() guard must suppress the finding"


def test_TP_still_fires_after_the_nil_ability_gate(tmp_path):
    """NON-VACUITY for round 2: the protected fixture and the discarded-error
    case must BOTH survive the new suppressions."""
    a = _scan(tmp_path, "keep1.go",
              "package main\n\nfunc process() {\n    val := obj.GetItem()\n    val.Use()\n}\n", "CWE-476")
    b = _scan(tmp_path, "keep2.go",
              'package main\n\nfunc f() {\n    req, _ := http.NewRequest("GET", url, nil)\n'
              '    req.Header.Set("X", "y")\n}\n', "CWE-476")
    assert a, "the protected E2E shape must still fire"
    assert b, "discarded error + dereference must still fire"


# ---- CWE-476 round 3: the Go `New*` constructor convention ------------------
# 56 remained after round 2. Sampling showed two classes: stdlib value-returners
# the list missed (strings.TrimSpace, exec.CommandContext, http.NewServeMux) and
# PROJECT constructors (handler.NewStreamHandler, localdev.NewLauncher).
#
# The unifying rule is Go's near-universal convention: a SINGLE-VALUE assignment
# from a `New*` function returns a ready-to-use value. A constructor that can
# fail returns (T, error) — a two-value assignment, which this does not
# suppress. Stated as an assumption because it IS one: a `New*` that returns a
# bare nil on bad input would now be missed. That is a recall cost paid
# knowingly, against 56 measured false positives at HIGH severity.

def test_FP_single_value_New_constructors(tmp_path):
    for name, code in {
        "h.go":   "package main\n\nfunc f() {\n    h := handler.NewStreamHandler(a, b)\n    h.SetX(1)\n}\n",
        "mux.go": "package main\n\nfunc f() {\n    mux := http.NewServeMux()\n    mux.HandleFunc(p, fn)\n}\n",
        "l.go":   "package main\n\nfunc f() {\n    launcher := localdev.NewLauncher(cfg)\n    launcher.Start()\n}\n",
    }.items():
        fs = _scan(tmp_path, name, code, "CWE-476")
        assert not fs, f"{name}: a single-value New* constructor is not a nil deref"


def test_FP_stdlib_value_returners(tmp_path):
    for name, code in {
        "t.go": "package main\n\nfunc f() {\n    s := strings.TrimSpace(line)\n    s.Foo()\n}\n",
        "c.go": 'package main\n\nfunc f() {\n    cmd := exec.CommandContext(ctx, "git")\n    cmd.Env = env\n}\n',
    }.items():
        fs = _scan(tmp_path, name, code, "CWE-476")
        assert not fs, f"{name}: a stdlib value-returner is not a nil deref"


def test_TP_two_value_constructor_that_can_fail_still_fires(tmp_path):
    """NON-VACUITY for round 3, and the boundary of the New* rule: a constructor
    returning (T, error) with the error DISCARDED is exactly the real bug, and
    must survive the suppression above."""
    fs = _scan(tmp_path, "n.go",
               'package main\n\nfunc f() {\n    req, _ := http.NewRequest("GET", u, nil)\n'
               '    req.Header.Set("A", "b")\n}\n',
               "CWE-476")
    assert fs, "two-value New* with a discarded error must still fire"


def test_TP_protected_fixture_survives_round_three(tmp_path):
    """obj.GetItem() is not a New* constructor, so the protected E2E shape is
    untouched by this rule."""
    fs = _scan(tmp_path, "p.go",
               "package main\n\nfunc process() {\n    val := obj.GetItem()\n    val.Use()\n}\n",
               "CWE-476")
    assert fs, "the protected E2E shape must still fire"


# ---- CWE-476 round 4: a nil guard is not always spelled `if x != nil` -------
# 20 remained after round 3. Two of four sampled were guarded by a form the
# pattern does not match: GO_NIL_CHECK requires a literal `if`, so a guard in a
# `return`, an `&&` chain or an assignment was invisible.

def test_FP_nil_guard_in_a_return_expression(tmp_path):
    fs = _scan(tmp_path, "ip.go",
               "package main\n\nfunc isLoopback(host string) bool {\n    ip := net.ParseIP(host)\n"
               "    return ip != nil && ip.IsLoopback()\n}\n",
               "CWE-476")
    assert not fs, "a nil guard in a return expression must suppress the finding"


def test_FP_nil_guard_in_an_assignment_shortcircuit(tmp_path):
    fs = _scan(tmp_path, "u.go",
               "package main\n\nfunc f() {\n    u, err := url.Parse(base)\n"
               '    ok := err == nil && u.Host != ""\n    _ = ok\n}\n',
               "CWE-476")
    assert not fs, "a short-circuit guard must suppress the finding"


def test_TP_unguarded_index_of_a_returned_slice_still_fires(tmp_path):
    """NON-VACUITY for round 4, and a REAL bug found on the Vulture tree:
    backend/internal/broker/server/complete.go:220 indexes [0] of a returned
    slice with no length check. Empty slice -> panic."""
    fs = _scan(tmp_path, "c.go",
               "package main\n\nfunc f() {\n    cands := sel.Candidates()\n"
               "    primary := cands[0]\n    use(primary)\n}\n",
               "CWE-476")
    assert fs, "an unguarded [0] index of a returned slice must still fire"


def test_TP_protected_fixture_survives_round_four(tmp_path):
    fs = _scan(tmp_path, "p4.go",
               "package main\n\nfunc process() {\n    val := obj.GetItem()\n    val.Use()\n}\n",
               "CWE-476")
    assert fs, "the protected E2E shape must still fire"

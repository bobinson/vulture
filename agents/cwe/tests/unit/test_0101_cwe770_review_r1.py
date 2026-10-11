"""Feature 0101 -- CWE-770 predicates added for the round-1 implementation review.

R770-IMPL-2  a keyword argument (`stdout=PIPE`, `stream=True`) is not a binding,
             and a member source (`proc.stdout`) consults its receiver.
R770-IMPL-3  an `add` whose arguments are only numeric is arithmetic, and a
             `var x T` of an atomic or wait-group type is a scalar.
R770-IMPL-4  pull roles: a read compared with end of stream, a read into a
             `&mut` slice, `fread`, an argument-less `.input()`, an attribute
             chain whose receiver is a source, a reader constructed over a source.
R770-IMPL-5  a `put` / `insert` keyed by a literal overwrites one entry.
R770-IMPL-1  the self-growth read and the running-total scan stay cheap on
             near-cap identifier lines.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from cwe_agent.skills import resource_check as rc


def _alloc(name: str, src: str) -> list[int]:
    lines = src.strip("\n").split("\n")
    out: list[dict] = []
    for n, line in enumerate(lines, 1):
        rc._check_unbounded_alloc(Path(name), line, n, lines, out)
    return [f["line_start"] for f in out]


# --- R770-IMPL-2: keyword arguments and member sources ------------------------

@pytest.mark.parametrize(("name", "text"), [
    ("stdout", "proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)"),
    ("stream", "resp = session.get(url, stream=True)"),
    ("stream", "session.get(url, timeout=5, stream=True)"),
])
def test_keyword_argument_is_not_a_binding(name: str, text: str) -> None:
    assert rc._binding_rhs(name, text) is None


@pytest.mark.parametrize(("name", "text", "rhs"), [
    ("line", "while ((line = br.readLine()) != null) {", " br.readLine()) != null) {"),
    ("x", "if (x = next()) {", " next()) {"),
    ("b", "a, b = pair()", " pair()"),
    ("proc", "proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)", " subprocess.Popen(cmd, stdout=subprocess.PIPE)"),
])
def test_statement_bindings_are_still_read(name: str, text: str, rhs: str) -> None:
    assert rc._binding_rhs(name, text) == rhs


@pytest.mark.parametrize(("src", "chain"), [
    ("proc.stdout", ["proc"]),
    ("sys.stdin.buffer", ["sys", "stdin"]),
    ("stdin.lock().lines()", ["stdin", "lock"]),
    ("lines", []),
])
def test_member_source_exposes_its_receiver_chain(src: str, chain: list[str]) -> None:
    assert rc._chain_receivers(src) == chain


@pytest.mark.parametrize(("src", "routine", "want"), [
    ("proc.stdout", "proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)", True),
    ("sys.stdin.buffer", "", True),
    ("settings.defaults.rows", "", False),
])
def test_member_source_verdict(src: str, routine: str, want: bool) -> None:
    assert rc._source_is_input(src, routine) is want


# --- R770-IMPL-3: numeric add, atomic and wait-group types ---------------------

@pytest.mark.parametrize("code", [
    "wg.Add(1)",
    "received.Add(1)",
    "acc.Add(int64(v))",
    "Interlocked.Add(ref received, n);",
    "metrics.add(1)",
    "metrics.add(value.length);",
    "hits.add(len(chunk))",
])
def test_numeric_add_is_arithmetic(code: str) -> None:
    assert rc._accumulator(code) is None


@pytest.mark.parametrize(("code", "acc"), [
    ("seen.add(d)", "seen"),
    ("seen.Add(string(buf[:n]))", "seen"),
    ("ids.append(1)", "ids"),
    ("nums.add(n)", "nums"),
    ("frames.Add((byte[])buf.Clone());", "frames"),
])
def test_non_numeric_growth_is_still_growth(code: str, acc: str) -> None:
    assert rc._accumulator(code) == acc


@pytest.mark.parametrize(("acc", "routine", "want"), [
    ("wg", "var wg sync.WaitGroup", True),
    ("wg", "wg := sync.WaitGroup{}", True),
    ("received", "var received atomic.Int64", True),
    ("hits", "var hits AtomicLong", True),
    ("conns", "var conns []net.Conn", False),
    ("seen", "var seen map[string]bool", False),
])
def test_scalar_types_in_declarations(acc: str, routine: str, want: bool) -> None:
    assert rc._is_scalar(acc, routine) is want


# --- R770-IMPL-4: pull roles ---------------------------------------------------

@pytest.mark.parametrize("text", [
    "while ((n = in.read(b)) != -1) {",
    "while ((r = in.read(data)) != -1) {",
    "while ((r = rd.read(cbuf)) > 0) {",
    "while let Ok(n) = stream.read(&mut tmp) {",
    "$out[] = fread($sock, 8192);",
    "for line in fileinput.input():",
])
def test_pull_roles(text: str) -> None:
    assert rc._pulls(text)


@pytest.mark.parametrize("text", [
    "parser.read(paths)",
    "config.read(files)",
    "visitor.accept(v)",
    "value = form.input(name)",
])
def test_not_pull_roles(text: str) -> None:
    assert not rc._pulls(text)


@pytest.mark.parametrize(("rhs", "want"), [
    ("BufReader::new(stream)", True),
    ("BufReader::new(conn)", True),
    ("BufReader::new(text.as_bytes())", None),
    ("BufReader::new(File::open(path)?)", None),
])
def test_constructor_over_a_source(rhs: str, want) -> None:
    assert rc._bound_source_verdict(rhs) is want


# --- R770-IMPL-5: literal-keyed overwrite ---------------------------------------

@pytest.mark.parametrize("code", [
    'map.put("", line);',
    "map.put(1, line);",
    'm.insert("", v);',
])
def test_literal_key_is_an_overwrite(code: str) -> None:
    assert rc._accumulator(code) is None


@pytest.mark.parametrize(("code", "acc"), [
    ("map.put(line, 1);", "map"),
    ("lst.insert(0, x)", "lst"),
    ("q.put(b)", "q"),
])
def test_keyed_or_positional_growth_stays(code: str, acc: str) -> None:
    assert rc._accumulator(code) == acc


# --- behaviour through the entry point ------------------------------------------

def test_popen_stdout_loop_reports() -> None:
    src = """
def run(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    out = []
    for line in proc.stdout:
        out.append(line)
    return out
"""
    assert _alloc("p.py", src) == [5]


def test_accept_loop_counters_are_clean() -> None:
    src = """
func serve(ln net.Listener) {
\tvar wg sync.WaitGroup
\tvar received atomic.Int64
\tfor {
\t\tconn, err := ln.Accept()
\t\tif err != nil {
\t\t\tbreak
\t\t}
\t\twg.Add(1)
\t\treceived.Add(1)
\t\tgo handle(conn)
\t}
}
"""
    assert _alloc("s.go", src) == []


# --- R770-IMPL-1: bounded per-line cost ----------------------------------------

def _best_ms(fn, *args) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        fn(*args)
        best = min(best, time.perf_counter() - start)
    return best * 1000.0


def test_self_growth_read_is_cheap_on_a_long_chain() -> None:
    line = "    " + ".".join(["a" * 60] * 31) + " += q"
    assert _best_ms(rc._accumulator, line) < 1.0


def test_running_totals_scan_each_body_once() -> None:
    body = [f"acc{i}.append(d); {'a' * 1900} = 1" for i in range(80)]
    rc._running_totals("acc0", body)
    assert _best_ms(lambda: [rc._running_totals(f"acc{i}", body) for i in range(77)]) < 20.0


def test_receiver_bound_to_a_pull_is_data_already_read() -> None:
    """`registry = await params.read()` then `registry.entries` iterates memory."""
    routine = "const registry = await params.read();"
    assert rc._source_is_input("registry.entries", routine) is False
    assert rc._source_is_input("proc.stdout", "proc = spawn(cmd)\nproc = subprocess.Popen(cmd)") is True

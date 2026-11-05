"""Feature 0101 -- CWE-770 predicates for the round-2 implementation review.

R770-R2-1  the self-growth read finds the OPERATOR first and reads the receiver
           backwards from it, so a chain of 1- or 2-character segments (every
           other character an identifier boundary) costs one bounded read per
           operator, not a 128-character attempt per segment.
R770-R2-2  per-identifier lookups compile nothing per name: a template is split
           at NAME into a left context and a suffix, both compiled once, and
           matched at each occurrence of the name. Parity with the composed
           pattern (``_named``) is pinned here on a battery of texts.
R770-R2-4  the numeric-``add`` exemption yields to a receiver bound in the
           routine to a collection (``seen = set(); seen.add(int(line))``).
R770-R2-5  trim verbs match without regard to case (C# ``Clear()``).
R770-R2-6  ``foreach`` and an ``await`` prefix open loops.
R770-R2-7  trims by verb prefix (pop*, remove*, dequeue*, reset, setLength, ...)
           and a self-slice reassignment (``recent = recent[1:]``).
R770-R2-8  ``var buf bytes.Buffer`` is a buffer binding, PHP ``.=`` grows,
           ``x.on<event> =`` is an input-event callback, an argument-less
           ``take()`` is a blocking pull, and a multi-argument ``read(...)``
           compared with end of stream is a pull.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from cwe_agent.skills import resource_check as rc
from cwe_agent.skills._lexical import MAX_SCAN_CHARS
from shared.testing.timing import budget


def _alloc(name: str, src: str) -> list[int]:
    lines = src.strip("\n").split("\n")
    out: list[dict] = []
    for n, line in enumerate(lines, 1):
        rc._check_unbounded_alloc(Path(name), line, n, lines, out)
    return [f["line_start"] for f in out]


def _best_ms(fn, *args) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        fn(*args)
        best = min(best, time.perf_counter() - start)
    return best * 1000.0


# --- R770-R2-1: operator-first self-growth ------------------------------------

@pytest.mark.parametrize(("code", "acc"), [
    ("x += q", "x"),
    ("self.buf += chunk", "buf"),
    ("out << line", "out"),
    ("@items << line", "items"),
    ("$out[] = fread($sock, 8192);", "out"),
    ("t[#t + 1] = line", "t"),
    ("buf = append(buf, b...)", "buf"),
    ("s.buf = append(s.buf, b...)", "buf"),
    ("data = realloc(data, used + got);", "data"),
    ("acc = acc + chunk", "acc"),
    ("array_push($rows, $line);", "rows"),
    ("$buf .= fread($sock, 8192);", "buf"),
])
def test_self_growth_receivers(code: str, acc: str) -> None:
    assert rc._accumulator(code) == acc


@pytest.mark.parametrize("code", [
    "x = append(y, v)",
    "a = b + c",
    "x := append(x, v)",
    "x == x + 1",
    "1 << 3",
    "a <<< b",
    "x[i] = v",
    "for i in 0..=n {",
    "t[#u + 1] = line",
])
def test_not_self_growth(code: str) -> None:
    assert rc._accumulator(code) is None


@pytest.mark.parametrize("tail", ["x += q", "x << q", "x[] = q", "x = x + q", "x .= q"])
@pytest.mark.parametrize("segment", ["a.", "ab.", "a_."])
def test_short_segment_chain_is_cheap(segment: str, tail: str) -> None:
    line = (segment * MAX_SCAN_CHARS)[:MAX_SCAN_CHARS - 20] + tail
    assert _best_ms(rc._accumulator, line) < budget(0.5)


def test_many_operators_on_one_line_are_cheap() -> None:
    for unit in ("a.b += ", "a << ", "a[] = ", "a = a + ", "= append(a, ", "a .= "):
        line = (unit * MAX_SCAN_CHARS)[:MAX_SCAN_CHARS]
        assert _best_ms(rc._accumulator, line) < budget(0.5), unit


# --- R770-R2-2: per-identifier lookups without a per-name compile ---------------

_PARITY_TEXTS = (
    "buf = []\nbuf.append(x)\n",
    "  let buf: string[] = [];\nbuf = buf.concat(x)",
    "chunks, total = [], 0\ntotal += len(c)",
    "var wg sync.WaitGroup\nwg.Add(1)",
    "proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)\nfor line in proc.stdout:",
    "x = 1; x = []\nx.append(v)",
    "with open(path) as fh:\n    for line in fh:",
    "ch := make(chan int)\nfor v := range ch {",
    "del buf\nbuf.pop()\nbuf.clear()",
    "  const n = 0\nn += 1",
    "abuf = []\nbuf_x = []\n$buf = ''\nobj.buf = []\nbuf += x",
    "a = b = []\nb.append(v)",
    "f(buf=1, b=2)\nbuf = deque(maxlen=5)",
    "q = asyncio.Queue()\nq.put_nowait(x)\n",
    "total += len(chunk)\nif total > LIMIT:\n    raise TooLarge",
)
_PARITY_NAMES = ("buf", "total", "wg", "proc", "x", "fh", "ch", "n", "b", "q", "a", "$buf", "chunks")


def _composed(template: str, name: str, text: str) -> list[tuple[int, str]]:
    return [(m.start(), m.group(0)) for m in rc._named(template, name).finditer(text)]


def _formed(template: str, name: str, text: str) -> list[tuple[int, str]]:
    return [(m.start(), m.group(0)) for m in rc._form_finditer(template, name, text)]


@pytest.mark.parametrize("template_id", sorted(
    k for k, v in vars(rc).items() if k.endswith("_TEMPLATE") and isinstance(v, str)
))
def test_form_matching_agrees_with_the_composed_template(template_id: str) -> None:
    template = getattr(rc, template_id)
    for text in _PARITY_TEXTS:
        for name in _PARITY_NAMES:
            assert _formed(template, name, text) == _composed(template, name, text), (template_id, name, text)


def test_form_lookup_compiles_nothing_per_name() -> None:
    rc._named.cache_clear()
    text = "\n".join(f"n{i} = []" for i in range(50))
    for i in range(5000):
        rc._form_search(rc._ACC_EMPTY_BIND_TEMPLATE, f"name{i}", text)
        rc._binding_rhs(f"name{i}", text)
    assert rc._named.cache_info().currsize == 0


def test_form_lookup_is_bounded_on_a_repetitive_text() -> None:
    text = ("a" + " a" * 60 + "\n") * 120
    for template in (rc._ACC_BIND_TEMPLATE, rc._ACC_SCALAR_BIND_TEMPLATE, rc._ACC_AS_TEMPLATE):
        assert _best_ms(lambda t=template: list(rc._form_finditer(t, "a", text))) < budget(2.0)


# --- R770-R2-4: numeric add on a collection -----------------------------------

def test_numeric_add_into_a_set_reports() -> None:
    src = """
def ids():
    seen = set()
    for line in sys.stdin:
        seen.add(int(line))
    return seen
"""
    assert _alloc("n.py", src) == [4]


def test_numeric_add_into_a_kotlin_list_reports() -> None:
    src = """
fun sizes(reader: BufferedReader): List<Int> {
    val lens = mutableListOf<Int>()
    while (true) {
        val line = reader.readLine() ?: break
        lens.add(line.length)
    }
    return lens
}
"""
    assert _alloc("n.kt", src) == [5]


@pytest.mark.parametrize("code", ["wg.Add(1)", "octets.Add(int64(n))", "Interlocked.Add(ref received, n);",
                                  "metrics.add(len(d))"])
def test_numeric_add_without_a_collection_binding_stays_arithmetic(code: str) -> None:
    src = f"""
def f(sock, metrics):
    var octets atomic.Int64
    while True:
        d = sock.recv(64)
        {code}
"""
    assert _alloc("c.py", src) == []


@pytest.mark.parametrize(("rhs", "want"), [
    ("set()", True), ("mutableListOf<Int>()", True), ("NewSet()", True), ("new HashSet<>()", True),
    ("map[int64]bool{}", True), ("[]", True), ("atomic.Int64{}", False), ("sync.WaitGroup{}", False),
    ("Counter()", False), ("new Metrics()", False), ("0", False),
])
def test_collection_constructor(rhs: str, want: bool) -> None:
    assert rc._bound_to_collection("x", f"x = {rhs}") is want


# --- R770-R2-5 / R2-7: trims -------------------------------------------------

@pytest.mark.parametrize("row", [
    "batch.Clear();", "sb.Clear();", "recent.RemoveAt(0);", "q.Dequeue();", "recent.removeFirst();",
    "recent.pop_front();", "buf.Reset()", "sb.setLength(0);", "buf.clear()", "recent.popleft()",
    "lst.splice(0, 10)", "del recent[0]",
])
def test_trim_rows(row: str) -> None:
    acc = row.split(".")[0].split()[-1].split("[")[0]
    assert rc._trimmed(acc, ["while True:", row])


@pytest.mark.parametrize(("acc", "row"), [
    ("recent", "recent = recent[1:]"),
    ("window", "window = window[-1024:]"),
    ("buf", "buf = buf[:0]"),
    ("buf", "buf = buf[n:];"),
])
def test_self_slice_is_a_trim(acc: str, row: str) -> None:
    assert rc._trimmed(acc, ["for {", row]) or rc._reset_in_loop(acc, ["for {", row])


@pytest.mark.parametrize(("acc", "row"), [
    ("recent", "recent = recent + [x]"),
    ("buf", "buf = buf[:n] + data"),
    ("buf", "other.clear()"),
    ("buf", "buffer.Clear();"),
])
def test_not_a_trim(acc: str, row: str) -> None:
    body = ["while True:", row]
    assert not rc._trimmed(acc, body) and not rc._reset_in_loop(acc, body)


# --- R770-R2-6: foreach -----------------------------------------------------

@pytest.mark.parametrize("header", [
    "foreach (var m in inbox.GetConsumingEnumerable()) {",
    "await foreach (var m in stream) {",
    "    foreach ($rows as $r) {",
])
def test_foreach_opens_a_loop(header: str) -> None:
    assert rc._ACC_LOOP_HEADER.match(header)


def test_foreach_iteration_over_a_stream_parameter_is_driven() -> None:
    assert rc._loop_driven("await foreach (var m in stream) {", "", "")
    assert not rc._loop_driven("foreach (var n in names) {", "", "")


# --- R770-R2-8 -------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "String m = queue.take();",
    "while ((got = read(fd, tmp, sizeof tmp)) > 0) {",
    "while ((got = read(fd, tmp, sizeof(tmp))) > 0) {",
])
def test_more_pull_roles(text: str) -> None:
    assert rc._pulls(text)


@pytest.mark.parametrize("text", ["it.take(10)", "s.take(n)", "config.read(a, b)"])
def test_still_not_pull_roles(text: str) -> None:
    assert not rc._pulls(text)


def test_assigned_event_callback_is_an_input_callback() -> None:
    lines = ["let log = '';", "ws.onmessage = (ev) => {", "  log += ev.data;", "};"]
    assert rc._input_callback_opener(lines, 3) == 2
    assert rc._input_callback_opener(["button.onclick = () => {", "  n += 1;", "};"], 2) is None


def test_var_declared_buffer_is_a_buffer_binding() -> None:
    src = """
func slurp(conn net.Conn) []byte {
\tvar buf bytes.Buffer
\ttmp := make([]byte, 512)
\tfor {
\t\tn, err := conn.Read(tmp)
\t\tif err != nil {
\t\t\treturn buf.Bytes()
\t\t}
\t\tbuf.Write(tmp[:n])
\t}
}
"""
    assert _alloc("w.go", src) == [9]


def test_php_concat_assign_reports_in_a_driven_loop() -> None:
    src = """
function slurp($sock) {
    $buf = '';
    while (!feof($sock)) {
        $buf .= fread($sock, 8192);
    }
    return $buf;
}
"""
    assert _alloc("s.php", src) == [4]

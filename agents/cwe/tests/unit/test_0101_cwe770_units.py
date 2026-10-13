"""Feature 0101 -- unit contract of the CWE-770 predicates (LLD 5.2.3 / 5.2.4).

Each predicate is exercised on its own, so a regression names the concept that
broke (sink, lifetime, loop discovery, body, driver, pull role, cap, callback)
instead of surfacing as one moved row in the E2E corpus.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from cwe_agent.skills import resource_check as rc
from cwe_agent.skills._lexical import MAX_SCAN_CHARS


def _lines(src: str) -> list[str]:
    return src.strip("\n").split("\n")


def _site(lines: list[str], needle: str) -> int:
    return next(i for i, line in enumerate(lines, 1) if needle in line)


def _alloc(name: str, src: str) -> list[int]:
    lines = _lines(src)
    out: list[dict] = []
    for n, line in enumerate(lines, 1):
        rc._check_unbounded_alloc(Path(name), line, n, lines, out)
    return [f["line_start"] for f in out]


# ---------------------------------------------------------------------------
# sink: _accumulator
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("code", "acc"), [
    ("out.append(x)", "out"),
    ("chunks.push(chunk);", "chunks"),
    ("lines.Add(line);", "lines"),
    ("v.push_back(line);", "v"),
    ("out.extend_from_slice(&buf[..n]);", "out"),
    ("items.AddRange(batch);", "items"),
    ("lines.append(contentsOf: more)", "lines"),
    ("q.put(b)", "q"),
    ("dq.unshift(x)", "dq"),
    ("data = append(data, buf[:n]...)", "data"),
    ("out = realloc(out, len + n);", "out"),
    ("buf = buf + chunk", "buf"),
    ("$rows[] = $line;", "rows"),
    ("t[#t + 1] = line", "t"),
    ("array_push($rows, $line);", "rows"),
    ("lines << line", "lines"),
    ("data += chunk", "data"),
])
def test_accumulator_names_the_growing_receiver(code: str, acc: str) -> None:
    assert rc._accumulator(code) == acc


@pytest.mark.parametrize("code", [
    "total = total.add(x)",          # value-returning add (BigDecimal)
    "out.concat(more)",               # JS concat returns a new array
    "x = 1 << 4",                     # shift
    "print(out)",
])
def test_accumulator_rejects_non_growth(code: str) -> None:
    assert rc._accumulator(code) is None


@pytest.mark.parametrize(("acc", "routine"), [
    ("count", "count = 0"),
    ("total_bytes", "total_bytes = 0"),
    ("n", ""),
    ("hits", "hits = 0"),
    ("seen", "seen = new AtomicLong()"),
    ("octetsSeen", "octetsSeen := atomic.Int64{}"),
])
def test_is_scalar_excludes_counters(acc: str, routine: str) -> None:
    assert rc._is_scalar(acc, routine)


@pytest.mark.parametrize(("acc", "routine"), [
    ("frames", "frames = []"),
    ("total", "total = []"),           # counter word, but an empty-collection initialiser
    ("buf", 'buf = b""'),
])
def test_is_scalar_keeps_collections(acc: str, routine: str) -> None:
    assert not rc._is_scalar(acc, routine)


def test_is_scalar_ignores_a_tuple_unpacking_binding() -> None:
    """`chunks, total = [], 0` binds total to 0, not to `[]` (the positions are not read)."""
    assert rc._is_scalar("total", "chunks, total = [], 0")


def test_plus_equals_on_an_unbound_name_is_arithmetic() -> None:
    src = """
def f(sock, acc):
    while True:
        d = sock.recv(10)
        acc += d
"""
    assert _alloc("a.py", src) == []


# ---------------------------------------------------------------------------
# lifetime
# ---------------------------------------------------------------------------

def test_declared_inside_the_body_does_not_outlive_an_iteration() -> None:
    body = ["while (true) {", "  const parts = [];", "  parts.push(x);"]
    assert rc._declared_inside("parts", body)
    assert not rc._declared_inside("chunks", body)


def test_reset_in_loop_clears_batch_and_flush() -> None:
    assert rc._reset_in_loop("batch", ["while True:", "    batch.append(b)", "    batch = []"])
    assert not rc._reset_in_loop("batch", ["while True:", "    batch = batch + [b]"])


# ---------------------------------------------------------------------------
# loop discovery: _enclosing_loops
# ---------------------------------------------------------------------------

def test_enclosing_loops_own_line_first() -> None:
    lines = ["  while ((line = r.readLine()) != null) lines.add(line);"]
    assert rc._enclosing_loops(lines, 1) == [1]


def test_enclosing_loops_excludes_a_sibling_loop() -> None:
    lines = _lines("""
def f(xs, cond):
    out = []
    for x in xs:
        pass
    if cond:
        out.append(1)
""")
    assert rc._enclosing_loops(lines, _site(lines, "out.append")) == []


def test_enclosing_loops_nested_nearest_first() -> None:
    lines = _lines("""
def f(sock):
    while True:
        data = sock.recv(10)
        for item in data:
            acc.append(item)
""")
    assert rc._enclosing_loops(lines, _site(lines, "acc.append")) == [4, 2]


def test_enclosing_loops_stops_at_the_routine() -> None:
    lines = _lines("""
while True:
    pass
def g():
    out.append(1)
""")
    assert rc._enclosing_loops(lines, _site(lines, "out.append")) == []


def test_enclosing_loops_allman_opener() -> None:
    lines = _lines("""
void F() {
    while (true)
    {
        chunks.Add(buf);
    }
}
""")
    assert rc._enclosing_loops(lines, _site(lines, "chunks.Add")) == [2]


def test_enclosing_loops_flat_brace_body() -> None:
    lines = _lines("""
async function f(request) {
for await (const c of request) {
chunks.push(c);
}
}
""")
    assert rc._enclosing_loops(lines, _site(lines, "chunks.push")) == [2]


def test_enclosing_loops_skips_comments_and_string_interiors() -> None:
    lines = _lines('''
def f(sock):
    while True:
        note = """
column-0 text
"""
# a column-0 comment
        frames.append(sock.recv(10))
''')
    assert rc._enclosing_loops(lines, _site(lines, "frames.append")) == [2]


def test_enclosing_loops_examines_at_most_four() -> None:
    lines = ["def f():"] + ["    " * (i + 1) + "while True:" for i in range(6)]
    lines.append("    " * 7 + "acc.append(1)")
    assert len(rc._enclosing_loops(lines, len(lines))) == 4


# ---------------------------------------------------------------------------
# body: _loop_body
# ---------------------------------------------------------------------------

def test_loop_body_indentation_stops_at_ruby_end() -> None:
    lines = _lines("""
def slurp(sock)
  while line = sock.gets
    lines << line
  end
  more << x
end
""")
    body = rc._loop_body(lines, 2)
    assert any("lines << line" in b for b in body)
    assert not any("more << x" in b for b in body)


def test_loop_body_brace_mode() -> None:
    lines = _lines("""
while (true) {
  parts.push(v);
}
after.push(v);
""")
    body = rc._loop_body(lines, 1)
    assert any("parts.push" in b for b in body) and not any("after.push" in b for b in body)


def test_loop_body_one_line_includes_the_header_tail() -> None:
    lines = ["while ((n = in.read(buf)) > 0) out.add(buf);"]
    assert "out.add" in rc._loop_body(lines, 1)[0]


def test_loop_body_do_and_repeat_join_the_trailer() -> None:
    lines = _lines("""
do {
  line = r.readLine();
  out.add(line);
} while (line != null);
""")
    assert any("while (line != null)" in b for b in rc._loop_body(lines, 1))


# ---------------------------------------------------------------------------
# driver: _loop_driven
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("header", "body", "routine", "driven"), [
    # infinite: driven iff the body pulls
    ("while True:", "data = sock.recv(10)", "", True),
    ("while True:", "j = s.find(',', i)", "", False),
    ("for {", "n, err := conn.Read(buf)", "", True),
    ("loop {", "let n = stream.read(&mut buf).unwrap();", "", True),
    # counted range: the bound must reach peer data
    ("for _ in range(count):", "", "count = int(request.args['count'])", True),
    ("for i in range(n):", "", "", False),
    ("for _ in range(MAX_MESSAGES):", "", "", False),
    # C-style
    ("for (let i = 0; i < n; i++) {", "", "", False),
    # iteration: materialiser, pull in the source, chan, binding, fallback, wrapper
    ("for name in blob.split(','):", "", "", False),
    ("for k in cfg.items():", "", "", False),
    ("for chunk in iter(lambda: s.recv(4096), b''):", "", "", True),
    ("for event in pubsub.listen():", "", "", True),
    ("for msg := range ch {", "", "ch := make(chan []byte)", True),
    ("for line in reader:", "", "reader = io.StringIO(text)", False),
    ("for line in conn_lines:", "", "conn_lines = sock.makefile('r')", True),
    ("for (const h of hosts) {", "", "const hosts = await resolveListenHosts(spec)", False),
    ("for msg in client_sock:", "", "", True),
    ("for ws_url in ws_urls:", "", "", False),
    ("for _, m := range req.Messages {", "", "", False),
    ("for line in self.rfile:", "", "", True),
    ("for line in urlopen(url):", "", "", True),
    # other while: header pull, in-memory receiver, limit-bounded header
    ("while ((line = reader.readLine()) != null) {", "", "", True),
    ("while ((line = br.readLine()) != null) {", "", "br = new BufferedReader(new StringReader(text))", False),
    ("while received < content_length:", "data = sock.recv(10)", "", True),
    ("while (n > 0) {", "n = in.read(buf);", "", True),
    ("while len(out) < MAX_ITEMS:", "data = sock.recv(10)", "", False),
])
def test_loop_driven(header: str, body: str, routine: str, driven: bool) -> None:
    assert rc._loop_driven(header, body, routine) is driven


@pytest.mark.parametrize("text", [
    "sock.recv(4096)", "await websocket.receive_text()", "s.recv_into(buf)", "fgets($h)",
    "reader.readLine()", "stream.read(buf)", "in.read(buf, 0, n)", "await reader.read()",
    "sc.nextLine()", "sc.hasNextLine()", "q.get()", "q.get(timeout=1)", "q.get_nowait()",
    "msg := <-ch", "input()", "sock.gets", "async for x in resp.aiter_lines()",
    "r.ReadLineAsync()", "stream.ReadAsync(buf, 0, n)", "conn.Read(buf)",
])
def test_pull_roles(text: str) -> None:
    assert rc._pulls(text)


@pytest.mark.parametrize("text", [
    "fs.readdirSync(dir)",            # case-sensitive suffix: not a pull
    "cp.read(paths)",                 # ConfigParser.read(paths): not a buffer/size argument
    "visitor.accept(v)",
    "path.read_text()",               # a materialiser, not a pull
    "await resolveListenHosts(spec)",  # a pull verb inside a longer identifier
    "d.get('k')",
])
def test_not_pull_roles(text: str) -> None:
    assert not rc._pulls(text)


# ---------------------------------------------------------------------------
# cap: _capped
# ---------------------------------------------------------------------------

def _cap(acc: str, src: str, routine: str = "") -> bool:
    rows = _lines(src)
    return rc._capped(acc, rows[0], [rows[0], *rows[1:]], routine)


@pytest.mark.parametrize(("acc", "src"), [
    ("buf", "while True:\n    c = sock.recv(10)\n    if not c or len(buf) >= MAX_FRAMES:\n        break"),
    ("chunks", "while True:\n    total += len(c)\n    if total > limit_bytes:\n        raise ValueError()"),
    ("frames", "while True:\n    if len(frames) == MAXIMUM_FRAMES:\n        break"),
    ("chunks", "for await (const c of s) {\n  size += c.length;\n  if (size > highWaterMark) throw e;"),
    ("parts", "while (true) {\n  seen += value.byteLength;\n  if (seen > maxBytes) {\n"
              "    try { await r.cancel() } catch {}\n    throw new Error('x');\n  }"),
    ("window", "while True:\n    window.append(b)\n    del window[:-100]"),
    ("sniff", "res.on('data', (c) => {\n  if (sniffLen < 16384) {\n    sniff.push(c);\n"
              "    sniffLen += c.length;\n  }"),
])
def test_capped_accepts(acc: str, src: str) -> None:
    assert _cap(acc, src)


def test_capped_by_construction_and_cap_wrappers() -> None:
    assert rc._capped("recent", "while True:", ["while True:"], "recent = deque(maxlen=500)")
    assert rc._capped("out", "for line in itertools.islice(sock_file, MAX_LINES):",
                      ["for line in itertools.islice(sock_file, MAX_LINES):"], "")
    assert rc._capped("lines", "for sc.Scan() {", ["for sc.Scan() {"],
                      "sc := bufio.NewScanner(io.LimitReader(conn, 1<<20))")


@pytest.mark.parametrize(("acc", "src"), [
    ("chunks", "while True:\n    attempts += 1\n    if attempts > RETRY_CEILING:\n        break"),
    ("lines", "while True:\n    if len(lines) > 0 and line == lines[-1]:\n        continue"),
    ("frames", "while True:\n    if len(frame) > MAX_FRAME:\n        raise ValueError()"),
    ("parts", "while True:\n    if len(other) > MAX_PARTS:\n        break"),
    ("out", "while True:\n    if i < n:\n        break"),
])
def test_capped_rejects(acc: str, src: str) -> None:
    assert not _cap(acc, src)


# ---------------------------------------------------------------------------
# input-event callback
# ---------------------------------------------------------------------------

def test_input_callback_opener_own_line_and_enclosing() -> None:
    lines = _lines("""
function f(req) {
  req.on('data', (c) => chunks.push(c));
  req.on("data", (chunk) => {
    parts.push(chunk);
  });
  req.on('end', () => {
    done.push(1);
  });
}
""")
    assert rc._input_callback_opener(lines, 2) == 2
    assert rc._input_callback_opener(lines, 4) == 3
    assert rc._input_callback_opener(lines, 7) is None


def test_callback_sink_is_judged_like_a_loop_body() -> None:
    capped = """
function f(req, maxSize) {
  req.on("data", (chunk) => {
    size += chunk.length;
    if (size > maxSize) {
      req.destroy();
      return;
    }
    parts.push(chunk);
  });
}
"""
    uncapped = """
function f(req) {
  req.on("data", (chunk) => parts.push(chunk));
}
"""
    assert _alloc("a.ts", capped) == []
    assert _alloc("a.ts", uncapped) == [2]


# ---------------------------------------------------------------------------
# entry point: the Go make arm and SIZE_LIMIT
# ---------------------------------------------------------------------------

def test_unbounded_alloc_patterns_is_the_go_make_arm_only() -> None:
    assert len(rc.UNBOUNDED_ALLOC_PATTERNS) == 1
    assert rc.UNBOUNDED_ALLOC_PATTERNS[0].search("items := make([]string, 0)")
    assert not hasattr(rc, "_py_append_is_in_a_loop")


def test_size_limit_applies_to_the_go_arm_over_stripped_context() -> None:
    capped = "func f() {\n    max_size := 100\n    items := make([]string, 0)\n}"
    comment = "func f() {\n    // no limit here yet\n    items := make([]string, 0)\n}"
    assert _alloc("a.go", capped) == []
    assert _alloc("a.go", comment) == [3]


def test_size_limit_word_in_a_comment_no_longer_silences_accumulation() -> None:
    src = """
def f(conn):
    frames = []
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        # TODO: there is no limit here yet
        frames.append(chunk)
"""
    assert _alloc("a.py", src) == [8]


def test_every_looked_at_line_is_capped() -> None:
    long_tail = "x" * (MAX_SCAN_CHARS * 4)
    assert len(rc.stripped_code("out.append(v)  # " + long_tail)) <= MAX_SCAN_CHARS
    assert "MAX_SCAN_CHARS" in inspect.getsource(rc.stripped_code)

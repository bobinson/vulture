# Feature 0087 — per-line expectations, VALUE-ERROR languages

Scope: `go_handlers.go` (work-order step 11) and `rs_handlers.rs` (step 12).
The exception-language fixtures are documented separately; this file is kept
apart so the two arms can be edited without write conflicts.

Tables generated from the in-file markers. **The fixtures are the source of
truth** — if this document and a marker disagree, the marker wins and this
document is stale. Regenerate rather than hand-edit.

---

## 0. How a test must read these files

### The marker grammar

Markers are bare. No prose follows the verdict:

```go
if err != nil { // EXPECT: finding
```

**That is deliberate and it is the one rule not to relax.** The detector is
line-based, and for the Go arm everything after the opening `{` — the trailing
comment included — is treated as the beginning of the handler body
(`header_tail = line.split("{", 1)[1]`). An inline reason such as
`-- propagates: wrap-and-return` puts the tokens `return`, `err`, `log`,
`panic` and `continue` inside the exact text `_GO_PROPAGATES`, `_GO_LOG` and
`_GO_EXCUSED` are matched against, and the fixture starts testing its own
comments. The reason for every line lives in the tables below, keyed by line
number.

A marker counts only when it TRAILS code on the same line:

```python
MARK = re.compile(r"//\s*EXPECT:\s*(finding|clean|deferred)\s*$")
m = MARK.search(line)
if m and line[: m.start()].strip() and not line.lstrip().startswith("//"):
    ...   # a real marker
```

The `line[: m.start()].strip()` guard is required, not cosmetic: each fixture's
header block spells the three marker words out in prose to document the
contract, and a naive `search` collects those doc lines as sites.

### The marker sits on the SITE line, never on the body line

The detector anchors a row on the handler header — `if err != nil {`,
`if let Err(..) = ..`, `Err(e) =>` — so a `clean` marker parked on the logging
call one line below asserts nothing: the row lands on the header and the
assertion misses it entirely. Four such placements were found and corrected
during verification of this file. Keep new cases on the header.

### The three populations

| marker | meaning | assertion |
|---|---|---|
| `finding` | the arm MUST emit a CWE-778 row anchored on this line | `line in reported` |
| `clean` | the arm MUST NOT emit a row on this line | `line not in reported` |
| `deferred` | outcome deliberately UNSPECIFIED by the 0087 plan | excluded from BOTH populations |

Unmarked code lines are implicitly clean, so the strict form is

```python
assert reported - deferred == finding
```

which catches a spurious row on scaffolding (imports, struct definitions, the
`Store` helper methods) as well as a missed one.

### Fixture location trap

Both files live under `agents/cwe/tests/`, `_TEST_DIRS` contains `tests`, so
`is_test_file()` is True and `_should_scan` drops them (`file_scanner.py`
:763,781). A test that calls `check_insufficient_logging` on the fixture
directory in place gets **zero findings and passes vacuously**. Either call the
arm function / `_scan_file` directly, or copy the tree to a `tmp_path` outside
any test-named directory first. Every measurement in §3 used the copy route.

### Non-vacuity floors

Assert the population before asserting anything about it. Floors, not
equalities — a later step may legitimately add cases:

```python
assert len(go_finding_lines) >= 13, "go fixture markers lost; test is vacuous"
assert len(go_clean_lines)   >= 25
assert len(rs_finding_lines) >= 11, "rust fixture markers lost; test is vacuous"
assert len(rs_clean_lines)   >= 24
assert len(reported_on_go)   >= 13   # gates step 11
assert len(reported_on_rs)   >= 11   # gates step 12
```

The last two are the ones that fail today (§3), and are the point of the
fixtures.

---

## 1. `go_handlers.go` — Go value-error arm (step 11)

788 non-test `if err != nil {` sites were brace-matched in the plan's census
(§1). 554 propagate and 72 log; only three body classes are defects. The
fixture is built to that census, one section per class, and every gated site
names its error variable literally `err` because that is the spelling the
census measured.

No authentication or authorization keyword appears anywhere in the file, in
code or in prose, so every row reported on it is attributable to the Go arm and
never to `auth_decision`.

### 1.1 MUST FIND (13)

| line | site | why |
|---|---|---|
| 230 | `if err := h.store.Save(r.Context(), req.Record); err != nil {` | swallow class 1: bare return, the client gets 202 and nothing anywhere records the failure |
| 239 | `if _, err := io.Copy(io.Discard, resp.Body); err != nil {` | swallow class 1 on the inline-assign form |
| 253 | `if err != nil {` | swallow class 2: continue, the skipped file leaves no trace |
| 258 | `if err := json.Unmarshal(raw, &rec); err != nil {` | swallow class 2: continue on the inline-assign form |
| 277 | `if err != nil {` | swallow class 2: break ends the loop and discards the reason |
| 293 | `if err != nil {` | swallow class 3: silent fallback, a malformed setting is indistinguishable from an absent one |
| 309 | `if _, err := s.Load(ctx, key); err != nil {` | swallow class 3: `fmt.Errorf(...).Error()` is string formatting, not propagation and not a record |
| 317 | `if err != nil {` | swallow class 3: `err.Error()` stored on a struct field is not a facility call |
| 323 | `if err != nil {` | swallow class 3: the status flag is flipped and nothing else happens |
| 331 | `if err := conn.SetDeadline(at); err != nil {` | empty handler body |
| 340 | `if err != nil && !errors.Is(err, io.EOF) {` | swallow class 3 on the compound condition form |
| 375 | `if err = s.db.PingContext(ctx); err != nil {` | swallow class 3: assigning nil to the named result destroys the error in place |
| 478 | `if _, err := s.db.ExecContext(ctx, "UPDATE records SET stale = true WHERE id = $1", id); err ...` | scope test: the only facility call nearby belongs to the NEXT function |

Class coverage — swallow class 1 (`return` without the error): 230, 239.
Class 2 (`continue` / `break`): 253, 258, 277. Class 3
(non-terminating): 293, 309, 317, 323, 340, 375.
Empty body: 331. Scope test: 478.

Site-shape coverage — plain `if err != nil {`: 253, 277, 293, 317,
323. Inline-assign `if x, err := f(); err != nil {`: 230, 239, 258,
309, 331, 478. Compound condition: 340. Named return: 375.

### 1.2 MUST NOT FIND (25)

| line | site | why |
|---|---|---|
| 114 | `if errors.Is(err, sql.ErrNoRows) {` | errors.Is is a classification branch, not a handler site |
| 117 | `if err != nil {` | propagates: wrap-and-return, the single most common Go shape |
| 126 | `if err != nil {` | propagates: bare return of the error value |
| 131 | `if err != nil {` | propagates: wrap-and-return |
| 135 | `if err := tx.Commit(); err != nil {` | propagates: errors.New on the inline-assign form |
| 149 | `if err != nil {` | stdlib facility on the body line |
| 155 | `if err != nil {` | structured stdlib facility (0087 B6 added this pattern) |
| 165 | `if _, err := s.Load(ctx, id); err != nil {` | zap through a receiver field |
| 173 | `if _, err := s.db.ExecContext(ctx, "VACUUM ANALYZE records"); err != nil {` | logrus |
| 180 | `if _, err := s.db.ExecContext(ctx, "CHECKPOINT"); err != nil {` | zerolog |
| 193 | `if _, err := s.db.ExecContext(ctx, "DELETE FROM records WHERE payload IS NULL"); err != nil {` | logrus package-level method |
| 200 | `if _, err := s.db.ExecContext(ctx, "CLUSTER records"); err != nil {` | zerolog through a receiver field, plain method |
| 211 | `if _, err := s.db.ExecContext(ctx, "UPDATE records SET updated_at = now() WHERE id = $1", id)...` | B1 guard: the whole handler, record included, is on the header line |
| 262 | `if err := s.Save(ctx, rec); err != nil {` | propagation is not available here, but the failure is recorded before continuing |
| 354 | `if _, err := s.db.ExecContext(ctx, ddl); err != nil {` | panic is CWE-248, not CWE-778 |
| 362 | `if err != nil {` | the process terminates; CWE-248, not CWE-778 |
| 383 | `if err = s.db.Close(); err != nil {` | propagates through the named result |
| 388 | `if err != nil {` | propagates: wrap-and-return |
| 413 | `rec, ok := cache[key]` | comma-ok is a presence test, `ok` is not an error |
| 414 | `if !ok {` | comma-ok branch, no error value exists to record |
| 424 | `if err == nil {` | success path, not a handler site |
| 441 | `_ = enc.Encode(rec)` | `_ =` discard, out of scope for 0087 (D-drop-3, follow-up 0087-F1) |
| 448 | `if err != nil {` | propagation is unavailable, but the failure is recorded |
| 452 | `defer rows.Close()` | deferred Close discard, out of scope for 0087 (D-drop-3, follow-up 0087-F1) |
| 456 | `if err := rows.Scan(&n); err != nil {` | propagation is unavailable, but the failure is recorded |

### 1.3 DEFERRED (2) — excluded from both populations

| line | site | why |
|---|---|---|
| 225 | `if err := json.NewDecoder(r.Body).Decode(&req); err != nil {` | writes an HTTP error response and returns, no record (D-drop-4, follow-up 0087-F2) |
| 401 | `if err = s.db.PingContext(ctx); err != nil {` | naked return under a named result propagates; known line-local precision limit |

Line 225 is the HTTP-error-response class (D-drop-4 /
follow-up 0087-F2): real, but deciding it needs one-hop callee resolution.
Line 401 is a naked `return` under a named result, which
genuinely propagates — a line-local class-1 rule cannot see the function
signature and will report it. Neither is gated, so an implementation may report
them or not without failing the fixture. Both are reported today.

### 1.4 The collision guards, and why they are load-bearing

**`fmt.Errorf` (line 309).** The body is
`s.lastFailure = fmt.Errorf("refresh %s: %w", key, err).Error()`. A Go
propagation pattern written as a bare `fmt\.Errorf` — rather than
`return\s+.*fmt\.Errorf` — excuses it. Nothing is forwarded: the wrapped error
is immediately flattened to a string and assigned to a field.

**`err.Error()` (lines 309, 317).** A Go log pattern written as a bare
`\.Error\(` collides with both `fmt.Errorf(` and `err.Error()`. Plan §3.3
requires a facility-shaped receiver (`log|slog|logger|zap|logrus|zerolog`)
before the method for exactly this reason, and these two lines are the gated
statement of that requirement.

**Builder vs. plain method (173, 180 vs. 193, 200).**
`Vacuum` and `Checkpoint` use each library's documented fluent builder
(`logrus.WithError(err).Warn`, `zerolog.Ctx(ctx).Error().Err(err).Msg`);
`Prune` and `Compact` use the plain package-level or receiver method. Both
spellings are pinned so that a D3 set widened only far enough to satisfy the
plain form still fails the fixture — which is exactly what happens today
(§3.1).

### 1.5 The scope test (line 478)

`collect_handler_body` returns the next five non-blank lines within ten raw
lines and tracks neither brace depth nor indentation, so the `slog.Info` call
in `sweepReport` — `markStale`'s successor — lands inside `markStale`'s
collected body and silently excuses it. Counting from the header: `return`,
`}`, `}`, the `func` line, then the `slog` call, the fifth non-blank line.
`collect_scoped_body` (plan §3.5) must stop at the closing brace of the `if`.

**Do not insert a comment or a blank-separated declaration between `markStale`
and `sweepReport`.** It changes which line is fifth and neuters the test.

---

## 2. `rs_handlers.rs` — Rust value-error arm (step 12)

Three site shapes ship: `if let Err(..)`, `match .. { Err(e) => .. }`, and
statement-position `expr.ok();`. Everything else in the Rust error surface is
excluded by name in D-drop-2 and plan §9, and the exclusions carry more fixture
weight than the sites do — they are where this arm can do damage.

Like the Go fixture, the file contains no authentication or authorization
keyword and no token the brace/`catch` family could match, so a count on it is
unambiguous.

### 2.1 MUST FIND (11)

| line | site | why |
|---|---|---|
| 203 | `if let Err(e) = fs::remove_file(&path) {` | empty `if let Err` body: the failure leaves no trace at all |
| 210 | `if let Err(_e) = fs::remove_file(self.root.join(format!("{id}.json"))) {` | binding discarded with `_e`; body only mutates a counter |
| 225 | `if let Err(e) = self.load(id) {` | `e.to_string()` onto a field is a Display conversion, not a record |
| 238 | `Err(e) => DEFAULT_TIMEOUT_SECONDS,` | silent fallback; a malformed setting is indistinguishable from an absent one |
| 253 | `Err(e) => Vec::new(),` | the arm binds the error and drops it; the caller cannot distinguish empty from failed |
| 261 | `Err(e) => return 0,` | returns a plausible zero; the reason is discarded |
| 270 | `Err(e) => (),` | `Err(e) => ()`, the explicit do-nothing arm named in the plan fixture list |
| 282 | `Err(e) => continue,` | `continue` on the error arm; the skipped record leaves no trace |
| 307 | `out.flush().ok();` | statement-position `.ok();` discards the error and nothing else |
| 312 | `fs::remove_dir_all(root.join("scratch")).ok();` | statement-position `.ok();` on a filesystem mutation |
| 414 | `if let Err(e) = fs::rename(self.root.join(id), self.root.join("quarantine").join(id)) {` | scope test: the only facility call nearby belongs to the NEXT function |

Shape coverage — `if let Err(..)`: 203, 210, 225, 414.
`match` error arm: 238, 253, 261, 270, 282.
Statement-position `.ok();`: 307, 312.

### 2.2 MUST NOT FIND (24)

| line | site | why |
|---|---|---|
| 106 | `let raw = fs::read(&path)?;` | `?` is the propagation operator (D-drop-2), never a site |
| 107 | `let rec: Record = serde_json::from_slice(&raw)?;` | `?` on a second fallible call, same reason |
| 113 | `fs::create_dir_all(&self.root)?;` | `?` propagates |
| 114 | `let encoded = serde_json::to_vec(rec)?;` | `?` propagates |
| 116 | `let mut file = File::create(&path)?;` | `?` propagates |
| 117 | `file.write_all(&encoded)?;` | `?` propagates |
| 125 | `fs::rename(&src, &dst).map_err(StoreError::Io)?;` | `map_err(..)?` is still propagation, not a handler |
| 133 | `None => Err(StoreError::NotFound(id.to_string())),` | constructs and returns the error; the caller receives it |
| 154 | `if let Err(e) = self.load(id) {` | `log::error!` on the body line records the failure |
| 164 | `Err(e) => {` | `tracing::error!` inside the match arm records the failure |
| 177 | `if let Err(e) = fs::write(&path, b"") { log::warn!("touch {id}: {e}"); }` | B1 guard: header line carries the record call |
| 183 | `if let Err(e) = self.load(id) {` | delegates to a named error-handling routine (`_body_delegates`) |
| 285 | `Err(e) => {` | recorded on the next line, then skipped |
| 317 | `let text = fs::read_to_string(path.with_extension("meta")).ok();` | EXPRESSION position: the Option is bound and returned, not discarded |
| 323 | `fs::metadata(path.with_extension("meta")).ok().is_some()` | EXPRESSION position: the Option is consumed by `is_some` |
| 336 | `serde_json::from_str(raw).unwrap()` | `.unwrap()` panics: CWE-248, not CWE-778 (criterion 7) |
| 341 | `let raw = std::env::var("STORE_ROOT").expect("STORE_ROOT must be set");` | `.expect()` panics: CWE-248, not CWE-778 (criterion 7) |
| 349 | `.expect("system clock before the epoch")` | `.expect()` on the canonical infallible-in-practice call |
| 364 | `iter.next().unwrap().clone()` | `Option::unwrap`, not `Result`: undecidable line-locally (D-drop-2) |
| 369 | `path.file_stem().expect("record path has a stem").to_string_lossy().into_owned()` | `Option::expect`, no error value exists |
| 374 | `cache.get(id)` | an Option lookup is a presence test, not an error site |
| 385 | `let _ = out.flush();` | `let _ = ..` discard, out of scope for 0087 (plan §9) |
| 390 | `raw.parse::<u32>().unwrap_or_default()` | `unwrap_or_default` is undecidable Result/Option, out of scope (plan §9) |
| 395 | `raw.parse::<usize>().unwrap_or(MAX_SWEEP_BATCH)` | `unwrap_or` supplies a deliberate default; out of scope |

### 2.3 Acceptance criterion 7 — the three named exclusions

Criterion 7 requires a fixture case for each of `?`, `.unwrap()` and
`.expect()`, and requires that none produces a CWE-778 row:

| exclusion | lines | why |
|---|---|---|
| `?` | 106, 107, 113, 114, 116, 117, 125 | The propagation operator. Enumerating it makes almost every line of a fallible function a site and drives any Rust repo's D1a score to zero. |
| `.unwrap()` on `Result` | 336 | Panics: CWE-248, a different weakness. |
| `.expect()` on `Result` | 341, 349 | The identical class. The LLD guarded only `.unwrap()`. |
| `.unwrap()` / `.expect()` on `Option` | 364, 369 | The stronger argument: `iter.next().unwrap()` has no error value in existence, and no line-local rule can tell it from `parse().unwrap()`. |

All eleven pass today.

### 2.4 `.ok()` — statement position vs. expression position

`Result::ok()` converts `Result<T, E>` into `Option<T>` and discards `E`. The
distinction the arm must make is the trailing `;` with no binding:

| position | lines | expectation |
|---|---|---|
| statement — `out.flush().ok();` | 307, 312 | **finding**: the expression exists only to throw the error away |
| expression — `let x = f().ok();`, `f().ok().is_some()` | 317, 323 | **clean**: the `Option` is bound or consumed, so nothing is discarded |

A rule matching `\.ok\(\)` without the statement anchor turns 317 and 323 into
false positives, which is why both spellings are gated.

### 2.5 Out of scope (plan §9), and must stay that way

`let _ = f();` (385), `.unwrap_or_default()` (390) and `.unwrap_or(..)` (395)
are undecidable line-locally between `Result` and `Option` and are named in
plan §9 as things this skill will not detect. A row on any of them is a
regression against the stated scope, not extra coverage. All three pass today.

### 2.6 Rust D3 note — confirmed by measurement

The shipped `_LOG_CALL` alternation carries `\btracing::` but its Rust-relevant
`log` branch is `\blog\.` — a **dot**. Rust spells it `log::error!`, with a path
separator and a bang, so `log::error!` does **not** match:

```
_LOG_CALL.search('log::error!("x");')  -> None
_LOG_CALL.search('log.error("x");')    -> match
```

Lines 154, 177 and 285 are the gated statement of the plan §3.3 union
requirement, and all three are false-positive rows today (§3.2).

---

## 3. Verified state at the time of writing

Both fixtures were copied to a directory outside any test-named path and passed
through `check_insufficient_logging` with shipped defaults. The skill is under
active development, so treat this section as a dated snapshot; §1 and §2 are
the contract and do not move with it.

| file | markers `finding` | reported | missed | spurious (row on a `clean` line) | rows on unmarked lines |
|---|---|---|---|---|---|
| `go_handlers.go` | 13 | 13 | 4 | 2 | 0 |
| `rs_handlers.rs` | 11 | 13 | 2 | 4 | 0 |

Neither file produces a row on an unmarked line, so no accidental population is
hiding in the scaffolding and every number above is attributable to a marked
case. Both `deferred` Go lines are currently reported, which the contract
permits.

Every cause below was isolated by matching the pattern against the exact
fixture line, not inferred from the row count.

### 3.1 Go — four missed, two spurious

| line | state | cause |
|---|---|---|
| 309 | missed | `_GO_CAPTURED` matches the body `s.lastFailure = fmt.Errorf(..).Error()` and excuses it as "captured into a variable for a later report". Nothing here is reported later: the value is flattened to a string on a struct field and never read by a facility. The excusal needs a narrower target than "an assignment whose right-hand side mentions err" |
| 317 | missed | same excusal on `h.status.Detail = err.Error()` |
| 331 | missed | empty handler body (`setDeadline`) — `_scan_go_error_check` returns early on `if not stripped`, so the empty-body case (plan §7, `go/k.go`: "empty body (FLAG)") can never fire |
| 340 | missed | compound condition — `_GO_SITE` anchors `!= nil\s{0,4}\{`, so `if err != nil && !errors.Is(err, io.EOF) {` is not recognised as a site at all. The plan lists the compound form in the Go site set |
| 173 | spurious | `logrus.WithError(err).Warn("vacuum skipped")` — `_GO_LOG` requires a facility receiver followed IMMEDIATELY by a level method, and logrus's documented builder puts `WithError` in between |
| 180 | spurious | `zerolog.Ctx(ctx).Error().Err(err).Msg("checkpoint failed")` — same shape, `Ctx` in between. Both are the canonical spelling for their library, and the plain-method cases at 193 and 200 pass, so the D3 set is exactly one builder-hop short |

A previous run of this fixture also missed every inline-assign site
(`if x, err := f(); err != nil`) because `_GO_CAPTURED` was matched against the
site's own header line, where `err := f(); … err` reads as a capture. That is
fixed — `_scan_go_error_check` now matches only `line.split("{", 1)[1]` — and
the fixture's six inline-assign findings pass. The case is recorded here so the
regression is recognisable if it returns.

### 3.2 Rust — two missed, four spurious

| line | state | cause |
|---|---|---|
| 307 | missed | `_RUST_OK_DISCARD` ends in `\s*;\s{0,4}$` and the line carries the trailing marker. `out.flush().ok();` matches once the comment is removed and not before. This is plan defect **B4 in Rust form** — the same `$`-anchor-versus-trailing-comment class that made 18 of vulture's `except` headers unreachable — and real Rust writes `out.flush().ok(); // best effort`, so it is a genuine defect and not an artefact of the marker |
| 312 | missed | a second, independent defect: `_RUST_OK_DISCARD` matches the receiver with the character class `[\w.()\[\]:&*?]`, which admits no quote, comma or space. `fs::remove_dir_all(root.join("scratch")).ok();` fails on the string literal even with the comment stripped. Any `.ok();` whose receiver takes a string, a multi-argument call or a closure is invisible |
| 154, 177, 285 | spurious | the handler records the failure with `log::error!` / `log::warn!` and is reported anyway — §2.6, the `log::` path-separator spelling. 177 is additionally the B1 single-line shape (whole handler on the header line), but the operative cause is the same log spelling, so fixing B1 alone will not clear it |
| 183 | spurious | the handler delegates to `self.report_error(&e)`. `_ERROR_DELEGATE` requires a CamelCase name ending in `Error`/`Err`/`Exception`/`Failure` **and** a bare error identifier as the argument; Rust's convention is snake_case and a borrow, so both halves miss. Verified: `_ERROR_DELEGATE.search("self.report_error(&e);")` -> `None` |

All four spurious rows sit on a handler that demonstrably records or forwards
the error, and both missed rows sit on a shape the plan lists in the Rust site
set. None of the six is a fixture error.

Line 307's cause and 312's cause are separable on purpose: 307 is a clean
receiver defeated only by the trailing comment, 312 is a receiver the character
class cannot express at all. An anchor fix alone turns 307 green and leaves 312
red, which is the intended signal — do not read a partial pass as done.

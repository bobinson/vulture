# CWE-778 exception-family fixtures — ground truth

Feature 0087. This directory holds one fixture per language for the
**exception family** of CWE-778 sites (`except` / `catch` / `rescue` /
`case` arms / suppression operators). Every marked site below is ground
truth for the recall and precision tests: the site line, the verdict the
rewritten detector must produce, and why.

This file covers the eleven `*_handlers.*` fixtures of the exception
family only. `go_handlers.go` and `rs_handlers.rs` in this directory are
the **value-error family** (Go / Rust arms, work-order steps 11-12) and
are documented in `EXPECTATIONS_VALUE.md`, which uses a marker contract of
its own (trailing `// EXPECT:` with no `id=`, plus a third `deferred`
verdict). Nothing here should be read as ground truth for those two.

## Marker contract

A marked site is a line carrying both `EXPECT: finding` / `EXPECT: clean`
and `id=<identifier>`, in the language's own comment syntax. Resolution
of a marker to its **site line** is mechanical:

1. If anything other than whitespace and a comment token precedes
   `EXPECT:` on that line, the marker is *attached*: the site line **is**
   the marker line. (Used for `} catch (...) {` headers, where a comment
   line above would split the brace, and for one-line handlers.)
2. Otherwise the marker is *standalone*: skip the following comment lines
   that carry no `id=` (they are continuation prose), then skip blank
   lines; the first remaining line is the site line. (Used for Python,
   Ruby, Scala `case` arms and statement-position sites.)

Marker prose deliberately contains no authentication/authorisation
keyword, so the `auth_decision` arm cannot fire on a fixture and
contaminate the exception-family counts. Verified: today's run emits zero
`auth_decision` rows on every file here.

**Non-vacuity floors.** A test over these fixtures must assert a
population floor before asserting anything about it. Per-file floors are
the site counts in the summary table below; the whole-corpus floor is
**78 marked sites, 39 of them `finding` and 39 `clean`**.

## Summary

| fixture | language | sites | expect finding | expect clean | in today's extension gate |
|---|---|---|---|---|---|
| `py_handlers.py` | Python | 9 | 6 | 3 | yes |
| `ts_handlers.ts` | TypeScript | 9 | 5 | 4 | yes |
| `tsx_handlers.tsx` | TypeScript (TSX) | 5 | 2 | 3 | **no** |
| `java_handlers.java` | Java | 6 | 3 | 3 | yes |
| `cs_handlers.cs` | C# | 6 | 3 | 3 | yes |
| `cpp_handlers.cpp` | C++ | 6 | 3 | 3 | **no** |
| `kt_handlers.kt` | Kotlin | 7 | 4 | 3 | **no** |
| `php_handlers.php` | PHP | 8 | 3 | 5 | yes |
| `rb_handlers.rb` | Ruby | 8 | 3 | 5 | yes |
| `swift_handlers.swift` | Swift | 7 | 3 | 4 | **no** |
| `scala_handlers.scala` | Scala | 7 | 4 | 3 | **no** |

Every fixture carries the five shapes the family is defined by: a silent
swallow (finding), a handler that logs (clean), a **one-line handler that
logs on the header line** (clean — defect B1), a handler that re-throws or
propagates (clean), and a swallow whose *next function* logs (finding —
defect B2, the scope leak). Language-specific shapes are listed per file.

## Ground truth, per file

### `py_handlers.py` — Python

| id | line | shape | expect | why |
|---|---|---|---|---|
| `py_swallow_multi` | 36 | `except (A, B) as e:` + default return | **finding** | the parse failure is turned into a default manifest and nothing records it |
| `py_bare_except` | 51 | bare `except:` | **finding** | swallows every class, including `KeyboardInterrupt`, with no trace |
| `py_logs` | 64 | `except X as e:` whose body logs | **clean** | the body logs the exception |
| `py_header_line_log` | 75 | same-line body on the `except` header, and it logs | **clean** | the handler logs; the log call merely sits on the header line (defect B1) |
| `py_reraise` | 84 | `raise ... from exc` | **clean** | the error is wrapped and re-raised, so the caller still has the evidence |
| `py_scope_leak` | 95 | swallow immediately before a logging function | **finding** | defect B2: the nearest log call belongs to `purge_cache()`; a different function must not excuse this handler |
| `py_trailing_comment_header` | 116 | `except X:  # trailing comment` | **finding** | defect B4: a trailing comment on the header must not hide the swallow |
| `py_inline_pass` | 125 | `except KeyError: pass` | **finding** | same-line trivial body |
| `py_suppress` | 133 | `with contextlib.suppress(...)` | **finding** | `contextlib.suppress` discards the error with no record |

### `ts_handlers.ts` — TypeScript

| id | line | shape | expect | why |
|---|---|---|---|---|
| `ts_swallow` | 27 | `} catch (err) {` + `return null` | **finding** | the rejection is turned into `null` with no record |
| `ts_logs` | 35 | `} catch (err) {` whose body logs | **clean** | the body logs the error |
| `ts_header_line_log` | 43 | whole one-line handler, log call on the header | **clean** | defect B1: the handler logs, on the header line |
| `ts_rethrow` | 50 | `throw new ExportError(..., { cause: err })` | **clean** | wrapped and propagated |
| `ts_no_binding` | 59 | ES2019 `} catch {` (no binding) | **finding** | defect B5: the no-binding form is still a swallowing handler |
| `ts_scope_leak` | 67 | swallow immediately before a logging function | **finding** | defect B2: the nearby log call belongs to `reportManifestAge()` |
| `ts_promise_catch` | 81 | `.catch(() => null)` chain | **finding** | `.catch()` is an error handler and it discards |
| `ts_promise_catch_logs` | 88 | `.catch((err) => { logger.error(...) })` chain | **clean** | `.catch()` handler logs the rejection |
| `ts_then_onrejected` | 97 | `.then(ok, err)` with a discarding onRejected arm | **finding** | the onRejected arm discards the rejection |

### `tsx_handlers.tsx` — TypeScript (TSX)

| id | line | shape | expect | why |
|---|---|---|---|---|
| `tsx_swallow` | 36 | `} catch (err) {` in a `useEffect` loader | **finding** | the panel renders empty and nothing records why |
| `tsx_logs` | 50 | `} catch (err) {` whose body logs | **clean** | the body logs the error |
| `tsx_header_line_log` | 60 | whole one-line handler, log call on the header | **clean** | defect B1: the handler logs, on the header line |
| `tsx_rethrow` | 66 | `throw new ReportError(..., { cause: err })` | **clean** | propagated to the error boundary |
| `tsx_scope_leak` | 74 | swallow immediately before a logging callback | **finding** | defect B2: the nearby log call belongs to `onPanelRendered` |

### `java_handlers.java` — Java

| id | line | shape | expect | why |
|---|---|---|---|---|
| `java_multi_catch` | 44 | `catch (A \| B e) {` multi-catch | **finding** | returns `Optional.empty()` with no record |
| `java_try_with_resources_logs` | 57 | try-with-resources handler that logs (`LOG.error`) | **clean** | the body logs via the `LOG` alias (D3 must include `LOG.`) |
| `java_header_line_log` | 66 | whole one-line handler, `LOG.warn` on the header | **clean** | defect B1 + the `LOG.` alias gap |
| `java_rethrow` | 73 | `throw new UncheckedIOException(..., e)` | **clean** | wrapped and propagated |
| `java_scope_leak` | 81 | swallow immediately before a logging method | **finding** | defect B2: the nearby log call belongs to `recordExportSize` |
| `java_allman` | 96 | Allman brace: `catch (IOException e)` then `{` on the next line | **finding** | Allman brace style is still a swallowing handler |

### `cs_handlers.cs` — C#

| id | line | shape | expect | why |
|---|---|---|---|---|
| `cs_when_filter` | 49 | `catch (SqlException ex) when (ex.Number == 1205)` filter | **finding** | an exception filter still selects a handler, and this one swallows |
| `cs_logs` | 63 | `catch (IOException ex)` whose body logs (`_logger.LogError`) | **clean** | the body logs via `_logger.LogError` (D3 must include the `_log`/`_logger` aliases) |
| `cs_header_line_log` | 74 | whole one-line handler, `_logger.LogWarning` on the header | **clean** | defect B1 + the `_logger.` alias gap |
| `cs_rethrow` | 84 | `throw new InvalidOperationException(..., ex)` | **clean** | wrapped and propagated |
| `cs_scope_leak` | 96 | swallow immediately before a logging method | **finding** | defect B2: the nearby log call belongs to `RecordExportSize` |
| `cs_empty_no_variable` | 109 | `catch (InvalidOperationException) { }` — variable-less, empty | **finding** | completely empty handler |

### `cpp_handlers.cpp` — C++

| id | line | shape | expect | why |
|---|---|---|---|---|
| `cpp_catch_all` | 40 | `} catch (...) {` | **finding** | catch-all leaves a default-constructed cursor and no record |
| `cpp_logs` | 55 | by-const-ref handler that logs (`spdlog::error`) | **clean** | the body logs via `spdlog::error` (B6: `spdlog` missing from `_LOG_CALL`) |
| `cpp_header_line_log` | 64 | whole one-line handler, `syslog(LOG_ERR, ...)` on the header | **clean** | defect B1: `syslog(LOG_ERR, ...)` is recognised but sits on the header line |
| `cpp_rethrow` | 71 | `throw std::runtime_error(...)` | **clean** | wrapped and propagated |
| `cpp_scope_leak` | 81 | swallow immediately before a logging function | **finding** | defect B2: the nearby log call belongs to `RecordExportSize` |
| `cpp_swallow_by_value_default` | 97 | `} catch (const std::exception& e) {` + cleared buffer | **finding** | returns an empty document with no record |

### `kt_handlers.kt` — Kotlin

| id | line | shape | expect | why |
|---|---|---|---|---|
| `kt_swallow` | 27 | `} catch (e: IOException) {` + `null` | **finding** | returns `null` with no record |
| `kt_logs` | 35 | `} catch (e: IOException) {` whose body logs | **clean** | the body logs the throwable |
| `kt_header_line_log` | 43 | whole one-line handler, `logger.warn` on the header | **clean** | defect B1: the handler logs, on the header line |
| `kt_rethrow` | 50 | `throw IllegalStateException(..., e)` | **clean** | wrapped and propagated |
| `kt_scope_leak` | 58 | swallow immediately before a logging method | **finding** | defect B2: the nearby log call belongs to `recordExportSize` |
| `kt_run_catching` | 70 | `runCatching { ... }.getOrNull()` | **finding** | `runCatching { }.getOrNull()` discards the throwable |
| `kt_swallow_empty` | 77 | `} catch (e: SecurityException) {` with an empty body | **finding** | empty handler body |

### `php_handlers.php` — PHP

| id | line | shape | expect | why |
|---|---|---|---|---|
| `php_docblock_at_param` | 30 | `@param` inside a docblock — NOT an `@`-suppression site | **clean** | a docblock tag is not code; comments are stripped before the `@` rule runs |
| `php_union_catch` | 38 | `catch (A \| \B $e) {` union catch | **finding** | returns an empty cursor with no record |
| `php_laravel_log` | 47 | handler that logs via `Log::error` | **clean** | the body logs via `Log::error` (D3 must include Laravel `Log::`) |
| `php_header_line_log` | 56 | whole one-line handler, `syslog(LOG_ERR, ...)` on the header | **clean** | defect B1: `syslog(LOG_ERR, ...)` is recognised but sits on the header line |
| `php_rethrow` | 64 | `throw new RuntimeException(..., 0, $e)` | **clean** | wrapped and propagated |
| `php_report_delegate` | 73 | `report($e)` — framework delegate, not a log call | **clean** | `report($e)` hands the throwable to the framework handler (plan §3.3: delegate set, not log set) |
| `php_scope_leak` | 83 | swallow immediately before a logging method | **finding** | defect B2: the nearby log call belongs to `recordExportSize` |
| `php_at_suppression` | 98 | `@file_get_contents(...)` error-suppression operator | **finding** | the `@` operator discards the warning entirely |

`php_docblock_at_param` is a non-site: the `@` of a docblock tag
must not be read as PHP's error-suppression operator (plan §2 —
comments are stripped before the `@` rule runs).

### `rb_handlers.rb` — Ruby

| id | line | shape | expect | why |
|---|---|---|---|---|
| `rb_rescue_swallow` | 28 | `rescue A, B => e` + `{}` | **finding** | returns an empty cursor with no record |
| `rb_logs` | 35 | `rescue A, B => e` whose body logs | **clean** | the body logs the failure |
| `rb_modifier_logs` | 43 | modifier `expr rescue Rails.logger.warn(...)` | **clean** | B1 analogue: the modifier body IS the header line, and it logs |
| `rb_reraise` | 49 | `raise CursorMissing, ...` | **clean** | wrapped and re-raised |
| `rb_scope_leak` | 57 | swallow immediately before a logging method | **finding** | defect B2: the nearby log call belongs to `record_export_size` |
| `rb_modifier_nil` | 69 | modifier `expr rescue nil` | **finding** | modifier `rescue nil` collapses every StandardError |
| `rb_comment_rescue` | 74 | the keyword `rescue` inside a comment | **clean** | the keyword is inside a comment; comments must be stripped first |
| `rb_ensure` | 78 | `ensure` clause — cleanup, not a handler | **clean** | `ensure` is a cleanup clause, not an error handler — not a site at all |

`rb_ensure` and `rb_comment_rescue` are non-sites: an `ensure`
clause is cleanup, not a handler, and a keyword inside a comment
is not code.

### `swift_handlers.swift` — Swift

| id | line | shape | expect | why |
|---|---|---|---|---|
| `swift_swallow` | 39 | bare `} catch {` + `return nil` | **finding** | returns `nil` with no record |
| `swift_typed_catch_logs` | 48 | `} catch let error as EncodingError {` that logs | **clean** | the arm logs the error |
| `swift_catch_all_logs` | 50 | trailing bare `} catch {` arm that logs | **clean** | the catch-all arm logs the error |
| `swift_header_line_log` | 58 | whole one-line `do { } catch { os_log(...) }` | **clean** | defect B1: `os_log` is on the header line |
| `swift_rethrow` | 66 | `} catch let error as DecodingError {` + `throw` | **clean** | wrapped and propagated as `CursorError.unreadable` |
| `swift_scope_leak` | 75 | swallow immediately before a logging method | **finding** | defect B2: the nearby log call belongs to `recordExportSize` |
| `swift_try_optional` | 87 | `try?` collapsing the error to nil | **finding** | `try?` collapses the error to `nil` |

### `scala_handlers.scala` — Scala

| id | line | shape | expect | why |
|---|---|---|---|---|
| `scala_arm_parse` | 33 | `case _: JsonParseException =>` arm returning `Map.empty` | **finding** | this arm swallows; the sibling arm's log call must not excuse it (one site per `case` arm) |
| `scala_arm_io` | 35 | sibling `case e: IllegalArgumentException =>` arm that logs | **clean** | this arm logs |
| `scala_nonfatal_logs` | 45 | `case NonFatal(e) => logger.error(...)` on one line | **clean** | B1 analogue: the whole arm body, log call included, is on the `case` line |
| `scala_rethrow` | 52 | `case NonFatal(e) => throw new IllegalStateException(...)` | **clean** | wrapped and propagated |
| `scala_scope_leak` | 61 | `case NonFatal(e) => 0L` immediately before a logging method | **finding** | defect B2: the nearby log call belongs to `recordExportSize` |
| `scala_try_tooption` | 70 | `Try(...).toOption` | **finding** | `Try(...).toOption` discards the Throwable |
| `scala_arm_typed_swallow` | 77 | `case e: DateTimeParseException => None` | **finding** | returns `None` with no record |

Non-sites in this file, asserted by construction: the `catch {`
openers on lines 30, 42, 50, 58 and 74 are **not** sites — Scala
emits one site per `case` arm, never one per `catch` (plan §2).

## Current behaviour

Measured against the **shipped** skill as of `5886294`
(`git archive HEAD` snapshot of `agents/shared/shared` +
`agents/cwe/cwe_agent`, so a work-in-progress working tree cannot move
these numbers). Two probes:

* **end-to-end** — the fixtures are copied to a temp directory outside any
  `tests/`- or `fixtures/`-named path (both are excluded by
  `is_test_file` / `is_generated_file`, so a fixture scanned in place
  yields zero findings and looks like a broken arm), then
  `check_insufficient_logging()` is run over the copy. This is what the
  detector actually does today.
* **gate-bypassed** — `_scan_py_except` / `_scan_catch` /
  `_scan_auth_decision` are called line by line on every fixture
  regardless of extension, which separates the extension gate (defect B7)
  from the pattern behaviour underneath it.

Today's extension gate: `.cs`, `.go`, `.java`, `.js`, `.php`, `.py`, `.rb`, `.ts` — so `.tsx`, `.cpp`, `.kt`,
`.swift` and `.scala` are not scanned at all.

### `py_handlers.py`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `py_swallow_multi` | 36 | finding | reported | row | agrees with the expected verdict |
| `py_bare_except` | 51 | finding | reported | row | agrees with the expected verdict |
| `py_logs` | 64 | clean | silent | no row | agrees with the expected verdict |
| `py_header_line_log` | 75 | clean | silent | no row | silent, but only because `_PY_EXCEPT`'s `\s*$` anchor rejects a same-line body — the site is invisible, not excused |
| `py_reraise` | 84 | clean | silent | no row | agrees with the expected verdict |
| `py_scope_leak` | 95 | finding | **MISSED** | no row | B2: `collect_handler_body` walked into `purge_cache()` and found its `logger.info` |
| `py_trailing_comment_header` | 116 | finding | **MISSED** | no row | B4: `_PY_EXCEPT` rejects the trailing comment |
| `py_inline_pass` | 125 | finding | reported | row | agrees with the expected verdict |
| `py_suppress` | 133 | finding | **MISSED** | no row | no `contextlib.suppress` shape exists |

### `ts_handlers.ts`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `ts_swallow` | 27 | finding | reported | row | agrees with the expected verdict |
| `ts_logs` | 35 | clean | silent | no row | agrees with the expected verdict |
| `ts_header_line_log` | 43 | clean | **FALSE POSITIVE** | row | B1: `_body_has_logging` is passed `body` only, never the header-line text |
| `ts_rethrow` | 50 | clean | silent | no row | agrees with the expected verdict |
| `ts_no_binding` | 59 | finding | **MISSED** | no row | B5: `_CATCH_LINE` requires `catch (...)` |
| `ts_scope_leak` | 67 | finding | **MISSED** | no row | B2: excused by `reportManifestAge`'s `logger.info` |
| `ts_promise_catch` | 81 | finding | **MISSED** | no row | no promise-chain shape |
| `ts_promise_catch_logs` | 88 | clean | silent | no row | no promise-chain shape (right verdict, no mechanism) |
| `ts_then_onrejected` | 97 | finding | **MISSED** | no row | no promise-chain shape |

### `tsx_handlers.tsx`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `tsx_swallow` | 36 | finding | **MISSED** | row | B7 gate only: `.tsx` is unscanned; gate-bypassed the shape matches and it is reported |
| `tsx_logs` | 50 | clean | silent | no row | gate today; gate-bypassed `logger.` excuses it correctly |
| `tsx_header_line_log` | 60 | clean | silent | row | gate today; gate-bypassed it is a B1 FALSE POSITIVE |
| `tsx_rethrow` | 66 | clean | silent | no row | gate today; gate-bypassed the propagation rule excuses it correctly |
| `tsx_scope_leak` | 74 | finding | **MISSED** | no row | gate today, and still missed gate-bypassed — B2: excused by `onPanelRendered`'s `logger.debug` |

### `java_handlers.java`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `java_multi_catch` | 44 | finding | reported | row | agrees with the expected verdict |
| `java_try_with_resources_logs` | 57 | clean | **FALSE POSITIVE** | row | B6/D3: `_LOG_CALL` has `\blog\.` (lower-case) and cannot match the `LOG.` alias |
| `java_header_line_log` | 66 | clean | **FALSE POSITIVE** | row | B1 + the `LOG.` alias gap |
| `java_rethrow` | 73 | clean | silent | no row | agrees with the expected verdict |
| `java_scope_leak` | 81 | finding | reported | row | right verdict, wrong reason: `LOG.info` is unrecognised, so the B2 leak did not get the chance to excuse it |
| `java_allman` | 96 | finding | **MISSED** | no row | `_CATCH_LINE` requires `{` on the header line |

### `cs_handlers.cs`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `cs_when_filter` | 49 | finding | **MISSED** | no row | `_CATCH_LINE`'s `\)\s*\{` cannot cross the ` when (...)` filter, and C# Allman puts `{` on the next line anyway |
| `cs_logs` | 63 | clean | silent | no row | silent only because the Allman `{` makes the site invisible; `\blogger\.` cannot match `_logger.` either |
| `cs_header_line_log` | 74 | clean | **FALSE POSITIVE** | row | B1 + the `_logger.` alias gap |
| `cs_rethrow` | 84 | clean | silent | no row | silent because of the Allman shape, not because of the propagation rule |
| `cs_scope_leak` | 96 | finding | **MISSED** | no row | Allman shape: no site |
| `cs_empty_no_variable` | 109 | finding | reported | row | agrees with the expected verdict |

### `cpp_handlers.cpp`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `cpp_catch_all` | 40 | finding | **MISSED** | row | gate only: `.cpp` is unscanned; gate-bypassed `catch (...)` matches and it is reported |
| `cpp_logs` | 55 | clean | silent | row | gate today; gate-bypassed it is a FALSE POSITIVE — B6: `spdlog` is not in `_LOG_CALL` |
| `cpp_header_line_log` | 64 | clean | silent | row | gate today; gate-bypassed it is a FALSE POSITIVE — B1: `syslog`/`LOG_E` are recognised only inside the collected body |
| `cpp_rethrow` | 71 | clean | silent | no row | gate today; gate-bypassed the propagation rule excuses it correctly |
| `cpp_scope_leak` | 81 | finding | **MISSED** | row | gate today; gate-bypassed it is reported, but only because `spdlog::info` is unrecognised — fixing D3 without the collector turns this into a B2 miss |
| `cpp_swallow_by_value_default` | 97 | finding | **MISSED** | row | gate only; the parenthesised shape matches once `.cpp` is added |

### `kt_handlers.kt`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `kt_swallow` | 27 | finding | **MISSED** | row | gate only: `.kt` is unscanned; gate-bypassed the parenthesised shape matches |
| `kt_logs` | 35 | clean | silent | no row | gate today; gate-bypassed `logger.` excuses it correctly |
| `kt_header_line_log` | 43 | clean | silent | row | gate today; gate-bypassed it is a B1 FALSE POSITIVE |
| `kt_rethrow` | 50 | clean | silent | no row | gate today; gate-bypassed the propagation rule excuses it correctly |
| `kt_scope_leak` | 58 | finding | **MISSED** | no row | gate today, and still missed gate-bypassed — B2: excused by `recordExportSize`'s `logger.info` |
| `kt_run_catching` | 70 | finding | **MISSED** | no row | gate today, and no `runCatching` shape exists either |
| `kt_swallow_empty` | 77 | finding | **MISSED** | row | gate only; `_CATCH_EMPTY` matches once `.kt` is added |

### `php_handlers.php`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `php_docblock_at_param` | 30 | clean | silent | no row | agrees with the expected verdict |
| `php_union_catch` | 38 | finding | reported | row | agrees with the expected verdict |
| `php_laravel_log` | 47 | clean | **FALSE POSITIVE** | row | D3: Laravel `Log::` is not in `_LOG_CALL` |
| `php_header_line_log` | 56 | clean | **FALSE POSITIVE** | row | B1: `syslog(LOG_ERR, ...)` is recognised, but it is on the header line |
| `php_rethrow` | 64 | clean | silent | no row | agrees with the expected verdict |
| `php_report_delegate` | 73 | clean | **FALSE POSITIVE** | row | `report($e)` is not in `_ERROR_DELEGATE` (it requires an `...Error|...Exception|...Failure` name shape) |
| `php_scope_leak` | 83 | finding | reported | row | right verdict, wrong reason: `Log::info` is unrecognised |
| `php_at_suppression` | 98 | finding | **MISSED** | no row | no `@`-suppression shape |

### `rb_handlers.rb`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `rb_rescue_swallow` | 28 | finding | **MISSED** | no row | no `rescue` shape exists at all |
| `rb_logs` | 35 | clean | silent | no row | agrees with the expected verdict |
| `rb_modifier_logs` | 43 | clean | silent | no row | agrees with the expected verdict |
| `rb_reraise` | 49 | clean | silent | no row | agrees with the expected verdict |
| `rb_scope_leak` | 57 | finding | **MISSED** | no row | no `rescue` shape exists at all |
| `rb_modifier_nil` | 69 | finding | **MISSED** | no row | no modifier-`rescue` shape exists |
| `rb_comment_rescue` | 74 | clean | silent | no row | agrees with the expected verdict |
| `rb_ensure` | 78 | clean | silent | no row | agrees with the expected verdict |

### `swift_handlers.swift`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `swift_swallow` | 39 | finding | **MISSED** | no row | gate today, and still no row gate-bypassed: `_CATCH_LINE` cannot match parenthesis-less `catch {` (plan §10) |
| `swift_typed_catch_logs` | 48 | clean | silent | no row | gate today; no Swift shape exists gate-bypassed either, so the silence is absence, not an excusal |
| `swift_catch_all_logs` | 50 | clean | silent | no row | gate today; no Swift shape exists gate-bypassed either |
| `swift_header_line_log` | 58 | clean | silent | no row | gate today; no Swift shape exists gate-bypassed either |
| `swift_rethrow` | 66 | clean | silent | no row | gate today; no Swift shape exists gate-bypassed either |
| `swift_scope_leak` | 75 | finding | **MISSED** | no row | gate today, and no Swift shape gate-bypassed |
| `swift_try_optional` | 87 | finding | **MISSED** | no row | gate today, and no `try?` shape exists either |

### `scala_handlers.scala`

| id | line | expect | today (end-to-end) | today (gate-bypassed) | what today's code does |
|---|---|---|---|---|---|
| `scala_arm_parse` | 33 | finding | **MISSED** | no row | gate today, and still no row gate-bypassed: `_CATCH_LINE` cannot match a `case` arm (plan §10) |
| `scala_arm_io` | 35 | clean | silent | no row | gate today; no Scala shape exists gate-bypassed either, so the silence is absence, not an excusal |
| `scala_nonfatal_logs` | 45 | clean | silent | no row | gate today; no Scala shape exists gate-bypassed either |
| `scala_rethrow` | 52 | clean | silent | no row | gate today; no Scala shape exists gate-bypassed either |
| `scala_scope_leak` | 61 | finding | **MISSED** | no row | gate today, and no `case`-arm shape gate-bypassed |
| `scala_try_tooption` | 70 | finding | **MISSED** | no row | gate today, and no `Try(...).toOption` shape exists either |
| `scala_arm_typed_swallow` | 77 | finding | **MISSED** | no row | gate today, and no `case`-arm shape gate-bypassed |

### Delta, in one line

Across the 78 marked exception-family sites the shipped detector emits **16 rows**. 9 of them land on a site that should be reported; **7 are false positives** on sites that should be silent. **30 of the 39** expected findings are missed.

* recall **9/39 = 23%**
* precision **9/16 = 56%**
* the remaining 32 clean sites are silent, several of them for the wrong reason (no shape exists, or the extension is not scanned) — see the per-site notes

Grouped by cause:

* **extension gate (B7)** — `.tsx`, `.cpp`, `.kt`, `.swift`, `.scala`: 32 of the 78 sites never reach a pattern.
* **B1, header-line logging** — every `*_header_line_log` site in a *scanned* file is a
  false positive today (`ts`, `java`, `cs`, `php`). The same shape sits behind the gate in
  `cpp`, `kt`, `tsx`, and in `swift`/`scala` no shape exists to reach it at all.
* **B2, scope leak** — `collect_handler_body` walks into the next function:
  `py_scope_leak`, `ts_scope_leak`, `kt_scope_leak` and `tsx_scope_leak` are excused by a
  log call belonging to a *different* function. The `java`/`php`/`cpp` scope-leak sites are
  reported today **only** because their language's log alias (`LOG.`, `Log::`, `spdlog`) is
  unrecognised — fixing D3 without fixing the collector converts those three into misses.
* **B4 / B5** — `py_trailing_comment_header` and `ts_no_binding`, both invisible.
* **B6 / D3 log-alias gaps** — `LOG.`, `_logger.`, `Log::`, `spdlog`, and the missing
  `report($e)` delegate: four of the seven false positives are handlers that demonstrably
  log or delegate.
* **shapes that do not exist yet** — `contextlib.suppress`, `.catch()` / `.then(ok, err)`,
  `@`-suppression, `runCatching`, `try?`, `Try(...).toOption`, Ruby `rescue` in every form,
  Scala `case` arms, C# `when` filters, Allman braces.

Reproducing this section: copy the fixtures to a directory outside any `tests/`- or
`fixtures/`-named path, run `check_insufficient_logging()` over the copy, and compare each
row's `line_start` against the tables above; for the gate-bypassed column call
`_scan_py_except` / `_scan_catch` / `_scan_auth_decision` per line instead.

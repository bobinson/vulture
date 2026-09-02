"""0087 steps 8/10/11/12: per-language handler shapes.

Each arm is asserted BOTH ways. A test that only checks the positive case cannot
tell a working detector from one that fires on everything, and three of these
arms were caught over-matching exactly that way during development.
"""

import shutil
from pathlib import Path

import pytest

from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cwe778" / "langs"


@pytest.fixture(scope="module")
def scanned(tmp_path_factory: pytest.TempPathFactory) -> dict[str, set[int]]:
    """Scan the fixtures from a path the skill will actually look at.

    The skill deliberately skips anything under a `tests/` directory, so the
    committed fixtures are unreachable where they live. Copying them to a
    neutral directory exercises the real entry point instead of reaching past
    `_should_scan` into the internals, which would stop the test from noticing
    if the language gate ever dropped one of these extensions.
    """
    root = tmp_path_factory.mktemp("corpus") / "app"
    shutil.copytree(FIXTURES, root)
    res = check_insufficient_logging(str(root))
    out: dict[str, set[int]] = {}
    for f in res.get("findings", []):
        out.setdefault(Path(f["file_path"]).name, set()).add(f["line_start"])
    return out


def test_rust_reports_only_the_silent_arms(scanned) -> None:
    hits = scanned.get("swallow.rs", set())
    assert 5 in hits, "`if let Err(e)` returning without logging must be reported"
    assert 13 in hits, "silent `Err(e) =>` match arm must be reported"
    assert 17 in hits, "statement-position `.ok()` discard must be reported"


@pytest.mark.parametrize(
    ("line", "why"),
    [
        (2, "`?` propagates to the caller"),
        (3, "`.unwrap()` panics loudly - CWE-248, not a silent failure"),
        (4, "`.expect()` panics with a message"),
        (8, "the arm logs via tracing::error!"),
    ],
)
def test_rust_leaves_correct_code_alone(line: int, why: str, scanned) -> None:
    assert line not in scanned.get("swallow.rs", set()), why


def test_ruby_rescue(scanned) -> None:
    hits = scanned.get("swallow.rb", set())
    assert 3 in hits, "`rescue => e` with a bare nil body must be reported"
    assert 8 not in hits, "the rescue that calls logger.error must be left alone"
    assert 13 not in hits, "the rescue that re-raises must be left alone"


def test_php_suppression_operator(scanned) -> None:
    hits = scanned.get("swallow.php", set())
    assert 2 in hits, "`@fopen(...)` discards the diagnostic entirely"
    assert 3 not in hits, "the unsuppressed call must be left alone"


@pytest.fixture(scope="module")
def scanned2(tmp_path_factory: pytest.TempPathFactory) -> dict[str, set[int]]:
    """Second corpus: the Go and JS arms."""
    root = tmp_path_factory.mktemp("corpus2") / "app"
    shutil.copytree(Path(__file__).parent.parent / "fixtures" / "cwe778" / "langs2", root)
    out: dict[str, set[int]] = {}
    for f in check_insufficient_logging(str(root)).get("findings", []):
        out.setdefault(Path(f["file_path"]).name, set()).add(f["line_start"])
    return out


def test_go_reports_the_silent_block(scanned2) -> None:
    assert 4 in scanned2.get("swallow.go", set()), (
        "`if err != nil { return 1 }` records the failure nowhere"
    )


@pytest.mark.parametrize(
    ("line", "why"),
    [
        (7, "fmt.Fprintf to os.Stderr IS how a Go CLI reports"),
        (11, "a fatal helper prints and exits"),
        (14, "`return nil, errInvalidRequest` propagates a sentinel error"),
        (17, "`lastErr = derr` retains the error for a later report"),
        (21, "`append(failed, err.Error())` collects it for a later report"),
        (24, "`fmt.Errorf(..%w..)` wraps and propagates - Go's dominant idiom"),
        (27, "the block logs via log.Printf"),
    ],
)
def test_go_leaves_reported_errors_alone(line: int, why: str, scanned2) -> None:
    assert line not in scanned2.get("swallow.go", set()), why


def test_js_reports_only_the_empty_handler(scanned2) -> None:
    hits = scanned2.get("swallow.ts", set())
    assert 2 in hits, "`.catch(() => {})` swallows the rejection outright"


@pytest.mark.parametrize(
    ("line", "why"),
    [
        (3, "`.catch(() => setSubmittable(false))` surfaces the failure via the UI"),
        (4, "`.catch(() => '')` is a value fallback, Promise.catch used as orElse"),
        (5, "`.catch(next)` delegates to error middleware"),
        (6, "the handler logs via console.error"),
        (9, "the handler shows the message to the user"),
    ],
)
def test_js_leaves_handled_rejections_alone(line: int, why: str, scanned2) -> None:
    # Regression guard for the unparenthesised alternation in _JS_CB: without the
    # outer (?:...) every one of these matched, because the pattern's first branch
    # ended at `=>` and the `{}` it was supposed to require was never applied.
    assert line not in scanned2.get("swallow.ts", set()), why


@pytest.fixture(scope="module")
def scanned3(tmp_path_factory: pytest.TempPathFactory) -> dict[str, set[int]]:
    """Step-10 languages: Swift, Scala, Ruby modifier form, PHP."""
    root = tmp_path_factory.mktemp("corpus3") / "app"
    shutil.copytree(FIXTURES, root)
    out: dict[str, set[int]] = {}
    for f in check_insufficient_logging(str(root)).get("findings", []):
        out.setdefault(Path(f["file_path"]).name, set()).add(f["line_start"])
    # Non-vacuity: the four step-10 fixtures must have produced SOMETHING, or
    # every "SHOULD NOT FLAG" assertion below passes for the wrong reason.
    total = sum(len(v) for k, v in out.items() if k.startswith(("swallow.sw", "swallow.sc", "swallow2")))
    assert total >= 6, f"step-10 fixtures yielded {total} rows; the assertions are vacuous"
    return out


@pytest.mark.parametrize(
    ("fixture", "line", "should_flag", "why"),
    [
        # Swift - work order step 10
        ("swallow.swift", 2, True, "bare `catch { }` swallows"),
        ("swallow.swift", 3, False, "os_log records it"),
        ("swallow.swift", 4, True, "`catch let e as IOError { }` is empty"),
        ("swallow.swift", 5, False, "NSLog records it"),
        ("swallow.swift", 6, False, "rethrows"),
        ("swallow.swift", 7, True, "`try?` discards the error silently"),
        ("swallow.swift", 8, False, "`try!` aborts loudly - CWE-248, not 778"),
        # Scala - ONE SITE PER CASE ARM is the explicit requirement
        ("swallow.scala", 4, True, "`case NonFatal(e) =>` with an empty arm"),
        ("swallow.scala", 6, False, "this arm logs via logger.error"),
        ("swallow.scala", 8, False, "this arm rethrows"),
        ("swallow.scala", 11, True, "`Try(..).toOption` discards the Failure"),
        ("swallow.scala", 12, False, "`getOrElse` is a value fallback, not a discard"),
        # Ruby modifier form
        ("swallow2.rb", 2, True, "`x = risky rescue nil` substitutes and discards"),
        ("swallow2.rb", 4, False, "`rescue_from` is a registration, not a handler"),
        ("swallow2.rb", 7, False, "`ensure` is not an exception handler"),
        # PHP
        ("swallow2.php", 6, True, "PHP 8 no-variable `catch (ValueError) { }`"),
        ("swallow2.php", 7, True, "union `catch (A | B $e) { }` is empty"),
        ("swallow2.php", 8, False, "`report($e)` delegates - Laravel's reporting path"),
        ("swallow2.php", 9, True, "`@fopen` discards the diagnostic"),
        ("swallow2.php", 10, False, "the unsuppressed call is fine"),
    ],
)
def test_step10_language_shapes(
    fixture: str, line: int, should_flag: bool, why: str, scanned3
) -> None:
    hit = line in scanned3.get(fixture, set())
    assert hit == should_flag, f"{fixture}:{line} - {why}"


def test_php_docblock_param_is_not_suppression(scanned3) -> None:
    """`@param` in a docblock is not the `@` error-suppression operator."""
    assert 3 not in scanned3.get("swallow2.php", set())

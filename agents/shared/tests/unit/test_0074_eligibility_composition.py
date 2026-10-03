"""Feature 0074 P6 T6.2' — eligibility COMPOSITION over every whitelisted extension (AC12').

The eligibility layer is three functions composed: the scanner's walk
(``scan_code_files``), the prompt feed's extension set (``llm_feed_extensions``)
and the test/generated filter (``_llm_eligible_files``). Each has its own tests;
none of them pins what the COMPOSITION admits per extension. A predicate added to
any one of the three that silently drops ``.hcl``, ``.proto`` or ``.gql`` passed
every existing guard (R19, R43).

The expected set below is ENUMERATED BY HAND, never recomputed from the
predicate under test — a test that derives its oracle from the code it checks
cannot fail (that is exactly why rev 1's version could not). When a whitelist
entry is added, ``test_fixture_table_covers_the_scan_set`` fails and forces a
deliberate decision about whether the new type reaches the model.

All fixtures are synthetic: one tiny file per extension in a fresh temp tree,
with token-free basenames so no test/generated heuristic can fire on a name.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.audit_runner import _llm_eligible_files
from shared.tools.file_scanner import (
    CODE_EXTENSIONS,
    WHITELIST_EXTENSIONS,
    clear_caches,
    llm_feed_extensions,
    scan_code_files,
)

# Hand-enumerated: extensions that MUST reach the LLM prompt on defaults.
_EXPECTED_FED: frozenset[str] = frozenset({
    # source and config (CODE_EXTENSIONS)
    ".py", ".pyw", ".go", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".mts",
    ".cts", ".java", ".rs", ".rb", ".rake", ".erb", ".php", ".phtml", ".cs",
    ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".kts", ".c", ".h", ".m",
    ".mm", ".swift", ".kt", ".scala", ".yaml", ".yml", ".toml", ".json", ".xml",
    ".sh", ".bash", ".dockerfile",
    # templates
    ".html", ".htm", ".hbs", ".handlebars", ".pug", ".jade", ".ejs",
    ".mustache", ".twig", ".liquid", ".njk", ".vue", ".svelte", ".astro",
    # schema and infrastructure-as-code (B3: the seven siblings stay eligible)
    ".sql", ".tf", ".tfvars", ".hcl", ".proto", ".graphql", ".gql",
    # config dialects
    ".properties", ".ini", ".cfg", ".conf", ".env", ".envrc",
    # shells and build files
    ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".mk", ".gradle",
    # further languages
    ".lua", ".pl", ".pm", ".dart", ".groovy", ".clj", ".ex", ".exs", ".r",
    # template/config dialects the skills carry arms for
    ".j2", ".jinja", ".jinja2", ".jsp", ".jspx", ".config", ".csproj",
})

# Hand-enumerated: scanned by the skills but kept out of the PROMPT on budget
# grounds (VULTURE_LLM_FEED_PROSE defaults off).
_EXPECTED_PROSE: frozenset[str] = frozenset({
    ".md", ".markdown", ".rst", ".adoc", ".txt", ".csv", ".tsv",
})

_ENV_TO_CLEAR = (
    "VULTURE_LLM_INELIGIBLE_EXTENSIONS",
    "VULTURE_LLM_FEED_PROSE",
    "VULTURE_LLM_FEED_UNIFY",
    "VULTURE_EXTRA_EXTENSIONS",
    "VULTURE_DISABLE_EXTENSION_WHITELIST",
    "VULTURE_IGNORE_GITIGNORE",
)


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    for name in _ENV_TO_CLEAR:
        monkeypatch.delenv(name, raising=False)
    clear_caches()
    yield
    clear_caches()


@pytest.fixture
def one_file_per_extension(tmp_path: Path) -> Path:
    """A flat synthetic tree: ``f<i><ext>`` for every hand-listed extension."""
    for index, ext in enumerate(sorted(_EXPECTED_FED | _EXPECTED_PROSE)):
        (tmp_path / f"f{index}{ext}").write_text(f"value_{index} = {index}\n")
    return tmp_path


def _eligible_suffixes(root: Path) -> frozenset[str]:
    """The composition under test, reduced to the extensions it admits."""
    files = _llm_eligible_files(
        scan_code_files(str(root), extensions=llm_feed_extensions(), max_files=10_000)
    )
    return frozenset(Path(f).suffix.lower() for f in files)


def test_fixture_table_covers_the_scan_set():
    """AC12' drift guard: the hand table must cover the whole scan set.

    A new whitelist entry fails here first, so whether it reaches the model is a
    decision someone writes down, not a side effect.
    """
    assert _EXPECTED_FED | _EXPECTED_PROSE == CODE_EXTENSIONS | WHITELIST_EXTENSIONS


def test_composition_admits_exactly_the_hand_enumerated_set(one_file_per_extension):
    """AC12': one file per whitelisted extension -> exactly the enumerated set."""
    got = _eligible_suffixes(one_file_per_extension)
    assert got == _EXPECTED_FED, (
        f"missing={sorted(_EXPECTED_FED - got)} unexpected={sorted(got - _EXPECTED_FED)}"
    )


@pytest.mark.parametrize("excluded", [".proto", ".hcl", ".gql"])
def test_populated_exclusion_removes_exactly_that_extension(
    one_file_per_extension, monkeypatch, excluded,
):
    """AC12': a populated VULTURE_LLM_INELIGIBLE_EXTENSIONS removes exactly that type."""
    monkeypatch.setenv("VULTURE_LLM_INELIGIBLE_EXTENSIONS", excluded)
    clear_caches()
    got = _eligible_suffixes(one_file_per_extension)
    assert got == _EXPECTED_FED - {excluded}, (
        f"missing={sorted((_EXPECTED_FED - {excluded}) - got)} "
        f"unexpected={sorted(got - (_EXPECTED_FED - {excluded}))}"
    )

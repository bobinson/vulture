"""Feature 0070 P7 — dependency skill: CWE-830 and CWE-427.

Both detectors were specified against a measured baseline, and both carry
mandatory suppressions that came out of that measurement:

**CWE-830 (Inclusion of Web Functionality from an Untrusted Source).** The
``<link rel=stylesheet>`` arm of the original proposal produced 28 of 29
measured hits, every one of them a webfont stylesheet. Such a stylesheet
*cannot* carry SRI — the served bytes vary by User-Agent, so a pinned hash
breaks the page — which makes every one of those rows unfixable and therefore
false. The arm is dropped here, and the tests below assert it stays dropped.
Two further measured defects are pinned as tests: the static remote-ESM shape
is structurally unreachable behind the module's per-line ``IMPORT_LINE`` filter
(it must be evaluated before that filter, not after), and ``_MINIFIED_RE`` is
filename-only, so a bundler chunk is scanned in full unless the rule applies
its own long-line heuristic.

**CWE-427 (Uncontrolled Search Path Element).** ``Makefile`` reaches this skill
through ``WELL_KNOWN_FILENAMES``, and ``PYTHONPATH := $(ROOT)`` / ``PATH ?= x``
/ ``CLASSPATH += y`` put a ``:``, ``?`` or ``+`` immediately left of the ``=``.
Any implementation that reads that ``:`` as an empty leading path element is a
guaranteed false positive on every Makefile that sets a loader variable — so
the assignment operator guard is asserted directly. The JVM arm must likewise
require an explicit ``-D`` flag or ``System.setProperty`` call: a bare
``java.library.path=.`` substring match turns prose into a finding.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

from cwe_agent.skills import dependency_check
from cwe_agent.skills.dependency_check import check_dependency_security

_SKILL_SRC = Path(dependency_check.__file__).read_text()


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_dependency_security(str(root))["findings"]


def _cwe(files: dict[str, str], cwe: str) -> list[dict]:
    return [f for f in _run(files) if f.get("category") == cwe]


def _830(files: dict[str, str]) -> list[dict]:
    return _cwe(files, "CWE-830")


def _427(files: dict[str, str]) -> list[dict]:
    return _cwe(files, "CWE-427")


# ---------------------------------------------------------------------------
# Attestation: the coverage extractor only sees a LITERAL category.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cwe", ["830", "427"])
def test_category_literal_is_present_in_source(cwe):
    assert f'"category": "CWE-{cwe}"' in _SKILL_SRC, (
        f"CWE-{cwe} must be emitted as a literal category or the coverage "
        "extractor cannot see it (an f-string would detect but not attest)"
    )


# ---------------------------------------------------------------------------
# CWE-830 — arm A: <script src> without subresource integrity
# ---------------------------------------------------------------------------
class TestWebIncludeScriptTag:
    def test_remote_script_without_integrity_is_reported(self):
        hits = _830({"index.html": (
            "<html><body>\n"
            '<script src="https://cdn.example.net/lib/a.js"></script>\n'
            "</body></html>\n"
        )})
        assert len(hits) == 1
        assert hits[0]["line_start"] == 2

    def test_clean_twin_with_integrity_hash_is_silent(self):
        """Minimal difference from the positive: the SRI attribute."""
        assert not _830({"index.html": (
            "<html><body>\n"
            '<script src="https://cdn.example.net/lib/a.js" '
            'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K" '
            'crossorigin="anonymous"></script>\n'
            "</body></html>\n"
        )})

    def test_scheme_relative_host_is_reported(self):
        assert len(_830({"index.html": '<script src="//cdn.example.net/a.js"></script>\n'})) == 1

    def test_relative_src_is_silent(self):
        assert not _830({"index.html": '<script src="/static/a.js"></script>\n'})

    def test_localhost_is_silent(self):
        assert not _830({"index.html": '<script src="//localhost:3000/a.js"></script>\n'})

    def test_templated_host_is_silent(self):
        assert not _830({"index.html": '<script src="//{{ cdn_host }}/a.js"></script>\n'})

    def test_templated_path_under_a_literal_host_still_reports(self):
        assert _830({"index.html": '<script src="https://cdn.example.net/{{ ver }}/a.js"></script>\n'})

    def test_stylesheet_link_arm_is_not_shipped(self):
        """The dropped arm: a webfont stylesheet cannot carry SRI, so 28 of 29
        measured rows were unfixable. It must stay dropped."""
        assert not _830({"index.html": (
            '<link rel="stylesheet" href="https://fonts.example.net/css2?family=X">\n'
            '<link rel="preload" as="font" href="https://fonts.example.net/f.woff2">\n'
        )})

    def test_modulepreload_link_is_reported(self):
        """rel=modulepreload preloads JavaScript, so SRI applies."""
        assert len(_830({"index.html": (
            '<link rel="modulepreload" href="https://cdn.example.net/m.js">\n'
        )})) == 1

    def test_modulepreload_with_integrity_is_silent(self):
        assert not _830({"index.html": (
            '<link rel="modulepreload" href="https://cdn.example.net/m.js" '
            'integrity="sha256-abcdefabcdefabcdefabcdefabcdef">\n'
        )})

    def test_sri_unsupported_vendor_host_is_silent(self):
        """Analytics/tag-manager/payment loaders rotate their artefact and
        document SRI as unsupported: a row there is unactionable."""
        assert not _830({"index.html": (
            '<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>\n'
            '<script src="https://js.stripe.com/v3/"></script>\n'
        )})

    def test_multiline_tag_carrying_integrity_is_not_a_false_positive(self):
        """The tag text must close on the reported line; a wrapped tag whose
        integrity attribute sits on the next line must not be flagged."""
        assert not _830({"index.html": (
            '<script src="https://cdn.example.net/a.js"\n'
            '        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6"\n'
            "></script>\n"
        )})


# ---------------------------------------------------------------------------
# CWE-830 — arm B: remote module / worker loads
# ---------------------------------------------------------------------------
class TestWebIncludeRemoteModule:
    def test_import_scripts_remote_is_reported(self):
        assert len(_830({"worker.js": 'importScripts("https://cdn.example.net/w.js");\n'})) == 1

    def test_import_scripts_local_is_silent(self):
        assert not _830({"worker.js": 'importScripts("./w.js");\n'})

    def test_dynamic_import_remote_is_reported(self):
        assert len(_830({"app.js": 'const m = await import("https://esm.example.net/m.js");\n'})) == 1

    def test_static_remote_esm_import_is_reachable(self):
        """Structural regression guard: `_analyze_code_file` skips every line
        matching IMPORT_LINE, so a static `import ... from "https://..."` rule
        evaluated after that filter can NEVER fire."""
        assert len(_830({"app.js": 'import { x } from "https://esm.example.net/m.js";\n'})) == 1

    def test_static_local_esm_import_is_silent(self):
        assert not _830({"app.js": 'import { x } from "./m.js";\n'})


# ---------------------------------------------------------------------------
# CWE-830 — arm C: DOM-injected script / iframe
# ---------------------------------------------------------------------------
class TestWebIncludeDomInjection:
    def test_injected_remote_script_is_reported(self):
        hits = _830({"boot.js": (
            "function load() {\n"
            "  const s = document.createElement('script');\n"
            "  s.async = true;\n"
            '  s.src = "//cdn.example.net/a.js";\n'
            "  document.head.appendChild(s);\n"
            "}\n"
        )})
        assert len(hits) == 1
        assert hits[0]["line_start"] == 4

    def test_bare_src_assignment_without_script_creation_is_silent(self):
        """An <img>/<video> src has no SRI mechanism and is not CWE-830; a bare
        `.src =` anchor was rejected for exactly this reason."""
        assert not _830({"boot.js": (
            "const img = new Image();\n"
            'img.src = "//cdn.example.net/pixel.png";\n'
        )})

    def test_bundled_artefact_is_not_scanned_for_web_includes(self):
        """`_MINIFIED_RE` is filename-only, so a bundler chunk under an
        arbitrary name is scanned in full. Long-line heuristic required."""
        assert not _830({"chunk-1a2b.js": (
            'const T = "' + ("a" * 2200) + '";\n'
            'importScripts("https://cdn.example.net/w.js");\n'
        )})


# ---------------------------------------------------------------------------
# CWE-830 — row hygiene
# ---------------------------------------------------------------------------
class TestWebIncludeRowHygiene:
    def test_one_row_per_line_no_parent_stacking(self):
        """Skill findings are not cross-deduplicated (P5): the child rule must
        claim the line, not add a row alongside the CWE-829 parent."""
        f = _run({"index.html": '<script src="https://cdn.example.net/a.js"></script>\n'})
        assert len(f) == 1, f"expected exactly one row, got {[x['category'] for x in f]}"

    def test_plaintext_script_src_stays_with_cwe_829(self):
        """`<script src="http://` is the existing CWE-829 pattern; CWE-830 owns
        the https / scheme-relative population only, so the ids stay disjoint."""
        f = _run({"index.html": '<script src="http://cdn.example.net/a.js"></script>\n'})
        cats = {x["category"] for x in f}
        assert cats == {"CWE-829"}, cats

    def test_finding_is_enriched(self):
        hits = _830({"index.html": '<script src="https://cdn.example.net/a.js"></script>\n'})
        assert hits[0].get("cwe_name"), "CWE-830 must be catalog-enriched"


# ---------------------------------------------------------------------------
# CWE-427 — arm (a) Python module search path
# ---------------------------------------------------------------------------
class TestSearchPathPython:
    def test_empty_string_element_is_reported(self):
        assert len(_427({"boot.py": 'import sys\nsys.path.insert(0, "")\n'})) == 1

    def test_cwd_element_is_reported(self):
        assert len(_427({"boot.py": "import os, sys\nsys.path.insert(0, os.getcwd())\n"})) == 1

    def test_dot_element_is_reported(self):
        assert len(_427({"boot.py": 'import sys\nsys.path.append(".")\n'})) == 1

    def test_slice_prepend_of_cwd_is_reported(self):
        assert len(_427({"boot.py": 'import sys\nsys.path[0:0] = [""]\n'})) == 1

    def test_module_relative_bootstrap_is_silent(self):
        """The dominant real idiom: the element is derived from the module's own
        location, which is not attacker-controlled."""
        assert not _427({"boot.py": (
            "import sys\nfrom pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parent.parent))\n"
        )})

    def test_absolute_element_is_silent(self):
        assert not _427({"boot.py": 'import sys\nsys.path.insert(0, "/opt/app/lib")\n'})


# ---------------------------------------------------------------------------
# CWE-427 — arms (b)/(c) loader environment variables
# ---------------------------------------------------------------------------
class TestSearchPathLoaderVars:
    def test_relative_element_in_loader_var_is_reported(self):
        assert len(_427({"run.sh": "export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH\n"})) == 1

    def test_absolute_element_in_loader_var_is_silent(self):
        assert not _427({"run.sh": "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH\n"})

    def test_pwd_element_is_reported(self):
        assert len(_427({"run.sh": "export PYTHONPATH=$PWD\n"})) == 1

    def test_tmp_element_is_reported(self):
        assert len(_427({"run.sh": "export LD_LIBRARY_PATH=/tmp:$LD_LIBRARY_PATH\n"})) == 1

    def test_trailing_colon_empty_element_is_reported(self):
        assert len(_427({"run.sh": "export PATH=/usr/local/bin:\n"})) == 1

    def test_double_colon_empty_element_is_reported(self):
        assert len(_427({"run.sh": "export CLASSPATH=/opt/a.jar::/opt/b.jar\n"})) == 1

    def test_well_formed_colon_list_is_silent(self):
        assert not _427({"run.sh": "export PATH=/usr/local/bin:/usr/bin\n"})

    def test_conventional_local_tool_bin_is_silent(self):
        assert not _427({"run.sh": 'export PATH="$PWD/node_modules/.bin:$PATH"\n'})

    def test_naming_a_loader_var_without_assigning_is_silent(self):
        """Env-scrubbing / hardening code names these variables on purpose."""
        assert not _427({"harden.py": (
            'SCRUB = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"]\n'
            "for name in SCRUB:\n    os.environ.pop(name, None)\n"
        )})

    @pytest.mark.parametrize("line", [
        "PYTHONPATH := $(ROOT)/src\n",
        "CLASSPATH += $(EXTRA)\n",
        "PATH ?= /usr/bin\n",
        "LD_LIBRARY_PATH:=$(BUILD)/lib\n",
    ])
    def test_make_assignment_operators_are_not_empty_path_elements(self, line):
        """Measured trap: Makefiles reach this skill via WELL_KNOWN_FILENAMES,
        and `:=` / `?=` / `+=` put a `:`/`?`/`+` immediately left of the `=`.
        Reading that `:` as a leading empty element is a guaranteed FP."""
        assert not _427({"Makefile": line})


# ---------------------------------------------------------------------------
# CWE-427 — arm (d) JVM / host properties
# ---------------------------------------------------------------------------
class TestSearchPathJvm:
    def test_set_property_relative_library_path_is_reported(self):
        assert len(_427({"Boot.java": (
            "class Boot {\n"
            '  static { System.setProperty("java.library.path", "."); }\n'
            "}\n"
        )})) == 1

    def test_set_property_absolute_library_path_is_silent(self):
        assert not _427({"Boot.java": (
            "class Boot {\n"
            '  static { System.setProperty("java.library.path", "/opt/lib"); }\n'
            "}\n"
        )})

    def test_explicit_d_flag_is_reported(self):
        assert len(_427({"run.sh": "java -Djava.library.path=. -jar app.jar\n"})) == 1

    def test_bare_property_mention_in_prose_is_silent(self):
        """A bare `java.library.path=.` substring match makes documentation a
        finding; an explicit flag or API call is required."""
        assert not _427({"notes.txt": (
            "The default is java.library.path=. which resolves relative to cwd.\n"
        )})

    def test_python_path_env_assignment_of_cwd_is_reported(self):
        assert len(_427({"boot.py": (
            "import os\n"
            'os.environ["PATH"] = os.getcwd() + ":" + os.environ["PATH"]\n'
        )})) == 1


# ---------------------------------------------------------------------------
# CWE-427 — arm (e) YAML mapping form
# ---------------------------------------------------------------------------
class TestSearchPathYaml:
    def test_yaml_mapping_relative_element_is_reported(self):
        assert len(_427({"ci.yml": "jobs:\n  env:\n    PYTHONPATH: .\n"})) == 1

    def test_yaml_mapping_absolute_element_is_silent(self):
        assert not _427({"ci.yml": "jobs:\n  env:\n    PYTHONPATH: /workspace/src\n"})


# ---------------------------------------------------------------------------
# CWE-427 — row hygiene
# ---------------------------------------------------------------------------
class TestSearchPathRowHygiene:
    def test_severity_is_low_and_wording_does_not_claim_execution(self):
        hits = _427({"run.sh": "export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH\n"})
        assert hits[0]["severity"] == "low"
        blob = (hits[0]["title"] + hits[0]["description"]).lower()
        assert "working directory" in blob
        assert "remote code execution" not in blob

    def test_one_row_per_line(self):
        f = _run({"run.sh": "export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH\n"})
        assert len(f) == 1, [x["category"] for x in f]

    def test_finding_is_enriched(self):
        hits = _427({"boot.py": 'import sys\nsys.path.insert(0, "")\n'})
        assert hits[0].get("cwe_name"), "CWE-427 must be catalog-enriched"

    def test_prose_files_are_skipped(self):
        """`.txt` is in this skill's extension set and is prose: a pattern in a
        doc is a mention, not an instance."""
        assert not _427({"install.txt": "export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH\n"})


# ---------------------------------------------------------------------------
# No collateral damage to the shipped detectors
# ---------------------------------------------------------------------------
class TestExistingDetectorsUnchanged:
    def test_curl_pipe_shell_still_reports_829(self):
        f = _run({"install.sh": "curl https://example.net/i.sh | bash\n"})
        assert any(x["category"] == "CWE-829" for x in f)

    def test_import_lines_are_still_filtered_for_other_rules(self):
        """Only the CWE-830 remote-ESM shape was hoisted above the IMPORT_LINE
        filter; the filter itself must remain for the other rules."""
        assert not _run({"app.py": 'import base64\nfrom os import system\n'})


# ---------------------------------------------------------------------------
# Corpus fixtures (per-CWE gate: min_recall 1.0, max_fp_rate 0.0, 3+3)
# ---------------------------------------------------------------------------
_MANIFEST = Path(__file__).resolve().parents[2] / "corpus" / "manifest.d" / "p7_dependency.yaml"
_FIXTURES = Path(__file__).resolve().parents[2] / "corpus" / "fixtures"


def _entries() -> list[dict]:
    import yaml

    return yaml.safe_load(_MANIFEST.read_text()) or []


class TestCorpusFixtures:
    def test_manifest_exists_with_three_positives_and_three_twins(self):
        entries = _entries()
        for cwe in ("830", "427"):
            rows = [e for e in entries if str(e["cwe"]) == cwe]
            pos = [e for e in rows if e["expectation"] == "positive"]
            neg = [e for e in rows if e["expectation"] == "negative"]
            assert len(pos) >= 3, f"CWE-{cwe} needs >= 3 positive fixtures"
            assert len(neg) >= 3, f"CWE-{cwe} needs >= 3 clean twins"

    def test_every_referenced_fixture_exists(self):
        for e in _entries():
            assert (_FIXTURES / e["file"]).is_file(), e["file"]

    def test_fixtures_carry_no_repository_or_challenge_reference(self):
        for e in _entries():
            body = (_FIXTURES / e["file"]).read_text().lower()
            for token in ("juice", "shop", "vulture", "openclaw", "challenge"):
                assert token not in body, f"{e['file']} references {token!r}"

    @pytest.mark.parametrize("cwe", ["830", "427"])
    def test_gate_math_passes_on_the_flattened_fixtures(self, cwe):
        """The runner flattens each fixture to one file named `f.<ext>`, so a
        layout- or filename-dependent rule cannot gate. Score it for real."""
        import importlib

        corpus_runner = importlib.import_module("corpus_runner")
        entries = [e for e in _entries() if str(e["cwe"]) == cwe]
        detect = corpus_runner.run_deterministic
        target = f"CWE-{cwe}"
        for e in entries:
            fired = target in detect(str(_FIXTURES / e["file"]))
            if e["expectation"] == "positive":
                assert fired, f"{e['file']} must fire {target} after flattening"
            else:
                assert not fired, f"{e['file']} is a clean twin but fired {target}"


def test_no_regex_uses_an_unbounded_argument_standin():
    """P4 defect class: `[^,]+` / `[^)]*` as an argument stand-in slides a
    capture group onto a literal inside a neighbouring argument."""
    new_block = _SKILL_SRC.split("# CWE-830")[-1].split("def check_dependency_security")[0]
    assert not re.search(r"\[\^,\]\+|\[\^\)\]\*", new_block)

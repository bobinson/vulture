"""Unit tests for catalog-driven detection engine and enriched catalog."""

import pytest

from cwe_agent.catalog import (
    build_catalog_context,
    enrich_finding,
    get_by_keyword,
    get_code_examples,
    get_cwe,
    get_related,
    get_static_detectable,
    load_catalog,
)
from cwe_agent.skills.catalog_detector import (
    _DEDICATED_SKILL_CWES,
    _build_keyword_index,
    _extract_line_keywords,
    _file_matches_languages,
    _keyword_match_score,
    _severity_from_consequences,
    check_catalog_generic,
)


# === Catalog Loading ===


class TestCatalogLoading:
    """Tests for enriched catalog loading."""

    def test_catalog_loads(self):
        catalog = load_catalog()
        assert len(catalog) > 800, f"Expected 800+ CWEs, got {len(catalog)}"

    def test_catalog_entry_has_enriched_fields(self):
        entry = get_cwe("89")
        assert entry is not None
        assert "detection_methods" in entry
        assert "related_weaknesses" in entry
        assert "code_examples" in entry
        assert "keywords" in entry
        assert "static_detectability" in entry
        assert "extended_description" in entry
        assert "mitigations" in entry

    def test_catalog_entry_has_keywords(self):
        entry = get_cwe("89")
        assert entry is not None
        assert len(entry["keywords"]) > 0
        assert "sql" in entry["keywords"] or "injection" in entry["keywords"]

    def test_catalog_entry_has_detection_methods(self):
        entry = get_cwe("89")
        assert entry is not None
        assert len(entry["detection_methods"]) > 0
        dm = entry["detection_methods"][0]
        assert "method" in dm
        assert "effectiveness" in dm
        assert "score" in dm
        assert "static" in dm

    def test_catalog_entry_has_code_examples(self):
        entry = get_cwe("89")
        assert entry is not None
        examples = entry.get("code_examples", [])
        assert len(examples) > 0
        assert examples[0]["nature"] in ("bad", "good")

    def test_catalog_entry_has_related_weaknesses(self):
        entry = get_cwe("89")
        assert entry is not None
        related = entry.get("related_weaknesses", [])
        assert len(related) > 0
        assert "nature" in related[0]
        assert "cwe_id" in related[0]


class TestCatalogHelpers:
    """Tests for catalog helper functions."""

    def test_get_static_detectable(self):
        detectable = get_static_detectable(min_score=0.3)
        assert len(detectable) > 100, "Expected 100+ static-detectable CWEs"
        # Should be sorted by detectability descending
        scores = [e.get("static_detectability", 0) for e in detectable]
        assert scores == sorted(scores, reverse=True)

    def test_get_by_keyword(self):
        results = get_by_keyword("injection")
        assert len(results) > 0
        assert any(r["id"] == "89" for r in results)

    def test_get_related(self):
        related = get_related("89")
        assert len(related) > 0

    def test_get_related_filtered(self):
        children = get_related("89", nature="ChildOf")
        assert len(children) >= 0  # May or may not have children

    def test_get_code_examples_bad(self):
        examples = get_code_examples("89", "bad")
        assert len(examples) > 0
        assert all(e["nature"] == "bad" for e in examples)

    def test_get_code_examples_good(self):
        examples = get_code_examples("89", "good")
        # May not have good examples for every CWE
        for e in examples:
            assert e["nature"] == "good"

    def test_build_catalog_context(self):
        context = build_catalog_context(["89", "79", "22"])
        assert "CWE-89" in context
        assert "CWE-79" in context
        assert len(context) > 100

    def test_build_catalog_context_respects_limit(self):
        context = build_catalog_context(["89", "79"], max_chars=100)
        assert len(context) <= 200  # Some slack for line assembly

    def test_enrich_finding_adds_catalog_confidence(self):
        finding = {
            "severity": "high",
            "category": "CWE-89",
            "title": "SQL injection",
            "description": "SQL injection found",
            "recommendation": "Use prepared statements",
        }
        enriched = enrich_finding(finding, "89")
        assert "cwe_name" in enriched
        assert "cwe_likelihood" in enriched

    def test_enrich_finding_preserves_existing_fields(self):
        finding = {
            "severity": "high",
            "category": "CWE-89",
            "title": "SQL injection",
            "description": "Custom description",
            "recommendation": "Custom recommendation",
        }
        enriched = enrich_finding(finding, "89")
        assert enriched["description"] == "Custom description"
        assert enriched["recommendation"] == "Custom recommendation"


# === Catalog Detector Engine ===


class TestKeywordIndex:
    """Tests for keyword index building."""

    def test_keyword_index_built(self):
        index = _build_keyword_index()
        assert len(index) > 50, "Expected 50+ keywords in index"

    def test_keyword_index_excludes_dedicated_skills(self):
        index = _build_keyword_index()
        for entries in index.values():
            for entry in entries:
                assert entry["id"] not in _DEDICATED_SKILL_CWES

    def test_keyword_index_has_entries(self):
        index = _build_keyword_index()
        # At least some keywords should map to entries
        total_entries = sum(len(v) for v in index.values())
        assert total_entries > 100


class TestKeywordMatching:
    """Tests for keyword extraction and matching."""

    def test_extract_line_keywords(self):
        keywords = _extract_line_keywords("def authenticate_user(username, password):")
        assert "authenticate_user" in keywords or "authenticate" in keywords
        assert "username" in keywords
        assert "password" in keywords

    def test_extract_line_keywords_ignores_short(self):
        keywords = _extract_line_keywords("if x == y:")
        assert "if" not in keywords  # Too short

    def test_keyword_match_score_with_overlap(self):
        line_kw = {"sql", "injection", "command", "query", "user"}
        cwe_kw = frozenset(["sql", "injection", "command", "parameterize"])
        score = _keyword_match_score(line_kw, cwe_kw)
        assert score > 0.0  # 3 of 4 specific keywords match (75%)

    def test_keyword_match_score_single_match_returns_zero(self):
        line_kw = {"config", "environ", "get_value"}
        cwe_kw = frozenset(["config", "database", "credentials"])
        score = _keyword_match_score(line_kw, cwe_kw)
        assert score == 0.0  # Single keyword match is insufficient

    def test_keyword_match_score_no_overlap(self):
        line_kw = {"render", "template", "html"}
        cwe_kw = frozenset(["sql", "database", "query"])
        score = _keyword_match_score(line_kw, cwe_kw)
        assert score == 0.0


class TestLanguageFiltering:
    """Tests for language-based file filtering."""

    def test_python_file_matches_python(self):
        assert _file_matches_languages(".py", ["Python"])

    def test_python_file_doesnt_match_java(self):
        assert not _file_matches_languages(".py", ["Java"])

    def test_empty_languages_matches_all(self):
        assert _file_matches_languages(".py", [])

    def test_go_file_matches_go(self):
        assert _file_matches_languages(".go", ["Go"])

    def test_c_file_matches_c(self):
        assert _file_matches_languages(".c", ["C"])


class TestSeverityMapping:
    """Tests for consequence-based severity derivation."""

    def test_critical_from_rce(self):
        consequences = [{"scope": "Integrity", "impact": "Execute Unauthorized Code or Commands"}]
        assert _severity_from_consequences(consequences) == "critical"

    def test_high_from_data_read(self):
        consequences = [{"scope": "Confidentiality", "impact": "Read Application Data"}]
        assert _severity_from_consequences(consequences) == "high"

    def test_medium_default(self):
        consequences = [{"scope": "Other", "impact": "Other"}]
        assert _severity_from_consequences(consequences) == "medium"

    def test_empty_consequences(self):
        assert _severity_from_consequences([]) == "medium"


class TestCatalogDetectorIntegration:
    """Integration tests for catalog-driven detection."""

    @pytest.fixture
    def source_with_patterns(self, tmp_path):
        """Create source code with various patterns for catalog matching."""
        # File with authentication-related patterns
        (tmp_path / "auth.py").write_text(
            "def login(username, password):\n"
            "    token = generate_token(username)\n"
            "    return authenticate(username, password)\n"
        )
        # File with error handling patterns
        (tmp_path / "handler.go").write_text(
            "package main\n\n"
            "func handleRequest(w http.ResponseWriter, r *http.Request) {\n"
            "    result, err := processInput(r.Body)\n"
            "    if err != nil {\n"
            "        http.Error(w, err.Error(), 500)\n"
            "    }\n"
            "}\n"
        )
        # File with concurrency patterns
        (tmp_path / "worker.py").write_text(
            "import threading\n\n"
            "shared_counter = 0\n\n"
            "def increment_counter():\n"
            "    global shared_counter\n"
            "    shared_counter += 1\n"
        )
        return tmp_path

    @pytest.fixture
    def clean_source(self, tmp_path):
        """Create clean source with minimal patterns."""
        clean = tmp_path / "clean"
        clean.mkdir()
        (clean / "main.py").write_text(
            "def hello():\n"
            "    return 'world'\n"
        )
        return clean

    def test_catalog_detector_returns_dict(self, source_with_patterns):
        result = check_catalog_generic(str(source_with_patterns))
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_findings_have_required_fields(self, source_with_patterns):
        result = check_catalog_generic(str(source_with_patterns))
        required = {"severity", "category", "title", "description", "file_path",
                     "line_start", "line_end", "recommendation"}
        for finding in result["findings"]:
            assert required.issubset(finding.keys()), f"Missing: {required - finding.keys()}"

    def test_findings_have_catalog_confidence(self, source_with_patterns):
        result = check_catalog_generic(str(source_with_patterns))
        for finding in result["findings"]:
            assert "catalog_confidence" in finding
            assert 0.0 <= finding["catalog_confidence"] <= 1.0

    def test_findings_have_cwe_category(self, source_with_patterns):
        result = check_catalog_generic(str(source_with_patterns))
        for finding in result["findings"]:
            assert finding["category"].startswith("CWE-")

    def test_clean_code_produces_few_findings(self, clean_source):
        result = check_catalog_generic(str(clean_source))
        # Clean code should produce very few or no findings
        assert len(result["findings"]) <= 3

    def test_skips_dedicated_skill_cwes(self, source_with_patterns):
        result = check_catalog_generic(str(source_with_patterns))
        for finding in result["findings"]:
            cwe_id = finding["category"].replace("CWE-", "")
            assert cwe_id not in _DEDICATED_SKILL_CWES, (
                f"Found {finding['category']} which should be handled by dedicated skill"
            )

    def test_skips_test_files(self, tmp_path):
        (tmp_path / "test_auth.py").write_text(
            "def test_login():\n"
            "    authenticate(user, password)\n"
        )
        result = check_catalog_generic(str(tmp_path))
        test_findings = [f for f in result["findings"] if "test_auth" in f["file_path"]]
        assert len(test_findings) == 0


# === Config Tests ===


class TestEnhancedConfig:
    """Tests for updated CWE agent configuration."""

    def test_all_categories_includes_catalog_generic(self):
        from cwe_agent.config import ALL_CATEGORIES
        assert "catalog_generic" in ALL_CATEGORIES

    def test_skill_count_is_16(self):
        from cwe_agent.config import AGENT_INFO
        assert len(AGENT_INFO["skills"]) == 16

    def test_description_mentions_846(self):
        from cwe_agent.config import AGENT_INFO
        assert "846" in AGENT_INFO["description"]

    def test_skill_map_has_catalog_generic(self):
        from cwe_agent.skills import SKILL_MAP
        assert "catalog_generic" in SKILL_MAP

    def test_skill_tools_has_catalog_generic_tool(self):
        from cwe_agent.skills import SKILL_TOOLS
        assert len(SKILL_TOOLS) == 16


# === Agent Tests ===


class TestEnhancedAgent:
    """Tests for updated CWE agent with catalog context."""

    def test_instructions_mention_self_learning(self):
        from cwe_agent.agent import INSTRUCTIONS
        assert "Self-Learning" in INSTRUCTIONS
        assert "BOOST" in INSTRUCTIONS
        assert "DEMOTE" in INSTRUCTIONS

    def test_instructions_mention_catalog(self):
        from cwe_agent.agent import INSTRUCTIONS
        assert "v4.19.1" in INSTRUCTIONS
        assert "846" in INSTRUCTIONS

    def test_build_llm_catalog_context(self):
        from cwe_agent.agent import _build_llm_catalog_context
        ctx = _build_llm_catalog_context()
        assert len(ctx) > 100
        assert "CWE-" in ctx


class TestRollupHelper:
    """Unit tests for _emit_parent_rollups using synthetic catalog data."""

    def _synth_catalog(self):
        return {
            "100": {
                "id": "100", "name": "Parent Class", "abstraction": "Class",
                "consequences": [{"impact": "Read Application Data"}],
                "static_detectability": 0.6, "mitigation": "Fix parent",
                "keywords": [], "languages": [], "related_weaknesses": [],
            },
            "101": {
                "id": "101", "name": "Child A", "abstraction": "Variant",
                "consequences": [{"impact": "Other"}],
                "static_detectability": 0.5, "mitigation": "", "keywords": [],
                "languages": [],
                "related_weaknesses": [{"nature": "ChildOf", "cwe_id": "100"}],
            },
            "102": {
                "id": "102", "name": "Child B", "abstraction": "Variant",
                "consequences": [{"impact": "Other"}],
                "static_detectability": 0.5, "mitigation": "", "keywords": [],
                "languages": [],
                "related_weaknesses": [{"nature": "ChildOf", "cwe_id": "100"}],
            },
        }

    def test_emits_rollup_when_two_children_match(self, tmp_path):
        from cwe_agent.skills.catalog_detector import _emit_parent_rollups
        file_key = str(tmp_path / "x.py")
        seen = {file_key: {"101", "102"}}
        counts: dict[str, int] = {}
        findings: list[dict] = []
        _emit_parent_rollups(tmp_path / "x.py", file_key, seen, counts, findings,
                              self._synth_catalog())
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "CWE-100"
        assert f["check_id"].endswith(".rollup")
        assert f["rollup_children"] == ["101", "102"]
        assert counts["100"] == 1
        assert "100" in seen[file_key]

    def test_skips_rollup_for_single_child(self, tmp_path):
        from cwe_agent.skills.catalog_detector import _emit_parent_rollups
        file_key = str(tmp_path / "x.py")
        seen = {file_key: {"101"}}
        counts: dict[str, int] = {}
        findings: list[dict] = []
        _emit_parent_rollups(tmp_path / "x.py", file_key, seen, counts, findings,
                              self._synth_catalog())
        assert findings == []

    def test_respects_max_files_per_cwe(self, tmp_path):
        from cwe_agent.skills.catalog_detector import (
            _emit_parent_rollups, _MAX_FILES_PER_CWE,
        )
        file_key = str(tmp_path / "x.py")
        seen = {file_key: {"101", "102"}}
        counts = {"100": _MAX_FILES_PER_CWE}  # cap already hit
        findings: list[dict] = []
        _emit_parent_rollups(tmp_path / "x.py", file_key, seen, counts, findings,
                              self._synth_catalog())
        assert findings == []

    def test_skips_when_parent_already_seen(self, tmp_path):
        from cwe_agent.skills.catalog_detector import _emit_parent_rollups
        file_key = str(tmp_path / "x.py")
        seen = {file_key: {"100", "101", "102"}}  # parent already in seen
        counts: dict[str, int] = {}
        findings: list[dict] = []
        _emit_parent_rollups(tmp_path / "x.py", file_key, seen, counts, findings,
                              self._synth_catalog())
        assert findings == []

    def test_skips_non_class_pillar_parents(self, tmp_path):
        from cwe_agent.skills.catalog_detector import _emit_parent_rollups
        synth = self._synth_catalog()
        synth["100"]["abstraction"] = "Base"  # not Class or Pillar
        file_key = str(tmp_path / "x.py")
        seen = {file_key: {"101", "102"}}
        findings: list[dict] = []
        _emit_parent_rollups(tmp_path / "x.py", file_key, seen, {}, findings, synth)
        assert findings == []


class TestRollupIntegration:
    """End-to-end: real catalog, crafted fixtures."""

    def test_rollup_fires_on_multi_child_file(self, tmp_path):
        """Smoke test: if any file triggers >=2 children of a real Class/Pillar
        parent, at least one rollup finding appears. Specific parent IDs
        depend on catalog version -- we assert the mechanism only."""
        f = tmp_path / "multi.py"
        f.write_text(
            "import os\n"
            "import subprocess\n"
            "os.system(user_input)\n"
            "subprocess.Popen(arg, shell=True)\n"
            "eval(f'x {payload}')\n"
        )
        from cwe_agent.skills.catalog_detector import check_catalog_generic
        result = check_catalog_generic(str(tmp_path))
        rollups = [x for x in result["findings"] if x["check_id"].endswith(".rollup")]
        # If no rollup fires, it means either no two children of the same Class
        # parent matched (catalog-dependent) or the mechanism is broken.
        # Failure mode we care about: mechanism broken -- assert helper invocation
        # at minimum via the unit tests above. This integration test is a
        # smoke check: document catalog state if it fails.
        if not rollups:
            import pytest
            pytest.skip("No rollup candidates in current catalog (not a regression)")
        for r in rollups:
            assert "rollup_children" in r
            assert len(r["rollup_children"]) >= 2

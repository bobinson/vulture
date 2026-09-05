"""XSS vulnerability scanner agent definition."""

from collections.abc import Generator
from pathlib import Path
from typing import Any

from shared.audit_kwargs import shared_audit_kwargs
from shared.audit_runner import run_combined_audit
from shared.llm.provider import (
    get_max_findings,  # noqa: F401  (module attribute: the fleet tests monkeypatch it)
)
from shared.prompt.manifests.generate import domain_instructions
from shared.tools.memory_client import (
    build_prior_context,  # noqa: F401  (module attribute: the fleet tests monkeypatch it)
)

from xss_agent.config import ALL_CATEGORIES
from xss_agent.skills import SKILL_MAP, SKILL_TOOLS

# Instructions live in a sibling .md file so the XSS detector's pattern
# scanner doesn't match its own LLM-prompt copy (the prompt has to mention
# things like '|safe' and 'dangerouslySetInnerHTML' as detection targets,
# which would otherwise fire as critical findings on this file). The .md
# extension is excluded from CODE_EXTENSIONS in shared.tools.file_scanner.
#
# NOT the prompt source any more — feature 0089 Phase 2.5 moved that to the
# fragment `domains/xss`, named at the `run_combined_audit` call below and
# rendered by `domain_instructions()` (see its note in
# `shared/prompt/manifests/generate.py`). `INSTRUCTIONS.md` stays as the
# transcription's INDEPENDENT oracle: `test_0089_manifest_generate.py` reads
# that file off disk and asserts the fragment equals it byte for byte, so it is
# the one assertion that can still see the fragment drift from the prompt this
# agent shipped. Do not reword, reformat or delete it: edit the fragment, then
# the `.md`, together. This binding is what keeps the `.md` reachable from code
# and therefore not mistakable for an orphan.
INSTRUCTIONS = (Path(__file__).parent / "INSTRUCTIONS.md").read_text(encoding="utf-8")


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the XSS vulnerability audit and yield SSE events."""
    categories = config.get("categories", ALL_CATEGORIES)

    _shared = shared_audit_kwargs(config, source_path, prior_findings, "xss")
    
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="XSS categories",
        **_shared,
        skill_tools=SKILL_TOOLS,
        instructions=domain_instructions(
            "domains/xss",
        ),
        # 0089 Phase 2.3 — stated, not defaulted (see run_combined_audit's
        # `category_enum` docs). `None`, deliberately: findings carry CWE-79 /
        # CWE-80 style categories as well as the five declared keys, so opting
        # in is a measurement to run, not part of a refactor.
        category_enum=None,
    )

"""GitHub Actions secret expressions are indirections, not hardcoded secrets.

`config_files.py` already routes a secret-named key whose value is a variable
reference to a benign `variable_reference` finding. Its `_VAR_REF_RE` knows
`${VAR}`, `$VAR`, `$(cmd)`, `%(VAR)s`, ERB and Jinja/Helm `{{ VAR }}` — but not
GitHub Actions' `${{ secrets.NAME }}`:

* the `${VAR}` alternative requires a word character after `${`, and Actions
  syntax has a second `{`
* the Jinja `{{ VAR }}` alternative expects `{{` at the start, and Actions
  values start with `$`

So a workflow doing exactly the right thing —

    ALCHEMY_API_KEY: ${{ secrets.ALCHEMY_API_KEY }}

— was reported as `medium` "Suspicious config key with literal value". On
one tree that is 22 rows across .github/workflows/, all of them wrong, and
they arrive the moment the `secrets` skill is wired into dispatch.

The fix must not weaken literal detection: a real embedded credential in a
workflow file has to keep firing.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills._var_reference import (
    is_variable_reference,
    line_value_is_variable_ref,
)
from cwe_agent.skills.secret_scan.config_files import _is_variable_reference


class TestActionsExpressionRecognised:
    def test_secrets_context(self):
        for v in (
            "${{ secrets.ALCHEMY_API_KEY }}",
            "${{ secrets.GITHUB_TOKEN }}",
            "${{ secrets.E2E_SOLUTIONS_WEBHOOK }}",
            "${{ secrets.CYPRESS_RECORD_KEY }}",
        ):
            assert _is_variable_reference(v), f"{v} is an indirection, not a literal"

    def test_other_actions_contexts(self):
        for v in (
            "${{ env.API_TOKEN }}",
            "${{ vars.REGISTRY }}",
            "${{ inputs.token }}",
            "${{ github.token }}",
        ):
            assert _is_variable_reference(v), f"{v} is an indirection, not a literal"

    def test_quoted_and_padded_forms(self):
        for v in (
            "'${{ secrets.TOKEN }}'",
            '"${{ secrets.TOKEN }}"',
            "  ${{ secrets.TOKEN }}  ",
        ):
            assert _is_variable_reference(v), f"{v!r} should still be recognised"

    def test_pre_existing_forms_still_recognised(self):
        """The additions must not disturb the shapes already covered.

        NB: `$(cmd)` substitution is covered by the shared guard but has never
        been covered here — it is asserted separately below rather than
        smuggled in as a regression pin.
        """
        for v in ("${API_KEY}", "$API_KEY",
                  "%(api_key)s", "{{ api_key }}", "<%= api_key %>"):
            assert _is_variable_reference(v), f"{v} regressed"

    def test_command_substitution_divergence_is_documented(self):
        """`$(vault read …)` exposes a three-way inconsistency, pinned not endorsed.

        * `is_variable_reference` (value level, shared)  — recognises it
        * `_is_variable_reference` (value level, local)  — does NOT
        * `line_value_is_variable_ref` (line level)      — does NOT, because
          `_RHS_CAPTURE` has no `$(...)` alternative, so nothing is extracted

        Pinned as the current state so a future consolidation is a deliberate
        change rather than a silent one. See the DRY note at the end of the file.
        """
        assert is_variable_reference("$(vault read secret/foo)"), \
            "the shared VALUE-level guard covers command substitution"
        assert not _is_variable_reference("$(vault read secret/foo)"), \
            "the local guard does not — if this passes, the regexes were merged"
        assert not line_value_is_variable_ref("KEY: $(vault read secret/foo)"), \
            "_RHS_CAPTURE cannot extract a $(...) RHS — if this passes, it gained one"


class TestLiteralsStillDetected:
    def test_plain_literal_is_not_an_indirection(self):
        for v in ("hunter2", "sk-ABCDEF1234567890", "'AKIAIOSFODNN7EXAMPLE'"):
            assert not _is_variable_reference(v), f"{v} is a literal and must still fire"

    def test_partial_or_malformed_expression_is_not_a_free_pass(self):
        """A literal that merely mentions Actions syntax must not be excused."""
        for v in ("${{ secrets.TOKEN }}-suffix", "prefix-${{ secrets.TOKEN }}",
                  "${{ }}", "${{"):
            assert not _is_variable_reference(v), \
                f"{v!r} is not a clean indirection; it must not suppress the finding"


class TestEndToEndOnAWorkflowFile:
    def _findings(self, body: str) -> list[dict]:
        from cwe_agent.skills import SKILL_MAP
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".github" / "workflows" / "ci.yml"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
            return SKILL_MAP["secrets"](str(d))["findings"]

    def test_correct_workflow_yields_no_medium_or_worse(self):
        body = (
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - run: npm test\n"
            "        env:\n"
            "          ALCHEMY_API_KEY: ${{ secrets.ALCHEMY_API_KEY }}\n"
            "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        )
        bad = [f for f in self._findings(body)
               if f["severity"] in ("medium", "high", "critical")]
        assert not bad, (
            "a workflow using ${{ secrets.* }} correctly must not produce a "
            f"medium+ secret finding; got {[(f['severity'], f['title']) for f in bad]}"
        )

    def test_hardcoded_secret_in_a_workflow_still_fires(self):
        body = (
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - run: npm test\n"
            "        env:\n"
            "          ALCHEMY_API_KEY: 3f8a9c2e1b7d4f6a8e0c2b4d6f8a1c3e\n"
        )
        bad = [f for f in self._findings(body)
               if f["severity"] in ("medium", "high", "critical")]
        assert bad, "an actual literal credential in a workflow must still be reported"


def test_shared_guard_also_understands_actions_syntax():
    """`_var_reference.py` carries a second, near-duplicate regex (DRY debt).

    Both are used for suppression decisions, so a shape recognised by one and
    not the other is a latent inconsistency. Keep them in agreement.
    """
    assert line_value_is_variable_ref("API_KEY: ${{ secrets.API_KEY }}"), \
        "the shared guard must recognise Actions syntax too"

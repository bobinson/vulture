"""CWE-20 must not fire when the guard for the extracted value is right there.

Measured on a real target: 80 of 102 CWE-20 rows had an explicit validation
guard within 25 lines of the flagged extraction. The context window was
line-4..line+3 -- seven lines -- so the commonest real shape (destructure,
THEN guard) fell outside it:

    const { zipCode } = request.body.input ?? {};   <- flagged here
    const userId = request.body.session_variables?.[...];
    if (!zipCode) throw new UserAuthenticationError("ZIPCODE_MISSING");
    if (!POSTAL_CODE_REGEX.test(zipCode)) throw ...

The lookahead is deliberately NOT "any guard nearby": it must reference a
name BOUND ON THE FLAGGED LINE, so an unrelated guard for a different
variable cannot excuse this extraction.
"""

from pathlib import Path

from cwe_agent.skills.input_validation_check import _check_no_validation


def _run(src: str) -> list[dict]:
    lines = src.split("\n")
    found: list[dict] = []
    for i, line in enumerate(lines, start=1):
        _check_no_validation(Path("api/h.ts"), line, i, lines, found)
    return [f for f in found if f["category"] == "CWE-20"]


GUARDED = """\
export default async function handler(request, response) {
  const { zipCode } = request.body.input ?? {};
  const userId = request.body.session_variables?.["x-hasura-user-id"];
  if (!userId) {
    throw new UserAuthenticationError("USERID_MISSING");
  }
  const adminClient = getHasuraAdminClient({ request });
  const extra = buildExtra();
  const more = buildMore();
  const other = buildOther();
  const another = buildAnother();
  if (!zipCode) {
    throw new UserAuthenticationError("ZIPCODE_MISSING");
  }
  if (!POSTAL_CODE_REGEX.test(zipCode)) {
    throw new UserAuthenticationError("INVALID_ZIPCODE");
  }
}
"""

UNGUARDED = """\
export default async function handler(request, response) {
  const { zipCode } = request.body.input ?? {};
  await db.save(zipCode);
}
"""

OTHER_VAR_GUARDED = """\
export default async function handler(request, response) {
  const { zipCode } = request.body.input ?? {};
  if (!somethingElse) {
    throw new UserAuthenticationError("NOPE");
  }
  await db.save(zipCode);
}
"""


class TestGuardLookahead:
    def test_guarded_extraction_is_not_reported(self):
        assert _run(GUARDED) == []

    def test_unguarded_extraction_is_still_reported(self):
        assert len(_run(UNGUARDED)) >= 1

    def test_guard_on_a_different_variable_does_not_excuse(self):
        assert len(_run(OTHER_VAR_GUARDED)) >= 1

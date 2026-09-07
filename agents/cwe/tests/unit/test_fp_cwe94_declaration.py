"""CWE-94 must not fire on a `eval(` that is a DECLARATION, not a call.

Measured on a real target: 3 of the top-20 critical rows were the same false
positive in three files, all of them a TypeScript interface member for a
Redis client:

    isOpen: boolean;
    connect(): Promise<unknown>;
    eval(
      script: string,
      options: { keys: string[]; arguments: string[] },
    ): Promise<unknown>;

That is Redis's EVAL command — Lua scripts for atomic rate limiting — and it
is a type declaration besides: nothing executes, and there is no argument to
be tainted. `CODE_INJECTION_PATTERNS` matched because
`(?<![\\w.\\]\\)])eval\\s*\\(` sees only an indent before `eval(`.

The discriminator is free and syntactic: a parameter TYPE ANNOTATION in the
argument position is impossible in a call expression. `f(a: T)` is not valid
JavaScript, so wherever it appears the construct is a signature.

The same shape already has a precedent here for another language --
`_CMD_DEF_BEFORE` skips a Ruby `def system` / PHP `function system`
definition -- so this closes the TypeScript half of the same class.
"""


from pathlib import Path

from cwe_agent.skills.injection_check import _check_code_injection


def _findings(lines: list[str]) -> list[dict]:
    """Run the CWE-94 arm over every line, as the sweep does."""
    out: list[dict] = []
    for i, line in enumerate(lines, start=1):
        _check_code_injection(Path("/x/client.ts"), line, i, lines, out)
    return out


REDIS_INTERFACE = [
    "interface RedisLikeClient {",
    "  isOpen: boolean;",
    "  connect(): Promise<unknown>;",
    "  eval(",
    "    script: string,",
    "    options: { keys: string[]; arguments: string[] },",
    "  ): Promise<unknown>;",
    "}",
]

REDIS_INTERFACE_SAME_LINE = [
    "interface RedisLikeClient {",
    "  eval(script: string, options: EvalOptions): Promise<unknown>;",
    "}",
]

EXEC_DECLARATION = [
    "interface Runner {",
    "  exec(",
    "    command: string,",
    "  ): Promise<Buffer>;",
    "}",
]

OPTIONAL_MEMBER = [
    "type Client = {",
    "  eval?(script: string): Promise<unknown>;",
    "};",
]

# --- shapes that MUST still fire -------------------------------------------

REAL_EVAL_CALL = [
    "function run(userInput) {",
    "  eval(userInput);",
    "}",
]

REAL_EVAL_MULTILINE = [
    "function run(userInput) {",
    "  eval(",
    "    userInput",
    "  );",
    "}",
]

REAL_EVAL_TERNARY_ARG = [
    "function run(a, b) {",
    "  eval(a ? b : a);",
    "}",
]

REAL_EVAL_OBJECT_ARG = [
    "function run(payload) {",
    "  eval(payload.code);",
    "}",
]

# A call whose argument is a bare object literal with a typed-looking key is
# still a CALL -- `{ a: 1 }` is data, not an annotation.
REAL_EVAL_OBJECT_LITERAL_ARG = [
    "function run(build) {",
    "  eval(build({ mode: 1 }));",
    "}",
]


class TestDeclarationsAreNotCalls:
    def test_multiline_interface_member_does_not_fire(self):
        assert _findings(REDIS_INTERFACE) == [], (
            "a parameter type annotation in the argument position cannot be a call"
        )

    def test_single_line_interface_member_does_not_fire(self):
        assert _findings(REDIS_INTERFACE_SAME_LINE) == []

    def test_exec_declaration_does_not_fire(self):
        assert _findings(EXEC_DECLARATION) == []

    def test_optional_member_does_not_fire(self):
        assert _findings(OPTIONAL_MEMBER) == []


class TestRealCallsStillFire:
    def test_bare_eval_of_user_input(self):
        assert len(_findings(REAL_EVAL_CALL)) == 1

    def test_eval_with_the_argument_on_the_next_line(self):
        """The guard must key off an annotation, not off a bare open paren."""
        assert len(_findings(REAL_EVAL_MULTILINE)) == 1

    def test_eval_with_a_ternary_argument(self):
        """A `?`/`:` pair is not a type annotation."""
        assert len(_findings(REAL_EVAL_TERNARY_ARG)) == 1

    def test_eval_of_a_property(self):
        assert len(_findings(REAL_EVAL_OBJECT_ARG)) == 1

    def test_eval_of_a_call_returning_an_object_literal(self):
        assert len(_findings(REAL_EVAL_OBJECT_LITERAL_ARG)) == 1

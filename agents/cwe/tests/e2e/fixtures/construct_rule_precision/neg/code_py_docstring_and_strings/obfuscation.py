"""Obfuscation helpers.

Detects base64 payloads and
EXPECT-NEXT: clean
exec(compile(...)) invocations.
"""

PATTERNS = [
    ("exec_compile", "exec(compile(...)) dynamic code execution"),  # EXPECT: clean
    ("eval_concat", "eval() with string concatenation"),  # EXPECT: clean
]

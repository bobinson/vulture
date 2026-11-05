import re

_DECLARATION_BEFORE = re.compile(
    r"(?:\b(?:def|function)\s+$)"
    r"|(?:^\s*$)"  # bare member line: `  eval(`   EXPECT: clean
)

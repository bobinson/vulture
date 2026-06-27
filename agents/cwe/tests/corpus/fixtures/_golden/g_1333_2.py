import re

# CWE-1333: nested quantifier compiled at import.
PATTERN = re.compile(r"(\d+)*$")

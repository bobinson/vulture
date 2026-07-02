import re

# CWE-1333: nested quantifier compiled at module load.
PATTERN = re.compile(r"(\d+)*$")

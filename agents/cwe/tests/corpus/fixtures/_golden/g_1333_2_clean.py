import re

# Safe: bounded, non-nested quantifier.
PATTERN = re.compile(r"^\d{1,9}$")

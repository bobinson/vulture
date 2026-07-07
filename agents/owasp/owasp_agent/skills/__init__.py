"""OWASP agent defines no detection skills (feature 0063).

Detection is delegated to the CWE agent; this agent maps CWE findings onto
OWASP Top 10 categories. See ``owasp_agent/agent.py``. The two empty names
below are kept so generic tooling expecting the scan-agent shape does not
break.
"""

SKILL_MAP: dict = {}
SKILL_TOOLS: list = []

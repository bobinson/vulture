"""CWE Weakness Auditor agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from cwe_agent.agent import run_audit
from cwe_agent.catalog import preload as preload_catalog
from cwe_agent.config import AGENT_INFO

# Warm the 2 MB CWE catalog at import time so the first request doesn't
# stall behind parsing it. Subsequent skill threads find it already in
# the lru_cache and skip the lock-serialized first-call path.
preload_catalog()

app = create_sse_app(
    agent_name="cwe",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)

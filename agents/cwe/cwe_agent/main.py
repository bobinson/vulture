"""CWE Weakness Auditor agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from cwe_agent.agent import run_audit
from cwe_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="cwe",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)

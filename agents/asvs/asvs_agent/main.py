"""ASVS Compliance Auditor agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from asvs_agent.agent import run_audit
from asvs_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="asvs",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)

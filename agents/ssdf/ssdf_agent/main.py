"""NIST SSDF v1.1 agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from ssdf_agent.agent import run_audit
from ssdf_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="ssdf",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)

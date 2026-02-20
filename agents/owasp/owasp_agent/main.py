"""OWASP Security agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from owasp_agent.agent import run_audit
from owasp_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="owasp",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)

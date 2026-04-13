"""XSS vulnerability scanner agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from xss_agent.agent import run_audit
from xss_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="xss",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)

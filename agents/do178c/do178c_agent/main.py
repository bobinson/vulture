"""DO-178C Compliance agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from do178c_agent.agent import run_audit
from do178c_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="do178c",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)

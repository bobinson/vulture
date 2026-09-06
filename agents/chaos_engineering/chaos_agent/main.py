"""Chaos Engineering agent FastAPI application."""

from chaos_agent.agent import run_audit
from chaos_agent.config import AGENT_INFO
from shared.transport.sse_app import create_sse_app

app = create_sse_app(
    agent_name="chaos_engineering",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)

"""Discover agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from discover_agent.agent import run_discover
from discover_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="discover",
    agent_info=AGENT_INFO,
    run_handler=run_discover,
)

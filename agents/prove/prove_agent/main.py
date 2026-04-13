"""Prove agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from prove_agent.agent import run_prove
from prove_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="prove",
    agent_info=AGENT_INFO,
    run_handler=run_prove,
)

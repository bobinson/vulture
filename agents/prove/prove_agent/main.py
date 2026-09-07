"""Prove agent FastAPI application."""

from prove_agent.agent import run_prove
from prove_agent.config import AGENT_INFO
from shared.transport.sse_app import create_sse_app

app = create_sse_app(
    agent_name="prove",
    agent_info=AGENT_INFO,
    run_handler=run_prove,
)

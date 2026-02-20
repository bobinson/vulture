"""SOC2 Compliance agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from soc2_agent.agent import run_audit
from soc2_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="soc2",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)

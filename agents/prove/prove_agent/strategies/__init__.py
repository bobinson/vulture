"""Strategy registry for finding verification."""

from prove_agent.strategies.owasp import OwaspStrategy
from prove_agent.strategies.chaos import ChaosStrategy
from prove_agent.strategies.soc2 import Soc2Strategy
from prove_agent.strategies.cwe import CweStrategy
from prove_agent.strategies.ssdf import SsdfStrategy

STRATEGY_MAP: dict[str, type] = {
    "owasp": OwaspStrategy,
    "chaos": ChaosStrategy,
    "soc2": Soc2Strategy,
    "cwe": CweStrategy,
    "ssdf": SsdfStrategy,
}

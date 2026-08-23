"""Base agent factory."""

from typing import Any

from agents import Agent, ModelSettings

from shared.llm.provider import get_model


def create_agent(
    name: str,
    instructions: str,
    tools: list[Any],
    model: str | None = None,
) -> Agent:
    """Create an OpenAI Agents SDK agent with resolved model.

    Args:
        name: Agent display name.
        instructions: System instructions for the agent.
        tools: List of @function_tool decorated tools.
        model: Optional model preference.

    Returns:
        Configured Agent instance.
    """
    resolved = get_model(model)
    # temperature=0.1 narrows sampling. It does NOT make an audit
    # reproducible, and the previous comment here claimed it did.
    #
    # Measured (feature 0076, E1): re-running the SAME commit reproduced only
    # 30.4% of findings by Dice overlap, at counts of 21/35/20/39 across four
    # runs of unchanged code. A low temperature only skews the token
    # distribution toward the argmax; the residual nondeterminism lives BELOW
    # this codebase — continuous-batching reduction order, non-batch-invariant
    # kernels, MoE expert routing, KV-cache reuse — and no client-side setting
    # reaches any of it. No seed is pinned either: ``ModelSettings``
    # (agents 0.17.7) has no ``seed`` field, delivery would have to go through
    # ``extra_args``, and litellm raises ``UnsupportedParamsError`` for gemini
    # and anthropic with ``drop_params=False``. At temperature 0 a seed is a
    # no-op anyway — greedy decoding never consults the sampler RNG.
    #
    # What 0.1 actually buys: fewer low-probability excursions, so structured
    # output stays well-formed and findings stay on-format. Verifiability is
    # the job of the anchor/quote verifier (0076), never of the sampler.
    #
    # prompt_cache_retention is available in newer SDK versions for cost savings.
    settings = ModelSettings(temperature=0.1)
    return Agent(
        name=name,
        instructions=instructions,
        tools=tools,
        model=resolved,
        model_settings=settings,
    )

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
    # temperature=0.1 ensures deterministic, reproducible audit results.
    # prompt_cache_retention is available in newer SDK versions for cost savings.
    settings = ModelSettings(temperature=0.1)
    return Agent(
        name=name,
        instructions=instructions,
        tools=tools,
        model=resolved,
        model_settings=settings,
    )

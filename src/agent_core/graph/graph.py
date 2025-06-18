import logging
from typing import Any

from langchain_core.runnables.config import RunnableConfig
from langgraph.graph.state import CompiledStateGraph


async def run_graph(
    graph: CompiledStateGraph, state: dict[str, Any] | None, config: RunnableConfig
) -> dict[str, Any] | Any | None:
    res = None
    """Run the graph with the initial state and print event details."""
    async for event in graph.astream(state, config=config):
        logging.info("Event received: %s", event)
        res = event

    return res

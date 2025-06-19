import logging
from dataclasses import dataclass
from typing import Literal

from langchain_core.messages import AIMessage

from target_scan_agent.state import (
    TargetScanState,
    Tool,
    ToolsCalls,
    ToolType,
    get_tools,
)


@dataclass
class ToolRouterEdge:
    origin_node: str
    end_node: str
    tools_node: str

    tools_type: ToolType

    def __call__(self, state: TargetScanState) -> str:
        """Route based on tool calls and limits"""
        last_message = state["messages"][-1]
        call_count = state["call_count"]
        max_calls = state["max_calls"]
        tools = [t.name for t in get_tools(state["tools"], self.tools_type)]
        calls = state["tools_calls"]

        if call_count >= max_calls:
            return self.end_node

        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return self.tools_node

        if not calls.is_limit_reached(tools):
            print(
                f"Limit is not reached: tools = {tools}, calls = {calls}, origin_node = {self.origin_node}"
            )
            return self.origin_node

        logging.info(
            f"ToolRouterEdge: No tool calls found in the last message. "
            f"Call count: {call_count}, Max calls: {max_calls}. "
            f"Routing to end node: {self.end_node}. "
            f"Last message: {last_message}"
        )
        return self.end_node

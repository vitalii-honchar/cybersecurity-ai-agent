from typing import Literal
from langchain_core.messages import AIMessage
from dataclasses import dataclass
from agent_core.state import ReActAgentState
import logging


@dataclass
class ToolRouterEdge[StateT: ReActAgentState]:
    origin_node: str
    end_node: str
    tools_node: str

    def __call__(self, state: StateT) -> str:
        """Route based on tool calls and limits"""
        last_message = state["messages"][-1]
        usage = state["usage"]
        tools_usage = state["tools_usage"]
        tools = state["tools"]
        tools_names = [t.name for t in tools.tools]

        if usage.is_limit_reached():
            return self.end_node

        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return self.tools_node

        if not tools_usage.is_limit_reached(tools_names):
            return self.origin_node

        return self.end_node

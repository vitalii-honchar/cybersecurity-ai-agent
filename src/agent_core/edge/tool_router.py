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
            logging.info(
                "Limit is reached, routing to end node: usage = %s, end_node = %s",
                usage,
                self.end_node,
            )
            return self.end_node

        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            logging.info("Routing to tools node: %s", self.tools_node)
            return self.tools_node

        if not tools_usage.is_limit_reached(tools_names):
            logging.info(
                "Limit is not reached: tools = %s, usage = %s, origin_node = %s",
                tools_names,
                tools_usage,
                self.origin_node,
            )
            return self.origin_node

        logging.info(
            "ToolRouterEdge: No tool calls found in the last message. "
            "Usage limit reached. Routing to end node: %s. "
            "Last message: %s",
            self.end_node,
            last_message,
        )
        return self.end_node

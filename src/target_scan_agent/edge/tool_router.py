from typing import Literal
from langchain_core.messages import AIMessage
from target_scan_agent.state import TargetScanState


class ToolRouterEdge:

    def route(self, state: TargetScanState) -> Literal["tools", "generate_report"]:
        """Route based on tool calls and limits"""
        last_message = state["messages"][-1]
        call_count = state["call_count"]
        max_calls = state["max_calls"]

        if call_count >= max_calls:
            return "generate_report"

        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"

        return "generate_report"

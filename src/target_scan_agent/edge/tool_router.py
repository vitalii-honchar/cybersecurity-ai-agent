from typing import Literal
from langchain_core.messages import AIMessage
from target_scan_agent.state import TargetScanState


class ToolRouterEdge:

    def route(self, state: TargetScanState) -> Literal["tools", "generate_report"]:
        """Route based on tool calls and call limits"""
        last_message = state["messages"][-1]

        # Hit the limit - generate final report
        if len(state["results"]) >= 5:
            return "generate_report"

        # LLM wants to use tools and we haven't hit limit
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"

        # No more tools needed - generate report
        return "generate_report"

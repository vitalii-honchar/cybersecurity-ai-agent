from typing import Literal
from langchain_core.messages import AIMessage
from target_scan_agent.state import TargetScanState

# Import the tool calling limit from assistant node
TOOLS_CALLING_LIMIT = 50


class ToolRouterEdge:

    def route(self, state: TargetScanState) -> Literal["tools", "generate_report"]:
        """Route based on tool calls and call limits"""
        last_message = state["messages"][-1]
        call_count = state.get("call_count", 0)

        # Hit the tool calling limit - generate final report
        if call_count >= TOOLS_CALLING_LIMIT:
            return "generate_report"

        # LLM wants to use tools and we haven't hit limit
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"

        # No more tools needed or LLM decided to stop - generate report
        return "generate_report"

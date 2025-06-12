from typing import Literal
from langchain_core.messages import AIMessage
from target_scan_agent.state import TargetScanState


class ToolRouterEdge:

    def route(self, state: TargetScanState) -> Literal["tools", "generate_report"]:
        """Route based on tool calls and limits"""
        last_message = state["messages"][-1]
        call_count = state["call_count"]
        max_calls = state["max_calls"]

        # Hit the global call limit - generate final report
        if call_count >= max_calls:
            return "generate_report"

        # Check if no tools are available at all
        if not self.has_tools_available(state):
            return "generate_report"

        # LLM wants to use tools - let them execute
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"

        # No tools requested or LLM decided to stop - generate report
        return "generate_report"

    def has_tools_available(self, state: TargetScanState) -> bool:
        """Check if any tools are still available within their limits"""
        tools_calls = state["tools_calls"]

        return (
            tools_calls.nuclei_calls_count < tools_calls.nuclei_calls_count_max
            or tools_calls.ffuf_calls_count < tools_calls.ffuf_calls_count_max
            or tools_calls.curl_calls_count < tools_calls.curl_calls_count_max
        )

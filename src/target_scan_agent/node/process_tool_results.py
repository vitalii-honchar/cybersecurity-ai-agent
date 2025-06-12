from target_scan_agent.state import (
    TargetScanState,
    TargetScanToolResult,
    ToolsCalls,
)
from target_scan_agent.tools.vulnerability.models import NucleiScanResult
from langchain_openai import ChatOpenAI
from langchain_core.messages import (
    ToolMessage,
    AnyMessage,
    AIMessage,
)
import logging
from dataclasses import dataclass


@dataclass
class ProcessToolResultNode:
    llm: ChatOpenAI

    def process_tool_results(self, state: TargetScanState):
        messages = state["messages"]
        tools_calls = state["tools_calls"]
        new_results = []

        results = state.get("results", [])

        call_id_to_result = {
            result.tool_call_id: result for result in results if result.tool_call_id
        }

        for msg in reversed(messages):
            if isinstance(msg, ToolMessage):
                if not call_id_to_result.get(msg.tool_call_id):
                    self._increment_tool_call_count(tools_calls, msg.name)
                    res = TargetScanToolResult(
                        result=str(msg.content),
                        tool_name=msg.name,
                        tool_arguments=self._find_tool_call_args(
                            messages, msg.tool_call_id
                        ),
                        tool_call_id=msg.tool_call_id,
                    )
                    new_results.append(res)

        return {
            "results": list(reversed(new_results)),
            "tools_calls": tools_calls,
        }

    def _find_tool_call_args(
        self, messages: list[AnyMessage], tool_call_id: str
    ) -> dict | None:
        for msg in reversed(messages):
            if isinstance(msg, AIMessage):
                for tool_call in msg.tool_calls:
                    if tool_call.get("id") == tool_call_id:
                        return tool_call.get("args")

    def _increment_tool_call_count(
        self, tools_calls: ToolsCalls, tool_name: str | None
    ):
        """Increment the tool call count based on the tool name."""
        if tool_name == "nuclei_scan_tool":
            tools_calls.nuclei_calls_count += 1
        elif tool_name == "ffuf_directory_scan":
            tools_calls.ffuf_calls_count += 1
        elif tool_name == "curl_tool":
            tools_calls.curl_calls_count += 1
        else:
            logging.warning(f"Unknown tool name: {tool_name}")

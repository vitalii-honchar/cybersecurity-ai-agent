from target_scan_agent.state import TargetScanState, TargetScan
from target_scan_agent.tools.vulnerability.models import NucleiScanResult
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
import json
import logging
from dataclasses import dataclass

system_prompt = """You are a cybersecurity expert analyzing tool execution results. 
Your task is to create a concise, actionable summary of the tool results.

For vulnerability scans (nuclei): Focus on severity, vulnerability types, and affected endpoints
For directory discovery (ffuf): Focus on discovered paths, interesting files, and potential attack vectors
For HTTP requests: Focus on response codes, interesting headers, and potential security issues

Return a TargetScan object with:
- name: Brief scan name (e.g., "Nuclei Vulnerability Scan", "Directory Discovery")
- severity: Use "critical", "high", "medium", "low", "info" or null based on findings
- description: Detailed summary of findings and their security implications
- possible_attacks: List of specific attack vectors or next steps with command examples

Keep descriptions concise but informative. Focus on actionable security insights."""

human_prompt = """Tool: {tool}
Tool Results: {tool_data}

Please analyze these tool results and provide a security-focused summary."""


@dataclass
class ProcessToolResultNode:
    llm: ChatOpenAI

    def process_tool_results(self, state: TargetScanState):
        messages = state["messages"]
        new_results = []
        call_count = state.get("call_count", 0)
        for msg in reversed(messages):
            if hasattr(msg, "type") and msg.type == "tool":
                call_count += 1
                processed_result = self._process_tool_message_with_llm(msg)
                new_results.append(processed_result)
            else:
                break

        return {"results": list(reversed(new_results)), "call_count": call_count}

    def _process_tool_message_with_llm(self, msg) -> TargetScan:
        """Process tool message using LLM to create intelligent summary."""
        tool_data = json.dumps(msg.content, indent=2)

        res = self.llm.with_structured_output(TargetScan).invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(
                    content=human_prompt.format(tool=msg.name, tool_data=tool_data)
                ),
            ]
        )

        if isinstance(res, TargetScan):
            return res
        raise ValueError("LLM did not return a valid TargetScan object")

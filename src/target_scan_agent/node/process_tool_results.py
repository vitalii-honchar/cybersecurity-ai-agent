from target_scan_agent.state import (
    TargetScanState,
    TargetScanToolResult,
    ToolsCalls,
    TargetScanToolSummary,
)
from target_scan_agent.tools.vulnerability.models import NucleiScanResult
from langchain_openai import ChatOpenAI
from langchain_core.messages import (
    SystemMessage,
    HumanMessage,
    ToolMessage,
    ToolCall,
    AnyMessage,
    AIMessage,
)
import json
import logging
from dataclasses import dataclass

system_prompt = """You are a senior cybersecurity analyst specializing in vulnerability assessment and threat analysis. Analyze tool execution results and provide actionable intelligence.

ANALYSIS FRAMEWORK:

NUCLEI SCAN RESULTS:
- Severity Classification:
  * CRITICAL: RCE, SQL injection, authentication bypass, sensitive data exposure
  * HIGH: XSS, CSRF, directory traversal, privilege escalation
  * MEDIUM: Information disclosure, misconfigurations, weak authentication
  * LOW: Version disclosure, fingerprinting, non-exploitable findings
  * INFO: General reconnaissance data, technology identification
- Focus on: Exploit details, affected URLs, payload evidence, impact assessment

DIRECTORY DISCOVERY (FFUF):
- Severity Classification:
  * HIGH: Admin panels, config files, database files, backup files
  * MEDIUM: Interesting directories, potential upload locations, API endpoints
  * LOW: Common directories, standard files, informational findings
- Focus on: Sensitive paths, file types, status codes, potential entry points

HTTP REQUESTS (CURL):
- Severity Classification:
  * CRITICAL: Authentication bypass, injection confirmations, data access
  * HIGH: Sensitive information in responses, authentication weaknesses
  * MEDIUM: Interesting headers, response patterns, potential issues
  * LOW: Standard responses, version information, general behavior
- Focus on: Response codes, headers, body content, authentication status

OUTPUT REQUIREMENTS:
- name: Descriptive scan identifier with key finding (e.g., "Admin Panel Discovery", "SQL Injection Confirmed")
- severity: Use exact values: "critical", "high", "medium", "low", "info", or null
- description: Technical summary with specific evidence (URLs, parameters, response codes)
- possible_attacks: Concrete next steps with specific commands, not generic suggestions

CRITICAL: Always include specific technical evidence. Avoid generic statements."""

human_prompt = """Tool: {tool}
Tool Results: {tool_data}

Please analyze these tool results and provide a security-focused summary."""


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
                        summary=self._generate_tool_result_summary(msg),
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

    def _generate_tool_result_summary(self, msg: ToolMessage) -> TargetScanToolSummary:
        """Generate a summary for the tool result using LLM."""

        summary = self.llm.with_structured_output(TargetScanToolSummary).invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(
                    content=human_prompt.format(tool=msg.name, tool_data=msg.content)
                ),
            ]
        )

        return TargetScanToolSummary.model_validate(summary)

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

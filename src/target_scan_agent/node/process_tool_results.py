from target_scan_agent.state import TargetScanState, TargetScan, ToolsCalls
from target_scan_agent.tools.vulnerability.models import NucleiScanResult
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
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
        tools_calls = state.get("tools_calls", ToolsCalls())
        new_results = []
        call_count = state.get("call_count", 0)

        for msg in reversed(messages):
            if hasattr(msg, "type") and msg.type == "tool":
                call_count += 1

                # Increment tool-specific counters based on tool name
                if msg.name == "nuclei_scan_tool":
                    tools_calls.nuclei_calls_count += 1
                elif msg.name == "ffuf_directory_scan":
                    tools_calls.ffuf_calls_count += 1
                elif msg.name == "curl_tool":
                    tools_calls.curl_calls_count += 1

                processed_result = self._process_tool_message_with_llm(msg)
                new_results.append(processed_result)
            else:
                break

        return {
            "results": list(reversed(new_results)),
            "call_count": call_count,
            "tools_calls": tools_calls,
        }

    def _process_tool_message_with_llm(self, msg) -> TargetScan:
        """Process tool message using LLM to create intelligent summary."""
        res = self.llm.with_structured_output(TargetScan).invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(
                    content=human_prompt.format(tool=msg.name, tool_data=msg.content)
                ),
            ]
        )

        if isinstance(res, TargetScan):
            return res
        raise ValueError("LLM did not return a valid TargetScan object")

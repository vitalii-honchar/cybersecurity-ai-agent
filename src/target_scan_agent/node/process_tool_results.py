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
        
        # Find the AI message with tool calls to get original call info
        ai_message_with_tool_calls = None
        for msg in reversed(messages):
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                ai_message_with_tool_calls = msg
                break

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

                # Find the original tool call info for this tool result
                tool_call_id = msg.tool_call_id if hasattr(msg, 'tool_call_id') else None
                original_tool_call = self._find_original_tool_call(
                    ai_message_with_tool_calls, msg.name, tool_call_id
                )
                
                processed_result = self._process_tool_message_with_llm(msg, original_tool_call)
                new_results.append(processed_result)
            else:
                break

        return {
            "results": list(reversed(new_results)),
            "call_count": call_count,
            "tools_calls": tools_calls,
        }

    def _find_original_tool_call(self, ai_message, tool_name: str, tool_call_id: str | None = None) -> dict | None:
        """Find the original tool call that matches the tool result."""
        if not ai_message or not hasattr(ai_message, 'tool_calls'):
            return None
        
        for tool_call in ai_message.tool_calls:
            # Match by tool_call_id if available, otherwise by tool name
            if tool_call_id and tool_call.get('id') == tool_call_id:
                return tool_call
            elif tool_call.get('name') == tool_name:
                return tool_call
        
        return None

    def _process_tool_message_with_llm(self, msg, original_tool_call: dict | None = None) -> TargetScan:
        """Process tool message using LLM to create intelligent summary."""
        # Convert tool result to JSON for better LLM parsing
        if hasattr(msg.content, 'to_json'):
            tool_data = msg.content.to_json()
        elif hasattr(msg.content, 'to_dict'):
            tool_data = json.dumps(msg.content.to_dict(), indent=2)
        else:
            tool_data = json.dumps(msg.content, indent=2, default=str)

        res = self.llm.with_structured_output(TargetScan).invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(
                    content=human_prompt.format(tool=msg.name, tool_data=tool_data)
                ),
            ]
        )

        if isinstance(res, TargetScan):
            # Add the original tool call information to avoid duplicates
            if original_tool_call:
                res.tool_name = original_tool_call.get('name')
                res.tool_arguments = original_tool_call.get('args', {})
                res.tool_call_id = original_tool_call.get('id')
            else:
                # Fallback if we couldn't find the original call
                res.tool_name = msg.name
                res.tool_arguments = {}
                res.tool_call_id = None
            
            return res
        raise ValueError("LLM did not return a valid TargetScan object")

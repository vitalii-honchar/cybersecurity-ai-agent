import json
from dataclasses import dataclass
from typing import Any, Dict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from target_scan_agent.state import (
    TargetScanOutput,
    TargetScanState,
    ToolType,
    get_tools,
)

system_prompt = """You are a senior penetration tester creating a comprehensive security report. Generate a detailed, professional security assessment based on the provided scan and attack results.

TARGET: {target}
DESCRIPTION: {description}
EXECUTION DATA: {context}

You must analyze ALL provided intelligence and create a complete security report. The report should be structured, comprehensive, and include all discovered vulnerabilities, leaked data, and attack evidence."""

human_prompt = """Generate a COMPLETE security assessment report for {url} using the provided intelligence data.

INTELLIGENCE DATA:
{scan_context}

Your report must be comprehensive and professional. Structure it with:

1. Executive Summary with overall risk assessment
2. Critical Findings organized by severity
3. Detailed vulnerability analysis with proof-of-concept evidence
4. Technology stack discovered
5. Attack vectors and exploitation scenarios
6. Technical evidence from scans and attacks
7. Comprehensive remediation recommendations

Extract ALL actual data from the intelligence including:
- Specific vulnerabilities found
- Actual leaked data (usernames, emails, system info)
- Exact commands used for discovery and exploitation
- Real HTTP responses and system outputs
- Technology versions and configurations
- Successful attack demonstrations

Create a detailed, actionable security report that demonstrates the complete security posture of the target based on the reconnaissance and attack intelligence provided.

Focus on factual findings supported by the actual scan and attack results. Include specific technical details, commands, and evidence from the tool executions."""


@dataclass
class GenerateReportNode:
    llm: ChatOpenAI

    def generate_report(self, state: TargetScanState) -> Dict[str, Any]:
        """Generate a comprehensive security report based on all available intelligence."""
        target = state["target"]
        timeout = state["timeout"]
        tools_calls = state["tools_calls"]
        results = state["results"]

        # Build comprehensive context
        available_tools = [t.to_dict() for t in state["tools"]]
        scan_results = state.get("scan_results", [])
        attack_results = state.get("attack_results", [])
        tools_results = [r.to_dict() for r in results] if results else []

        context = {
            "available_tools": available_tools,
            "scan_results": scan_results,
            "attack_results": attack_results,
            "tools_results": tools_results,
            "execution_summary": {
                "total_tools_available": len(available_tools),
                "scan_phases_completed": len(scan_results),
                "attack_phases_completed": len(attack_results),
                "total_tool_executions": len(tools_results),
            },
        }

        scan_context = json.dumps(context, indent=2)
        formatted_system_prompt = system_prompt.format(
            target=target.url,
            description=target.description,
            context=scan_context,
        )

        report_messages = [
            SystemMessage(content=formatted_system_prompt),
            HumanMessage(
                content=human_prompt.format(url=target.url, scan_context=scan_context)
            ),
        ]

        response = self.llm.with_structured_output(TargetScanOutput).invoke(
            report_messages
        )

        return {
            "report": response,
        }

    def __call__(self, state: TargetScanState) -> Dict[str, Any]:
        """Make the node callable for LangGraph."""
        return self.generate_report(state)

from target_scan_agent.state import (
    TargetScanState,
    TargetScanOutput,
    get_tools,
    ToolType,
)
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from dataclasses import dataclass
from typing import Dict, Any
import json

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

        # Comprehensive context with all intelligence sources
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

        print("Context for report generation:", json.dumps(context, indent=2))
        scan_context = json.dumps(context, indent=2)

        try:
            # Use formatted system prompt
            formatted_system_prompt = system_prompt.format(
                target=target.url,
                description=target.description,
                context=scan_context,
            )

            report_messages = [
                SystemMessage(content=formatted_system_prompt),
                HumanMessage(
                    content=human_prompt.format(
                        url=target.url, 
                        scan_context=scan_context
                    )
                ),
            ]
            
            # Try structured output first, fall back to regular response
            try:
                response = self.llm.with_structured_output(TargetScanOutput).invoke(
                    report_messages
                )
                
                # Check if we got a valid structured response
                if isinstance(response, TargetScanOutput) and response.summary:
                    return {"summary": response.summary, "scan_output": response}
                else:
                    # If structured output failed, get regular response
                    regular_response = self.llm.invoke(report_messages)
                    report_content = regular_response.content if hasattr(regular_response, 'content') else str(regular_response)
                    
                    # Create TargetScanOutput manually
                    scan_output = TargetScanOutput(summary=report_content)
                    return {"summary": report_content, "scan_output": scan_output}
                    
            except Exception as structured_error:
                print(f"Structured output failed: {structured_error}")
                # Fall back to regular LLM call
                regular_response = self.llm.invoke(report_messages)
                report_content = regular_response.content if hasattr(regular_response, 'content') else str(regular_response)
                
                # Create TargetScanOutput manually
                scan_output = TargetScanOutput(summary=report_content)
                return {"summary": report_content, "scan_output": scan_output}

        except Exception as e:
            print(f"Report generation error: {str(e)}")
            # Generate basic report from available data
            basic_report = self._generate_basic_report(context, target.url)
            scan_output = TargetScanOutput(summary=basic_report)
            return {"summary": basic_report, "scan_output": scan_output}

    def _generate_basic_report(self, context: Dict[str, Any], target_url: str) -> str:
        """Generate a basic report when LLM fails."""
        
        # Extract key information from context
        tools_results = context.get("tools_results", [])
        scan_results = context.get("scan_results", [])
        attack_results = context.get("attack_results", [])
        
        report_parts = [
            f"# Security Assessment Report for {target_url}",
            "",
            "## Executive Summary",
            f"- Target: {target_url}",
            f"- Tools executed: {len(tools_results)}",
            f"- Scan phases completed: {len(scan_results)}",
            f"- Attack phases completed: {len(attack_results)}",
            "",
            "## Discovered Endpoints"
        ]
        
        # Extract discovered endpoints from tools results
        for tool_result in tools_results:
            if tool_result.get("tool_name") == "ffuf_directory_scan":
                result_data = json.loads(tool_result.get("result", "{}"))
                findings = result_data.get("findings", [])
                for finding in findings:
                    report_parts.append(f"- {finding.get('url')} (Status: {finding.get('status')})")
        
        report_parts.extend([
            "",
            "## Attack Attempts",
        ])
        
        # Extract attack information
        for tool_result in tools_results:
            if tool_result.get("tool_name") == "curl_tool":
                args = tool_result.get("tool_arguments", {})
                curl_args = args.get("curl_args", "")
                report_parts.append(f"- Attack: {curl_args}")
        
        report_parts.extend([
            "",
            "## Recommendations",
            "- Review discovered endpoints for proper authentication",
            "- Implement input validation on all endpoints",
            "- Review server configuration and security headers",
            "",
            "## Technical Details",
            "Raw scan and attack data available in execution logs."
        ])
        
        return "\n".join(report_parts)

    def __call__(self, state: TargetScanState) -> Dict[str, Any]:
        """Make the node callable for LangGraph."""
        return self.generate_report(state)
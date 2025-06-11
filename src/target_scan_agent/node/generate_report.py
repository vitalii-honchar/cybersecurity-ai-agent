from target_scan_agent.state import TargetScanState, TargetScanOutput
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class GenerateReportNode:
    llm: ChatOpenAI

    def generate_report(self, state: TargetScanState) -> Dict[str, Any]:
        """Generate a factual security scan report based only on actual findings."""
        messages = state["messages"]
        target = state["target"]
        results = state.get("results", [])

        # Build context from all scan results
        scan_context = self._build_scan_context(results)

        report_prompt = f"""You are a senior penetration tester creating a comprehensive security assessment report for {target.url}.

SCAN RESULTS DATA:
{scan_context}

Generate a professional security report with the following structure:

## EXECUTIVE SUMMARY
- Overall security posture assessment
- Key risk areas identified
- Critical findings count and severity breakdown

## DISCOVERED TECHNOLOGIES
List all identified technologies with versions when available:
- Web servers, frameworks, CMS platforms
- Programming languages, databases
- Third-party services and plugins
- Operating system and infrastructure details

## VULNERABILITY FINDINGS
Organize by severity (Critical → High → Medium → Low → Info):
For each vulnerability include:
- **Vulnerability Name**: Clear, descriptive title
- **Severity**: Critical/High/Medium/Low/Info with justification
- **Location**: Specific URLs, endpoints, parameters affected
- **Evidence**: Technical proof (status codes, responses, payloads)
- **Impact**: Potential consequences if exploited
- **Exploitation Details**: How the vulnerability can be leveraged

## SECURITY INSIGHTS
- Exposed endpoints and interesting discoveries
- Configuration issues and misconfigurations
- Information disclosure findings
- Attack surface analysis
- Security controls observed (or lack thereof)

## TECHNICAL APPENDIX
- Detailed tool outputs for verification
- Request/response examples for critical findings
- Proof-of-concept commands where applicable

FORMATTING REQUIREMENTS:
- Use markdown formatting for structure
- Include specific technical evidence for all claims
- Prioritize findings by exploitability and impact
- Maintain professional, technical language
- If no findings in a section, state "No findings identified"

Focus on actionable intelligence that demonstrates actual security posture and confirmed vulnerabilities."""

        try:
            report_messages = [HumanMessage(report_prompt)]
            response = self.llm.with_structured_output(TargetScanOutput).invoke(
                report_messages
            )

            if isinstance(response, TargetScanOutput) and response.summary:
                return {"summary": response.summary, "scan_output": response}
            else:
                return {"summary": "No scan results to report.", "scan_output": None}

        except Exception as e:
            return {
                "summary": f"Report generation failed: {str(e)}",
                "scan_output": None,
            }

    def _build_scan_context(self, results) -> str:
        """Build organized context from scan results."""
        if not results:
            return "No scan results available."

        context_parts = []

        for i, result in enumerate(results, 1):
            if hasattr(result, "scan_result") and result.scan_result:
                # Clean up the scan result for better context
                scan_text = result.scan_result.strip()
                context_parts.append(f"=== SCAN {i} ===\n{scan_text}")

        return (
            "\n\n".join(context_parts)
            if context_parts
            else "No valid scan results found."
        )

    def __call__(self, state: TargetScanState) -> Dict[str, Any]:
        """Make the node callable for LangGraph."""
        return self.generate_report(state)

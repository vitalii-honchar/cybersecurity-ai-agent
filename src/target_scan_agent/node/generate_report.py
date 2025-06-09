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

        report_prompt = f"""You are a security analyst creating a factual report based on completed scans of {target.url}.

SCAN RESULTS:
{scan_context}

Create a concise security report that includes ONLY what was actually discovered during the scans. Do NOT include recommendations, suggestions, or assumptions.

REPORT SECTIONS:
1. **Found Technologies**: List any identified technologies, frameworks, server software, or services that were detected
2. **Found Vulnerabilities**: List any confirmed vulnerabilities discovered with specific details (endpoints, parameters, evidence)
3. **Found Insights**: Notable findings like exposed endpoints, unusual responses, configuration details, or security-relevant information

IMPORTANT RULES:
- Report ONLY confirmed findings from the actual scan results
- Do NOT suggest additional testing or recommendations  
- Do NOT mention tools that could be used
- Do NOT speculate about potential vulnerabilities
- If no findings in a category, state "None detected" for that section
- Be specific with URLs, status codes, and evidence when available
- Focus on facts, not possibilities

Format your response as a clear, structured report."""

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

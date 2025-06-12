from target_scan_agent.state import TargetScanState, TargetScanOutput
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from dataclasses import dataclass
from typing import Dict, Any
import json

system_prompt = """You are a senior penetration tester with extensive experience in security assessments. Your role is to create comprehensive, professional security reports based on technical scan results.

Your expertise includes:
- Vulnerability assessment and analysis
- Risk prioritization and impact evaluation
- Technical evidence interpretation
- Professional security reporting standards
- Exploit development and attack vector analysis
- Data exfiltration and impact assessment

You analyze scan results objectively and present findings in a detailed, actionable format that helps stakeholders understand their security posture. Your reports must be comprehensive and include specific examples of leaked data, exact attack commands, and detailed exploitation scenarios that demonstrate the real-world impact of vulnerabilities."""

human_prompt = """You must generate a COMPLETE, COMPREHENSIVE security assessment report for {url}. This is NOT a summary - this is the FULL detailed report that will be the final output.

SCAN RESULTS DATA:
{scan_context}

CRITICAL INSTRUCTIONS:
- Analyze the scan results data above and extract ALL specific information
- Include ALL actual leaked data found in the scans (usernames, emails, system info, etc.)
- Use the actual tool results to populate the report sections
- Generate the COMPLETE detailed report using this structure - NOT a brief summary

You MUST generate the complete report using this EXACT structure and formatting:

# 🔒 SECURITY ASSESSMENT REPORT FOR {url}

## 🚨 EXECUTIVE SUMMARY
**Overall Risk Level:** [Determine from scan results]
**Total Vulnerabilities Found:** [Count from actual scan results by severity]
**Immediate Actions Required:** [Based on actual findings]
**Attack Surface:** [Based on discovered endpoints and data]

## 🎯 CRITICAL FINDINGS (Sorted by Severity)

[FOR EACH vulnerability found in the scan results, create a section organized by severity:]

### 🔴 CRITICAL SEVERITY VULNERABILITIES
[If any critical vulnerabilities found, list them here]

### 🟠 HIGH SEVERITY VULNERABILITIES
[For each HIGH severity finding from scan results:]
#### 🔍 [Vulnerability Name from scan]
- **📍 Location:** [Exact URL/endpoint from scan]
- **💥 Impact:** [Detailed consequences based on scan data]
- **🔓 Leaked Data:** [Extract ALL actual leaked data from scan results]
- **⚡ Exploitation Commands:**
  ```bash
  [Exact command from scan results that found this]
  ```
- **🎯 Attack Scenario:** [Based on the actual vulnerability found]
- **🛡️ Remediation:** [Specific fix for this vulnerability]

### 🟡 MEDIUM SEVERITY VULNERABILITIES
[Same format for each medium severity finding]

### 🟢 LOW SEVERITY VULNERABILITIES
[Same format for each low severity finding]

## 📊 LEAKED DATA ANALYSIS
**Data Categories Found:** [Extract from actual scan results]
- **Usernames:** [List actual usernames found in scans]
- **Email Addresses:** [List actual emails found in scans]
- **System Information:** [List actual system info from scans]
- **Other Sensitive Data:** [Any other data found]

**Exposure Commands:**
```bash
[Show the actual commands that revealed this data]
```

## 🔧 DISCOVERED TECHNOLOGIES
[Extract from scan results:]
- **Web Server:** [From scan headers/responses]
- **Framework:** [From scan results]
- **Version Information:** [From actual scan data]
- **Security Headers:** [From scan analysis]

## 🎯 ATTACK VECTORS & EXPLOITATION SCENARIOS

### 🔓 Primary Attack Path
[Create based on actual vulnerabilities found:]
1. **Initial Access:** [Method from scan results]
2. **Data Extraction:** [Based on actual leaked data]
3. **Privilege Escalation:** [If applicable from findings]
4. **Persistence:** [If applicable]

### 💀 Complete Attack Chain Example
```bash
[Create realistic attack chain using actual endpoints and data found]
```

## 🔍 TECHNICAL EVIDENCE
**Proof-of-Concept Commands:**
```bash
[Include ALL actual commands from scan results]
```

**Raw Responses:**
[Include relevant actual response data from scans]

## 🛡️ REMEDIATION RECOMMENDATIONS
1. **Immediate Actions:** [Based on severity of actual findings]
2. **Security Controls:** [Missing protections identified]
3. **Configuration Changes:** [Specific to findings]

CRITICAL REQUIREMENTS:
- Extract ALL actual data from the scan results provided
- Use real vulnerability names, locations, and leaked data from scans
- Include actual commands that found the vulnerabilities
- Be comprehensive and detailed using the actual scan findings
- Generate the FULL structured report, not a brief summary"""


@dataclass
class GenerateReportNode:
    llm: ChatOpenAI

    def generate_report(self, state: TargetScanState) -> Dict[str, Any]:
        """Generate a factual security scan report based only on actual findings."""
        target = state["target"]
        results = state["results"]

        # Build context from all scan results
        scan_context = (
            json.dumps([result.to_dict() for result in results], indent=2) 
            if results else "No scan results available."
        )

        try:
            report_messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(
                    content=human_prompt.format(
                        url=target.url, scan_context=scan_context
                    )
                ),
            ]
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

    def __call__(self, state: TargetScanState) -> Dict[str, Any]:
        """Make the node callable for LangGraph."""
        return self.generate_report(state)

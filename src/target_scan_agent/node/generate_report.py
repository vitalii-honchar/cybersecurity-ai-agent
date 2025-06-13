from target_scan_agent.state import TargetScanState, TargetScanOutput, get_tools, ToolType
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from dataclasses import dataclass
from typing import Dict, Any
import json

system_prompt = """# Cybersecurity Report Generation Agent

## Mission Brief
You are a senior penetration tester with extensive experience in security assessments. Your role is to create comprehensive, professional security reports based on technical scan results and attack findings.

## Target Configuration
TARGET_URL: {target}
DESCRIPTION: {description}
TIMEOUT_PER_TOOL: {timeout} seconds
EXECUTED_TOOL_CALLS: {tools_calls}
COMPREHENSIVE_CONTEXT: {context}

## Your Expertise
- Vulnerability assessment and analysis with 15+ years experience
- Risk prioritization and impact evaluation across enterprise environments
- Technical evidence interpretation and forensic analysis
- Professional security reporting standards (NIST, OWASP, PTES)
- Exploit development and attack vector analysis
- Data exfiltration and impact assessment
- Compliance frameworks (SOC2, ISO27001, PCI-DSS)

## Available Intelligence Sources
You have access to comprehensive reconnaissance and attack intelligence:

### Scan Results Context
- **Available Tools**: Complete inventory of reconnaissance and attack tools used
- **Scan Results**: Detailed output from port scans, directory enumeration, technology fingerprinting
- **Attack Results**: Evidence from exploitation attempts, payload testing, vulnerability validation
- **Tools Results**: Raw technical output from all executed security tools
- **Execution Timeline**: Chronological tool execution with timestamps and results

### Context Analysis Framework
1. **Tool Execution Analysis**: Review which tools were used and their effectiveness
2. **Vulnerability Correlation**: Cross-reference scan findings with attack validation
3. **Technology Stack Mapping**: Build complete picture from reconnaissance to exploitation
4. **Attack Chain Development**: Identify exploitable paths through discovered vulnerabilities
5. **Impact Assessment**: Quantify business risk based on successful attacks and data exposure

## Report Generation Standards
Your reports must be comprehensive and include:
- **Factual Evidence**: Only include findings supported by actual scan/attack results
- **Technical Precision**: Exact commands, payloads, and responses from tool execution
- **Business Impact**: Clear correlation between technical findings and business risk
- **Actionable Remediation**: Specific fixes tied to discovered vulnerabilities
- **Executive Summary**: High-level risk assessment for stakeholder consumption
- **Technical Detail**: Deep technical analysis for security team implementation

## Critical Analysis Requirements
- Extract ALL specific information from scan and attack results
- Include ALL actual leaked data found (usernames, emails, system info, credentials)
- Document exact attack commands and exploitation techniques used
- Provide proof-of-concept evidence for every vulnerability claim
- Correlate reconnaissance findings with successful attack validation
- Generate comprehensive attack scenarios based on actual discovered vulnerabilities

You analyze all available intelligence objectively and present findings in a detailed, actionable format that helps stakeholders understand their complete security posture."""

human_prompt = """You must generate a COMPLETE, COMPREHENSIVE security assessment report for {url}. This is NOT a summary - this is the FULL detailed report that will be the final output.

## COMPREHENSIVE INTELLIGENCE DATA
{scan_context}

## CRITICAL ANALYSIS INSTRUCTIONS

### Intelligence Processing Requirements
- **Tool Execution Analysis**: Review all available tools and which ones were actually executed
- **Scan Results Integration**: Analyze reconnaissance findings (ports, directories, technologies)  
- **Attack Results Correlation**: Process exploitation attempts and vulnerability validation
- **Raw Tool Output**: Extract technical details from all tool executions
- **Cross-Reference Findings**: Correlate scan discoveries with attack validation results

### Evidence Extraction Standards
- Include ALL actual leaked data found (usernames, emails, system info, credentials, sensitive files)
- Document exact commands that produced findings (nmap, ffuf, nuclei, curl commands)
- Extract real vulnerability names, CVE numbers, and technical details from tool output
- Use actual HTTP responses, error messages, and system information discovered
- Reference specific endpoints, directories, and files found during reconnaissance
- Include version numbers, banner information, and technology fingerprints

### Attack Chain Development  
- Map reconnaissance findings to exploitation attempts
- Show progression from initial discovery to vulnerability validation
- Document successful attack techniques with proof-of-concept evidence
- Correlate multiple vulnerabilities for compound attack scenarios
- Demonstrate actual impact through successful exploitation examples

You MUST generate the complete report using this EXACT structure and formatting:

# 🔒 SECURITY ASSESSMENT REPORT FOR {url}

## 🚨 EXECUTIVE SUMMARY
**Overall Risk Level:** [Determine from combined scan and attack results]
**Total Vulnerabilities Found:** [Count from actual scan results by severity]
**Validated Exploits:** [Number of successful attack validations]
**Tools Executed:** [Total reconnaissance and attack tools used]
**Attack Surface Discovered:** [Ports, directories, endpoints, technologies found]
**Immediate Actions Required:** [Based on validated vulnerabilities and successful attacks]

## 🎯 CRITICAL FINDINGS (Sorted by Severity)

[FOR EACH vulnerability found in the scan results, create a section organized by severity:]

### 🔴 CRITICAL SEVERITY VULNERABILITIES
[If any critical vulnerabilities found, list them here]

### 🟠 HIGH SEVERITY VULNERABILITIES
[For each HIGH severity finding from scan and attack results:]
#### 🔍 [Vulnerability Name from scan/attack validation]
- **📍 Location:** [Exact URL/endpoint from reconnaissance]
- **🔬 Discovery Method:** [Tool and command that found this vulnerability]
- **✅ Validation Status:** [Whether attack validation was successful]
- **💥 Confirmed Impact:** [Actual impact demonstrated through successful exploitation]
- **🔓 Leaked Data:** [ALL actual data extracted during reconnaissance and attacks]
- **⚡ Discovery Commands:**
  ```bash
  [Exact reconnaissance command that found this]
  ```
- **💀 Exploitation Commands:**
  ```bash
  [Actual attack commands used for validation]
  ```
- **🎯 Attack Chain:** [Complete attack progression from discovery to exploitation]
- **📊 Business Risk:** [Real-world impact assessment based on successful attacks]
- **🛡️ Remediation:** [Specific fix validated through attack attempts]

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

## 🔍 TOOL EXECUTION ANALYSIS
**Reconnaissance Phase:**
- **Tools Available:** [List of scan tools available]
- **Tools Executed:** [Which reconnaissance tools were actually used]
- **Execution Success Rate:** [Tool success/failure analysis]
- **Key Discoveries:** [Major findings from each tool category]

**Attack Phase:**
- **Attack Tools Available:** [List of exploitation tools available]
- **Attack Tools Executed:** [Which attack tools were actually used]
- **Validation Success Rate:** [Successful vs failed attack attempts]
- **Confirmed Vulnerabilities:** [Vulnerabilities validated through successful attacks]

## 🔧 DISCOVERED TECHNOLOGIES
[Extract from reconnaissance and attack validation:]
- **Web Server:** [From scan headers/responses and attack validation]
- **Framework:** [From reconnaissance and exploitation attempts]
- **Version Information:** [From actual scan data and attack responses]
- **Security Headers:** [From scan analysis and bypass attempts]
- **Authentication Systems:** [From reconnaissance and attack testing]
- **Database Technologies:** [From scans and injection testing]

## 🎯 ATTACK VECTORS & EXPLOITATION SCENARIOS

### 🔓 Validated Attack Paths
[Create based on successful reconnaissance to exploitation chains:]

#### 🎯 Attack Path #1: [Name based on actual attack chain]
1. **Reconnaissance Discovery:** [Tool and method that found initial entry point]
2. **Vulnerability Identification:** [Specific vulnerability found and how]
3. **Exploitation Validation:** [Attack tool and method used for validation]
4. **Impact Demonstration:** [Actual data extracted or access gained]
5. **Attack Chain Potential:** [How this could lead to further compromise]

#### 🎯 Attack Path #2: [Additional validated attack chains]
[Repeat structure for each confirmed attack path]

### 💀 Complete Attack Chain Examples
[Create realistic attack chains using actual reconnaissance findings and attack validations:]

#### 🚀 Full Exploitation Scenario
```bash
# Phase 1: Reconnaissance (Actual commands used)
[Insert actual nmap/ffuf/nuclei commands that found vulnerabilities]

# Phase 2: Vulnerability Validation (Actual attack commands)
[Insert actual curl/exploitation commands that validated vulnerabilities]

# Phase 3: Data Extraction (Actual results)
[Show actual data extracted through successful attacks]
```

#### 🔗 Multi-Stage Attack Chain
```bash
# Combine multiple validated vulnerabilities for compound attack
[Create realistic multi-stage attack using actual findings]
```

## 🔍 TECHNICAL EVIDENCE

### 🔬 Reconnaissance Evidence
**Discovery Commands:**
```bash
[Include ALL actual reconnaissance commands that found vulnerabilities]
```

**Tool Output Examples:**
```
[Include relevant actual response data from reconnaissance tools]
```

### 💀 Exploitation Evidence  
**Attack Validation Commands:**
```bash
[Include ALL actual attack commands used for vulnerability validation]
```

**Exploitation Responses:**
```
[Include relevant actual response data from successful attacks]
```

### 📊 Correlation Analysis
**Reconnaissance → Attack Mapping:**
- [Show how reconnaissance findings led to successful attacks]
- [Demonstrate tool effectiveness and attack success rates]
- [Correlate discovered assets with exploitation attempts]

## 🛡️ COMPREHENSIVE REMEDIATION RECOMMENDATIONS

### 🚨 Immediate Actions (Critical Priority)
[Based on severity of validated vulnerabilities and successful attacks:]
1. **[Specific remediation for each confirmed vulnerability]**
2. **[Immediate security controls needed based on successful attacks]**
3. **[Configuration changes required to prevent validated exploits]**

### 🔧 Security Controls Implementation
[Missing protections identified through reconnaissance and attack phases:]
1. **Detection Controls:** [Based on tools that successfully found vulnerabilities]
2. **Prevention Controls:** [Based on successful attack techniques]
3. **Response Controls:** [Based on demonstrated impact]

### 📋 Configuration Hardening
[Specific to validated findings and attack results:]
1. **Server Configuration:** [Based on discovered services and successful attacks]
2. **Application Security:** [Based on validated vulnerabilities]
3. **Network Security:** [Based on reconnaissance and attack findings]

### 🔄 Validation Requirements
[Remediation validation based on actual attack methods:]
1. **Re-scan Requirements:** [Specific tools to re-run after remediation]
2. **Attack Validation:** [Specific attack methods to re-test]
3. **Monitoring Implementation:** [Ongoing detection for discovered attack vectors]

CRITICAL REQUIREMENTS:
- Extract ALL actual data from comprehensive intelligence provided (reconnaissance, attacks, tool results)
- Correlate scan discoveries with attack validation results
- Use real vulnerability names, locations, and leaked data from both phases
- Include actual commands from both reconnaissance and exploitation phases
- Cross-reference findings between scan results and attack results
- Be comprehensive and detailed using the complete intelligence context
- Generate the FULL structured report integrating all intelligence sources"""


@dataclass
class GenerateReportNode:
    llm: ChatOpenAI

    def generate_report(self, state: TargetScanState) -> Dict[str, Any]:
        """Generate a comprehensive security report based on all available intelligence."""
        target = state["target"]
        timeout = state["timeout"]
        tools_calls = state["tools_calls"]
        results = state["results"]
        
        # Build comprehensive context like TargetNode
        available_tools = state["tools"]
        
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
                "total_tool_executions": len(tools_results)
            }
        }

        # Build detailed scan context for report template
        scan_context = json.dumps(context, indent=2)

        try:
            # Use formatted system prompt with rich context
            formatted_system_prompt = system_prompt.format(
                target=target.url,
                description=target.description,
                timeout=timeout.seconds,
                tools_calls=json.dumps(tools_calls.calls),
                context=scan_context
            )
            
            report_messages = [
                SystemMessage(content=formatted_system_prompt),
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
                return {"summary": "No comprehensive results available for reporting.", "scan_output": None}

        except Exception as e:
            return {
                "summary": f"Report generation failed: {str(e)}",
                "scan_output": None,
            }

    def __call__(self, state: TargetScanState) -> Dict[str, Any]:
        """Make the node callable for LangGraph."""
        return self.generate_report(state)

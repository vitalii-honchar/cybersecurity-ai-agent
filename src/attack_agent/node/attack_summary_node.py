import json
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage

from attack_agent.state import AttackAgentState
from attack_agent.state.attack_agent_state import AttackReportSummary

ATTACK_SUMMARY_BEHAVIOR_PROMPT = """# Cybersecurity Attack Execution Analysis Specialist

## Mission Brief
You are a cybersecurity analysis specialist tasked with creating a comprehensive structured summary of attack execution results for:
TARGET: {target_url}
TARGET_TYPE: {target_type}
DESCRIPTION: {target_description}

## Attack Execution Results
The following attack tools were executed during the penetration test:

{tool_results}

## Original Reconnaissance Intelligence
The attack was based on the following reconnaissance findings:

{scan_summary}

## Analysis Requirements

Based on the attack execution results above, create a detailed AttackReportSummary with the following components:

### 1. Exploit Attempts Analysis
Document all exploitation attempts made during the attack:
- **Technique Classification** - Map attack methods to MITRE ATT&CK framework (T1190, T1059, etc.)
- **Target Endpoint Specification** - Full URL path, parameters, and HTTP methods tested
- **Payload Documentation** - Complete payloads including encoding, obfuscation techniques
- **Success Determination** - Binary success/failure with confidence scores (0-100%)
- **Response Pattern Analysis** - Status codes, timing variations, error fingerprints
- **Impact Quantification** - CVSS scoring with exploitability and impact metrics

### 2. Compromised Assets Assessment
Identify and document any successfully compromised assets:
- **Asset Taxonomy** - Web application components, databases, file systems, APIs
- **Geolocation Precision** - Exact paths, database schemas, service instances
- **Privilege Escalation Mapping** - Initial access → elevated permissions progression
- **Compromise Validation** - Multiple proof points confirming successful exploitation
- **Persistence Mechanism Evaluation** - Backdoors, scheduled tasks, modified configurations

### 3. Security Control Bypass Documentation
Document security controls that were successfully circumvented:
- **Control Framework Mapping** - NIST, ISO 27001, OWASP control categories
- **Bypass Technique Taxonomy** - Evasion methods with technical implementation details
- **Effectiveness Quantification** - Percentage of control circumvented (partial/complete)
- **Detection Probability Assessment** - SIEM, WAF, IDS evasion likelihood scoring

### 4. Attack Kill Chain Timeline
Create a detailed chronological attack progression:
- **Phase-based Sequencing** - Reconnaissance → Initial Access → Execution → Persistence
- **Dependency Mapping** - Prerequisites and enablers for each successful exploit
- **Success Amplification Analysis** - How initial compromises enabled lateral movement
- **Decision Tree Documentation** - Attack path selection rationale and alternatives

### 5. Business Impact Quantification
Evaluate organizational risk exposure from successful attacks:
- **Data Classification Impact** - PII, financial, intellectual property exposure levels
- **System Integrity Compromise** - Database manipulation, configuration changes, code injection
- **Service Availability Disruption** - DoS potential, resource exhaustion, system crashes  
- **Financial Risk Modeling** - Breach costs, compliance fines, business disruption estimates
- **Regulatory Compliance Violations** - GDPR, HIPAA, PCI-DSS, SOX implications

### 6. Tactical Security Recommendations
Provide prioritized remediation guidance based on attack vectors:
- **Critical Path Remediation** - High-impact fixes that block multiple attack vectors
- **Configuration Hardening Matrix** - System, application, and network security settings
- **Code Remediation Specifications** - Exact vulnerable code locations and secure alternatives
- **Defense Architecture Improvements** - Network segmentation, access controls, monitoring
- **Detection Engineering Requirements** - Security rules, signatures, and behavioral analytics

## Enhanced Analysis Standards
- **Evidence Correlation** - Cross-validate findings across multiple attack vectors
- **False Positive Elimination** - Distinguish actual exploits from tool artifacts
- **Reconnaissance Validation** - Confirm attack success aligns with initial intelligence
- **Exploit Chain Analysis** - Document multi-stage attack dependencies and amplification
- **Defensive Gap Assessment** - Identify where existing controls failed or were bypassed

## Structured Output Requirements
- **Executive Summary Section** - Business-focused impact assessment (2-3 paragraphs)
- **Technical Findings Matrix** - Tabular format with severity, exploitability, impact scores
- **Remediation Roadmap** - Prioritized timeline with effort estimates (hours/days/weeks)
- **Risk Heat Map** - Visual representation of vulnerability distribution and severity
- **Compliance Impact Assessment** - Regulatory requirements affected by findings

## Quality Assurance Criteria
- **Reproducibility Documentation** - Step-by-step exploit recreation instructions
- **Confidence Scoring** - High/Medium/Low confidence levels for each finding
- **Attack Vector Completeness** - Ensure all tool outputs are analyzed and categorized
- **Business Context Integration** - Translate technical findings to business risk language
- **Remediation Feasibility** - Consider organizational constraints and resource availability

## Critical Analysis Instructions
- Analyze ONLY the attack execution results provided in {tool_results}
- Structure output as AttackReportSummary with all mandatory fields populated
- Cross-reference successful exploits against {scan_summary} for validation consistency
- Flag anomalous results requiring manual security analyst review
- Prioritize findings using business impact scoring rather than purely technical metrics
- Focus on actionable intelligence that directly improves defensive security posture

## Report Completeness Validation
Ensure the final AttackReportSummary includes:
- Complete exploit attempt inventory with success/failure ratios
- Quantified impact assessment for each compromised asset
- Detailed security control bypass documentation with remediation steps
- Chronological attack timeline with decision point analysis
- Business-justified risk prioritization with compliance implications
- Tactical remediation roadmap with implementation effort estimates"""

class AttackSummaryNode:
    def __init__(self, llm: BaseChatModel):
        self.structured_llm = llm.with_structured_output(AttackReportSummary)

    def __call__(self, state: AttackAgentState) -> dict:
        target = state["target"]
        scan_summary = state["scan_summary"]

        system_prompt = ATTACK_SUMMARY_BEHAVIOR_PROMPT.format(
            target_url=target.url,
            target_description=target.description,
            target_type=target.type,
            tool_results=json.dumps([r.to_dict() for r in state["results"]]),
            scan_summary=scan_summary.model_dump_json()
        )

        prompt_messages = [SystemMessage(content=system_prompt), state["messages"][-1]]
        attack_summary = self.structured_llm.invoke(prompt_messages)

        return {"attack_summary": attack_summary}
import operator
from typing import Optional
from pydantic import BaseModel, Field

from agent_core.state import ReActAgentState


class DiscoveredEndpoint(BaseModel):
    path: str = Field(description="The endpoint path")
    status_code: int = Field(description="HTTP status code")
    content_type: str = Field(description="Response content type")
    notes: str = Field(description="Additional notes about the endpoint")


class TechStackItem(BaseModel):
    technology: str = Field(description="Technology name")
    confidence: str = Field(description="Confidence level (High/Medium/Low)")
    evidence: str = Field(description="Evidence that led to this conclusion")


class SensitiveInfo(BaseModel):
    type: str = Field(description="Type of sensitive information")
    location: str = Field(description="Where it was found")
    details: str = Field(description="Details about the finding")
    risk_level: str = Field(description="Risk level (High/Medium/Low)")


class Vulnerability(BaseModel):
    name: str = Field(description="Vulnerability name or type")
    severity: str = Field(description="Severity level")
    description: str = Field(description="Detailed description")
    location: str = Field(description="Where the vulnerability was found")
    impact: str = Field(description="Potential impact")


class RiskAssessment(BaseModel):
    category: str = Field(description="Risk category")
    priority: str = Field(description="Priority level (High/Medium/Low)")
    details: str = Field(description="Detailed risk description")
    rationale: str = Field(description="Why this risk level was assigned")


class AttackRecommendation(BaseModel):
    technique: str = Field(description="Attack technique or method")
    target: str = Field(description="Target endpoint or component")
    description: str = Field(description="How to perform this attack")
    priority: str = Field(description="Priority for execution")
    prerequisites: str = Field(description="What's needed before attempting")


class ScanAgentSummary(BaseModel):
    discovered_endpoints: list[DiscoveredEndpoint] = Field(
        description="List of discovered endpoints with metadata"
    )
    tech_stack: list[TechStackItem] = Field(
        description="Identified technology stack with confidence levels"
    )
    sensitive_information: list[SensitiveInfo] = Field(
        description="Sensitive information found during reconnaissance"
    )
    vulnerabilities: list[Vulnerability] = Field(
        description="Identified vulnerabilities and security issues"
    )
    risk_assessment: list[RiskAssessment] = Field(
        description="Risk-prioritized assessment of findings"
    )
    attack_recommendations: list[AttackRecommendation] = Field(
        description="Recommended attack vectors for the next phase"
    )
    summary_text: str = Field(description="Human-readable summary of all findings")

    def to_markdown(self) -> str:
        """Generate a markdown report from the scan agent summary."""
        report = []

        # Title and Header
        report.append("# 🔍 Reconnaissance Summary Report")
        report.append("")
        report.append("---")
        report.append("")

        # Executive Summary
        if self.summary_text:
            report.append("## 📋 Executive Summary")
            report.append("")
            report.append(self.summary_text)
            report.append("")

        # Technology Stack
        if self.tech_stack:
            report.append("## 💻 Technology Stack")
            report.append("")
            for tech in self.tech_stack:
                confidence_emoji = {
                    "high": "🟢",
                    "medium": "🟡", 
                    "low": "🟠"
                }
                emoji = confidence_emoji.get(tech.confidence.lower(), "⚪")
                report.append(f"### {emoji} {tech.technology}")
                report.append("")
                report.append(f"**Confidence:** {tech.confidence}")
                report.append("")
                report.append(f"**Evidence:** {tech.evidence}")
                report.append("")

        # Discovered Endpoints
        if self.discovered_endpoints:
            report.append("## 🔍 Discovered Endpoints")
            report.append("")
            report.append("| Path | Status | Content Type | Notes |")
            report.append("|------|--------|--------------|-------|")
            for endpoint in self.discovered_endpoints:
                # Escape pipe characters and other markdown special chars in table cells
                path = endpoint.path.replace("|", "\\|")
                content_type = endpoint.content_type.replace("|", "\\|")
                notes = endpoint.notes.replace("|", "\\|").replace("\n", " ")
                report.append(f"| `{path}` | {endpoint.status_code} | {content_type} | {notes} |")
            report.append("")

        # Sensitive Information
        if self.sensitive_information:
            report.append("## 🔓 Sensitive Information")
            report.append("")
            for info in self.sensitive_information:
                risk_emoji = {
                    "high": "🔴",
                    "medium": "🟡",
                    "low": "🟢"
                }
                emoji = risk_emoji.get(info.risk_level.lower(), "⚪")
                report.append(f"### {emoji} {info.type}")
                report.append("")
                report.append(f"**Location:** `{info.location}`")
                report.append("")
                report.append(f"**Risk Level:** {info.risk_level}")
                report.append("")
                report.append(f"**Details:** {info.details}")
                report.append("")

        # Vulnerabilities
        if self.vulnerabilities:
            report.append("## 🚨 Vulnerabilities")
            report.append("")
            
            # Group by severity
            vulnerabilities_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for vuln in self.vulnerabilities:
                severity_key = vuln.severity.lower()
                if severity_key in vulnerabilities_by_severity:
                    vulnerabilities_by_severity[severity_key].append(vuln)

            severity_emojis = {
                "critical": "🔴",
                "high": "🟠", 
                "medium": "🟡",
                "low": "🟢",
                "info": "🔵"
            }

            for severity in ["critical", "high", "medium", "low", "info"]:
                vulnerabilities_list = vulnerabilities_by_severity[severity]
                if vulnerabilities_list:
                    report.append(f"### {severity_emojis[severity]} {severity.upper()} Severity ({len(vulnerabilities_list)})")
                    report.append("")
                    for vuln in vulnerabilities_list:
                        report.append(f"#### {vuln.name}")
                        report.append("")
                        report.append(f"**Location:** `{vuln.location}`")
                        report.append("")
                        report.append(f"**Description:** {vuln.description}")
                        report.append("")
                        report.append(f"**Impact:** {vuln.impact}")
                        report.append("")

        # Risk Assessment
        if self.risk_assessment:
            report.append("## ⚠️ Risk Assessment")
            report.append("")
            for risk in self.risk_assessment:
                priority_emoji = {
                    "critical": "🔴",
                    "high": "🔴",
                    "medium": "🟡",
                    "low": "🟢"
                }
                emoji = priority_emoji.get(risk.priority.lower(), "⚪")
                report.append(f"### {emoji} {risk.category}")
                report.append("")
                report.append(f"**Priority:** {risk.priority}")
                report.append("")
                report.append(f"**Details:** {risk.details}")
                report.append("")
                report.append(f"**Rationale:** {risk.rationale}")
                report.append("")

        # Attack Recommendations
        if self.attack_recommendations:
            report.append("## ⚔️ Attack Recommendations")
            report.append("")
            for i, rec in enumerate(self.attack_recommendations, 1):
                priority_emoji = {
                    "1": "🔴",
                    "2": "🟠", 
                    "3": "🟡",
                    "4": "🟢",
                    "5": "🔵",
                    "6": "⚪",
                    "high": "🔴",
                    "medium": "🟡", 
                    "low": "🟢"
                }
                # Try to get emoji by priority number first, then by priority text
                emoji = priority_emoji.get(str(i), priority_emoji.get(rec.priority.lower(), "⚪"))
                report.append(f"### {emoji} {i}. {rec.technique}")
                report.append("")
                report.append(f"**Target:** `{rec.target}`")
                report.append("")
                report.append(f"**Priority:** {rec.priority}")
                report.append("")
                report.append(f"**Description:** {rec.description}")
                report.append("")
                if rec.prerequisites:
                    report.append(f"**Prerequisites:** {rec.prerequisites}")
                    report.append("")
                report.append("")

        # Footer
        report.append("---")
        report.append("")
        report.append("*Report generated by Scan Agent* 🤖")
        report.append("")

        return "\n".join(report)


class ScanAgentState(ReActAgentState):
    summary: ScanAgentSummary | None

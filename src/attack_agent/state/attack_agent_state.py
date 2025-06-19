from pydantic import BaseModel, Field

from agent_core.state import ReActAgentState
from scan_agent.state.scan_agent_state import ScanAgentSummary


class ExploitAttempt(BaseModel):
    technique: str = Field(description="Attack technique or exploit method used")
    target_endpoint: str = Field(description="Target endpoint or component attacked")
    payload: str = Field(description="Actual payload or attack vector used")
    success: bool = Field(description="Whether the exploit attempt was successful")
    response_details: str = Field(description="Response details and evidence")
    impact_assessment: str = Field(description="Assessment of the exploit impact")


class CompromisedAsset(BaseModel):
    asset_type: str = Field(description="Type of compromised asset (endpoint, service, etc.)")
    location: str = Field(description="Location or identifier of the compromised asset")
    access_level: str = Field(description="Level of access gained (read, write, admin)")
    evidence: str = Field(description="Evidence of successful compromise")
    persistence_method: str = Field(description="Method used to maintain access")


class SecurityBypass(BaseModel):
    control_type: str = Field(description="Type of security control bypassed")
    bypass_method: str = Field(description="Method used to bypass the control")
    effectiveness: str = Field(description="How effective the bypass was")
    detection_risk: str = Field(description="Risk of detection for this bypass")


class AttackReportSummary(BaseModel):
    exploit_attempts: list[ExploitAttempt] = Field(
        description="List of all exploit attempts made during the attack"
    )
    compromised_assets: list[CompromisedAsset] = Field(
        description="Assets successfully compromised during the attack"
    )
    security_bypasses: list[SecurityBypass] = Field(
        description="Security controls that were successfully bypassed"
    )
    attack_timeline: str = Field(description="Chronological timeline of the attack")
    impact_summary: str = Field(description="Overall impact assessment of the attack")
    recommendations: str = Field(description="Security recommendations based on findings")

    def to_markdown(self) -> str:
        """Generate a markdown report from the attack agent summary."""
        report = []

        # Title and Header
        report.append("# ⚔️ Attack Execution Report")
        report.append("")
        report.append("---")
        report.append("")

        # Executive Summary
        if self.impact_summary:
            report.append("## 📋 Executive Summary")
            report.append("")
            report.append(self.impact_summary)
            report.append("")

        # Attack Timeline
        if self.attack_timeline:
            report.append("## ⏱️ Attack Timeline")
            report.append("")
            report.append(self.attack_timeline)
            report.append("")

        # Exploit Attempts
        if self.exploit_attempts:
            report.append("## 🎯 Exploit Attempts")
            report.append("")
            for i, attempt in enumerate(self.exploit_attempts, 1):
                success_emoji = "✅" if attempt.success else "❌"
                report.append(f"### {success_emoji} {i}. {attempt.technique}")
                report.append("")
                report.append(f"**Target:** `{attempt.target_endpoint}`")
                report.append("")
                report.append(f"**Success:** {'Yes' if attempt.success else 'No'}")
                report.append("")
                report.append(f"**Payload:** ```{attempt.payload}```")
                report.append("")
                report.append(f"**Response:** {attempt.response_details}")
                report.append("")
                report.append(f"**Impact:** {attempt.impact_assessment}")
                report.append("")

        # Compromised Assets
        if self.compromised_assets:
            report.append("## 🔓 Compromised Assets")
            report.append("")
            for asset in self.compromised_assets:
                access_emoji = {
                    "read": "👁️",
                    "write": "✏️", 
                    "admin": "👑",
                    "full": "🔑"
                }
                emoji = access_emoji.get(asset.access_level.lower(), "🎯")
                report.append(f"### {emoji} {asset.asset_type}")
                report.append("")
                report.append(f"**Location:** `{asset.location}`")
                report.append("")
                report.append(f"**Access Level:** {asset.access_level}")
                report.append("")
                report.append(f"**Evidence:** {asset.evidence}")
                report.append("")
                report.append(f"**Persistence:** {asset.persistence_method}")
                report.append("")

        # Security Bypasses
        if self.security_bypasses:
            report.append("## 🛡️ Security Bypasses")
            report.append("")
            for bypass in self.security_bypasses:
                effectiveness_emoji = {
                    "high": "🔴",
                    "medium": "🟡",
                    "low": "🟢"
                }
                emoji = effectiveness_emoji.get(bypass.effectiveness.lower(), "⚪")
                report.append(f"### {emoji} {bypass.control_type}")
                report.append("")
                report.append(f"**Bypass Method:** {bypass.bypass_method}")
                report.append("")
                report.append(f"**Effectiveness:** {bypass.effectiveness}")
                report.append("")
                report.append(f"**Detection Risk:** {bypass.detection_risk}")
                report.append("")

        # Recommendations
        if self.recommendations:
            report.append("## 🔒 Security Recommendations")
            report.append("")
            report.append(self.recommendations)
            report.append("")

        # Footer
        report.append("---")
        report.append("")
        report.append("*Report generated by Attack Agent* ⚔️")
        report.append("")

        return "\n".join(report)


class AttackAgentState(ReActAgentState):
    scan_summary: ScanAgentSummary
    attack_summary: AttackReportSummary | None
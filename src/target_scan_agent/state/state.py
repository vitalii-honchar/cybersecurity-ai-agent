import operator
from datetime import timedelta
from typing import Annotated, Literal

from langgraph.graph import MessagesState
from pydantic import BaseModel, Field

from .tools import Tool, ToolName


class Target(BaseModel):
    description: str = Field(description="A description of the target to be scanned.")
    url: str = Field(description="The URL of the target to be scanned.")

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


SeverityLevel = Literal["info", "low", "medium", "high", "critical"]


class TargetScanToolResult(BaseModel):
    result: str = Field(description="The raw result of the tool execution.")
    tool_name: str | None = Field(
        default=None,
        description="The name of the tool that was called",
    )
    tool_arguments: dict | None = Field(
        default=None,
        description="The arguments passed to the tool when it was called",
    )
    tool_call_id: str = Field(
        description="Unique identifier for the tool call to avoid duplicates"
    )

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class Vulnerability(BaseModel):
    name: str = Field(description="Name or title of the vulnerability")
    severity: SeverityLevel = Field(
        description="Severity level: critical, high, medium, low, info"
    )
    cve_id: str | None = Field(default=None, description="CVE identifier if available")
    cvss_score: float | None = Field(default=None, description="CVSS score (0.0-10.0)")
    description: str = Field(description="Detailed description of the vulnerability")
    affected_endpoint: str | None = Field(
        default=None, description="Affected URL or endpoint"
    )
    proof_of_concept: str | None = Field(
        default=None, description="Working exploit or proof of concept"
    )
    remediation: str | None = Field(
        default=None, description="Specific remediation steps"
    )


class ExposedData(BaseModel):
    data_type: str = Field(
        description="Type of exposed data (credentials, files, database, etc.)"
    )
    content: str = Field(description="Actual exposed data content")
    source: str = Field(description="Where the data was found (endpoint, file, etc.)")
    sensitivity: SeverityLevel = Field(
        description="Sensitivity level of the exposed data"
    )


class AttackVector(BaseModel):
    name: str = Field(description="Name of the attack vector")
    description: str = Field(description="Description of how the attack works")
    required_tools: list[str] = Field(description="List of tools needed for the attack")
    commands: list[str] = Field(description="Actual commands used for the attack")
    success_indicators: list[str] = Field(
        description="Signs that indicate successful attack"
    )


class TechnicalEvidence(BaseModel):
    tool_name: str = Field(description="Name of the tool that generated this evidence")
    command_executed: str = Field(description="Exact command that was executed")
    raw_output: str = Field(description="Raw output from the tool")
    findings_summary: str = Field(
        description="Summary of key findings from this evidence"
    )


class OpenPort(BaseModel):
    port: int = Field(description="Port number")
    protocol: str = Field(description="Protocol (TCP/UDP)")
    state: str = Field(description="Port state (open/closed/filtered)")
    service: str | None = Field(default=None, description="Service name")
    version: str | None = Field(default=None, description="Service version")


class ServiceInfo(BaseModel):
    name: str = Field(description="Service name")
    version: str | None = Field(default=None, description="Service version")
    port: int | None = Field(default=None, description="Port number")
    extra_info: str | None = Field(
        default=None, description="Additional service details"
    )


class DiscoveredEndpoint(BaseModel):
    url: str = Field(description="Full URL or endpoint path")
    status_code: int | None = Field(default=None, description="HTTP status code")
    content_length: int | None = Field(
        default=None, description="Response content length"
    )
    content_type: str | None = Field(default=None, description="Response content type")


class HiddenResource(BaseModel):
    path: str = Field(description="Resource path or URL")
    status_code: int = Field(description="HTTP status code")
    access_level: str = Field(description="Access level (forbidden, hidden, etc.)")
    potential_value: str | None = Field(
        default=None, description="Potential security value"
    )


class EntryPoint(BaseModel):
    name: str = Field(description="Entry point name or description")
    location: str = Field(description="URL, port, or system location")
    risk_level: SeverityLevel = Field(description="Risk level assessment")
    attack_methods: list[str] = Field(description="Possible attack methods")


class RiskAssessment(BaseModel):
    overall_risk: SeverityLevel = Field(description="Overall risk level")
    business_impact: str = Field(description="Business impact assessment")
    exploitability: str = Field(description="Exploitability analysis")
    threat_level: str = Field(description="Threat level evaluation")


class RemediationItem(BaseModel):
    priority: SeverityLevel = Field(description="Remediation priority level")
    category: str = Field(description="Category (immediate, short-term, long-term)")
    description: str = Field(description="Remediation description")
    effort: str | None = Field(default=None, description="Effort required")


class NetworkIntelligence(BaseModel):
    open_ports: list[OpenPort] = Field(
        default=[], description="List of open ports with service details"
    )
    services: list[ServiceInfo] = Field(
        default=[], description="Discovered services with version information"
    )
    os_fingerprint: str | None = Field(
        default=None, description="Operating system identification"
    )
    network_topology: str | None = Field(
        default=None, description="Network topology insights"
    )


class AttackSurface(BaseModel):
    discovered_endpoints: list[DiscoveredEndpoint] = Field(
        default=[], description="All discovered URLs and endpoints"
    )
    hidden_resources: list[HiddenResource] = Field(
        default=[], description="Hidden or forbidden resources found"
    )
    technology_stack: list[str] = Field(
        default=[], description="Identified technologies and versions"
    )
    entry_points: list[EntryPoint] = Field(
        default=[], description="Potential entry points ranked by risk"
    )


class TargetScanOutput(BaseModel):
    summary: str | None = Field(
        default=None,
        description="Executive summary of the security assessment with overall risk assessment",
    )
    vulnerabilities: list[Vulnerability] = Field(
        default=[],
        description="List of all discovered vulnerabilities with detailed information including CVEs, CVSS scores, and proof of concepts",
    )
    exposed_data: list[ExposedData] = Field(
        default=[],
        description="Actual leaked or exposed data found during scans (usernames, emails, files, database content, etc.)",
    )
    attack_vectors: list[AttackVector] = Field(
        default=[],
        description="Detailed attack scenarios with step-by-step exploitation instructions and required tools",
    )
    technical_evidence: list[TechnicalEvidence] = Field(
        default=[],
        description="Raw technical evidence from all tools including commands, outputs, and scan results",
    )
    network_intelligence: NetworkIntelligence | None = Field(
        default=None,
        description="Network reconnaissance data including open ports, services, OS detection, and topology",
    )
    attack_surface: AttackSurface | None = Field(
        default=None,
        description="Complete attack surface mapping including endpoints, hidden resources, and technology stack",
    )
    risk_assessment: RiskAssessment | None = Field(
        default=None,
        description="Risk prioritization with threat modeling, business impact, and exploitability analysis",
    )
    remediation_roadmap: list[RemediationItem] = Field(
        default=[],
        description="Prioritized remediation recommendations with immediate fixes, short-term, and long-term improvements",
    )
    compliance_gaps: list[str] = Field(
        default=[],
        description="Identified violations of security frameworks (OWASP, PCI-DSS, etc.) and compliance requirements",
    )

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class ToolsCalls(BaseModel):
    limits: dict[ToolName, int] = Field(
        description="A dictionary mapping tool names to their call limits."
    )
    calls: dict[ToolName, int] = Field(
        default={},
        description="A dictionary mapping tool names to the number of times they have been called.",
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")

    def _is_limit_reached(self, tool_name: ToolName) -> bool:
        return self.calls.get(tool_name, 0) >= self.limits.get(tool_name, 0)

    def is_limit_reached(self, tools: list[ToolName]) -> bool:
        return all([self._is_limit_reached(tool_name) for tool_name in tools])


class TargetScanState(MessagesState):
    target: Target
    tools: list[Tool]
    tools_calls: ToolsCalls
    timeout: timedelta
    results: Annotated[list[TargetScanToolResult], operator.add]
    scan_results: Annotated[list[str], operator.add]
    attack_results: Annotated[list[str], operator.add]
    report: TargetScanOutput
    call_count: int
    max_calls: int

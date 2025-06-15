from target_scan_agent.state import (
    TargetScanOutput,
    Vulnerability,
    ExposedData,
    AttackVector,
)


def create_markdown_report(scan_results: TargetScanOutput) -> str:
    """Generate a markdown report from the scan results."""
    report = []

    # Title and Header
    report.append("# 🔐 Cybersecurity Assessment Report")
    report.append("")
    report.append("---")
    report.append("")

    # Executive Summary
    if scan_results.summary:
        report.append("## 📋 Executive Summary")
        report.append("")
        report.append(scan_results.summary)
        report.append("")

    # Risk Assessment
    if scan_results.risk_assessment:
        report.append("## ⚠️ Risk Assessment")
        report.append("")
        risk_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }
        overall_risk = scan_results.risk_assessment.overall_risk
        report.append(
            f"**Overall Risk Level:** {risk_emoji.get(overall_risk, '⚪')} **{overall_risk.upper()}**"
        )
        report.append("")
        report.append(
            f"**Business Impact:** {scan_results.risk_assessment.business_impact}"
        )
        report.append("")
        report.append(
            f"**Exploitability:** {scan_results.risk_assessment.exploitability}"
        )
        report.append("")
        report.append(f"**Threat Level:** {scan_results.risk_assessment.threat_level}")
        report.append("")

    # Vulnerabilities
    if scan_results.vulnerabilities:
        report.append("## 🚨 Discovered Vulnerabilities")
        report.append("")

        # Group vulnerabilities by severity
        vuln_by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }
        for vuln in scan_results.vulnerabilities:
            vuln_by_severity[vuln.severity].append(vuln)

        severity_order = ["critical", "high", "medium", "low", "info"]
        severity_emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }

        for severity in severity_order:
            vulns = vuln_by_severity[severity]
            if vulns:
                report.append(
                    f"### {severity_emojis[severity]} {severity.upper()} Severity ({len(vulns)})"
                )
                report.append("")

                for vuln in vulns:
                    report.append(f"#### {vuln.name}")
                    if vuln.cve_id:
                        report.append(f"**CVE ID:** `{vuln.cve_id}`")
                    if vuln.cvss_score:
                        report.append(f"**CVSS Score:** {vuln.cvss_score}/10.0")
                    if vuln.affected_endpoint:
                        report.append(
                            f"**Affected Endpoint:** `{vuln.affected_endpoint}`"
                        )
                    report.append("")
                    report.append(f"**Description:** {vuln.description}")
                    report.append("")

                    if vuln.proof_of_concept:
                        report.append("**Proof of Concept:**")
                        report.append("```")
                        report.append(vuln.proof_of_concept)
                        report.append("```")
                        report.append("")

                    if vuln.remediation:
                        report.append(f"**Remediation:** {vuln.remediation}")
                        report.append("")

                    report.append("---")
                    report.append("")

    # Network Intelligence
    if scan_results.network_intelligence:
        report.append("## 🌐 Network Intelligence")
        report.append("")

        if scan_results.network_intelligence.os_fingerprint:
            report.append(
                f"**Operating System:** {scan_results.network_intelligence.os_fingerprint}"
            )
            report.append("")

        if scan_results.network_intelligence.open_ports:
            report.append("### 🔌 Open Ports")
            report.append("")
            report.append("| Port | Protocol | State | Service | Version |")
            report.append("|------|----------|-------|---------|---------|")

            for port in scan_results.network_intelligence.open_ports:
                service = port.service or "N/A"
                version = port.version or "N/A"
                report.append(
                    f"| {port.port} | {port.protocol} | {port.state} | {service} | {version} |"
                )
            report.append("")

        if scan_results.network_intelligence.services:
            report.append("### 🛠️ Discovered Services")
            report.append("")
            for service in scan_results.network_intelligence.services:
                port_info = f":{service.port}" if service.port else ""
                version_info = f" v{service.version}" if service.version else ""
                report.append(f"- **{service.name}**{version_info}{port_info}")
                if service.extra_info:
                    report.append(f"  - {service.extra_info}")
            report.append("")

    # Attack Surface
    if scan_results.attack_surface:
        report.append("## 🎯 Attack Surface Analysis")
        report.append("")

        if scan_results.attack_surface.technology_stack:
            report.append("### 💻 Technology Stack")
            report.append("")
            for tech in scan_results.attack_surface.technology_stack:
                report.append(f"- {tech}")
            report.append("")

        if scan_results.attack_surface.discovered_endpoints:
            report.append("### 🔍 Discovered Endpoints")
            report.append("")
            report.append("| URL | Status | Content Type | Size |")
            report.append("|-----|--------|--------------|------|")

            for endpoint in scan_results.attack_surface.discovered_endpoints:
                status = endpoint.status_code or "N/A"
                content_type = endpoint.content_type or "N/A"
                size = endpoint.content_length or "N/A"
                report.append(
                    f"| `{endpoint.url}` | {status} | {content_type} | {size} |"
                )
            report.append("")

        if scan_results.attack_surface.entry_points:
            report.append("### 🚪 Entry Points")
            report.append("")
            for entry in scan_results.attack_surface.entry_points:
                risk_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                    "info": "🔵",
                }
                report.append(
                    f"#### {risk_emoji.get(entry.risk_level, '⚪')} {entry.name}"
                )
                report.append(f"**Location:** `{entry.location}`")
                report.append(f"**Risk Level:** {entry.risk_level.upper()}")
                report.append("**Possible Attack Methods:**")
                for method in entry.attack_methods:
                    report.append(f"- {method}")
                report.append("")

    # Exposed Data
    if scan_results.exposed_data:
        report.append("## 🔓 Exposed Data")
        report.append("")
        for data in scan_results.exposed_data:
            sensitivity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "info": "🔵",
            }
            report.append(
                f"### {sensitivity_emoji.get(data.sensitivity, '⚪')} {data.data_type}"
            )
            report.append(f"**Source:** `{data.source}`")
            report.append(f"**Sensitivity:** {data.sensitivity.upper()}")
            report.append("**Content:**")
            report.append("```")
            report.append(data.content)
            report.append("```")
            report.append("")

    # Attack Vectors
    if scan_results.attack_vectors:
        report.append("## ⚔️ Attack Vectors")
        report.append("")
        for i, vector in enumerate(scan_results.attack_vectors, 1):
            report.append(f"### {i}. {vector.name}")
            report.append("")
            report.append(f"**Description:** {vector.description}")
            report.append("")

            if vector.required_tools:
                report.append("**Required Tools:**")
                for tool in vector.required_tools:
                    report.append(f"- {tool}")
                report.append("")

            if vector.commands:
                report.append("**Commands:**")
                report.append("```bash")
                for cmd in vector.commands:
                    report.append(cmd)
                report.append("```")
                report.append("")

            if vector.success_indicators:
                report.append("**Success Indicators:**")
                for indicator in vector.success_indicators:
                    report.append(f"- {indicator}")
                report.append("")

    # Remediation Roadmap
    if scan_results.remediation_roadmap:
        report.append("## 🛠️ Remediation Roadmap")
        report.append("")

        # Group by priority
        remediation_by_priority = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }
        for item in scan_results.remediation_roadmap:
            remediation_by_priority[item.priority].append(item)

        priority_order = ["critical", "high", "medium", "low", "info"]
        priority_emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }

        for priority in priority_order:
            items = remediation_by_priority[priority]
            if items:
                report.append(
                    f"### {priority_emojis[priority]} {priority.upper()} Priority"
                )
                report.append("")
                for item in items:
                    report.append(f"**Category:** {item.category}")
                    report.append(f"**Description:** {item.description}")
                    if item.effort:
                        report.append(f"**Effort Required:** {item.effort}")
                    report.append("")

    # Compliance Gaps
    if scan_results.compliance_gaps:
        report.append("## 📜 Compliance Gaps")
        report.append("")
        for gap in scan_results.compliance_gaps:
            report.append(f"- ❌ {gap}")
        report.append("")

    # Technical Evidence
    if scan_results.technical_evidence:
        report.append("## 🔬 Technical Evidence")
        report.append("")
        for i, evidence in enumerate(scan_results.technical_evidence, 1):
            report.append(f"### Evidence #{i}: {evidence.tool_name}")
            report.append("")
            report.append(f"**Command Executed:**")
            report.append(f"```bash")
            report.append(evidence.command_executed)
            report.append("```")
            report.append("")

            report.append(f"**Findings Summary:** {evidence.findings_summary}")
            report.append("")

            report.append("**Raw Output:**")
            report.append("```")
            # Truncate very long outputs
            raw_output = evidence.raw_output
            if len(raw_output) > 2000:
                raw_output = raw_output[:2000] + "\n... (output truncated)"
            report.append(raw_output)
            report.append("```")
            report.append("")

    # Footer
    report.append("---")
    report.append("")
    report.append("*Report generated by Cybersecurity AI Agent* 🤖")
    report.append("")

    return "\n".join(report)

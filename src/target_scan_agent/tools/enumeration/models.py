from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class FfufFinding(BaseModel):
    """Represents a single ffuf directory/file discovery result."""

    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str = Field(alias="content-type", default="")
    redirectlocation: str = Field(alias="redirectlocation", default="")

    class Config:
        populate_by_name = True

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")

    @property
    def is_interesting(self) -> bool:
        """Check if this finding is particularly interesting for security."""
        return self.status in [200, 403, 401, 500]

    @property
    def is_accessible(self) -> bool:
        """Check if the endpoint is accessible (200 status)."""
        return self.status == 200

    @property
    def is_forbidden(self) -> bool:
        """Check if the endpoint exists but is forbidden (403)."""
        return self.status == 403

    @property
    def size_formatted(self) -> str:
        """Get human-readable size."""
        if self.length < 1024:
            return f"{self.length} bytes"
        elif self.length < 1024 * 1024:
            return f"{self.length / 1024:.1f} KB"
        else:
            return f"{self.length / (1024 * 1024):.1f} MB"


class FfufScanResult(BaseModel):
    """Container for ffuf scan results with metadata and helper methods."""

    findings: List[FfufFinding]
    count: int
    scan_completed: bool = True
    error: Optional[str] = None
    target: str
    wordlist_type: str
    wordlist_size: int
    extensions: str
    scan_duration: Optional[float] = None

    @classmethod
    def create_empty(
        cls,
        target: str,
        wordlist_type: str,
        wordlist_size: int,
        extensions: str,
        scan_completed: bool = True,
    ) -> "FfufScanResult":
        """Create empty result for when no findings are found."""
        return cls(
            findings=[],
            count=0,
            scan_completed=scan_completed,
            target=target,
            wordlist_type=wordlist_type,
            wordlist_size=wordlist_size,
            extensions=extensions,
        )

    @classmethod
    def create_error(
        cls,
        error_message: str,
        target: str = "",
        wordlist_type: str = "",
        wordlist_size: int = 0,
        extensions: str = "",
    ) -> "FfufScanResult":
        """Create error result."""
        return cls(
            findings=[],
            count=0,
            scan_completed=False,
            error=error_message,
            target=target,
            wordlist_type=wordlist_type,
            wordlist_size=wordlist_size,
            extensions=extensions,
        )

    def has_findings(self) -> bool:
        """Check if scan has any findings."""
        return self.count > 0

    def get_findings_by_status(self, status: int) -> List[FfufFinding]:
        """Get findings filtered by HTTP status code."""
        return [f for f in self.findings if f.status == status]

    def get_accessible_findings(self) -> List[FfufFinding]:
        """Get only accessible endpoints (200 status)."""
        return self.get_findings_by_status(200)

    def get_forbidden_findings(self) -> List[FfufFinding]:
        """Get only forbidden endpoints (403 status)."""
        return self.get_findings_by_status(403)

    def get_interesting_findings(self) -> List[FfufFinding]:
        """Get findings that are particularly interesting for security."""
        return [f for f in self.findings if f.is_interesting]

    def get_status_summary(self) -> Dict[int, int]:
        """Get count of findings by status code."""
        summary = {}
        for finding in self.findings:
            summary[finding.status] = summary.get(finding.status, 0) + 1
        return summary

    def get_largest_findings(self, limit: int = 10) -> List[FfufFinding]:
        """Get findings sorted by response size (largest first)."""
        return sorted(self.findings, key=lambda f: f.length, reverse=True)[:limit]

    def get_potential_config_files(self) -> List[FfufFinding]:
        """Get findings that might be configuration files."""
        config_patterns = [
            "config",
            "settings",
            ".env",
            "web.config",
            "application.properties",
            "database.yml",
            "secrets",
        ]
        return [
            f
            for f in self.findings
            if any(pattern in f.url.lower() for pattern in config_patterns)
        ]

    def get_admin_panels(self) -> List[FfufFinding]:
        """Get findings that might be admin panels."""
        admin_patterns = ["admin", "dashboard", "panel", "manage", "control"]
        return [
            f
            for f in self.findings
            if any(pattern in f.url.lower() for pattern in admin_patterns)
        ]

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")

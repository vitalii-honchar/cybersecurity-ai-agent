from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class NmapPort(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None
    product: Optional[str] = None
    extrainfo: Optional[str] = None
    reason: Optional[str] = None
    reason_ttl: Optional[int] = None
    script_results: Optional[Dict[str, Any]] = None

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class NmapHost(BaseModel):
    ip: str
    hostname: Optional[str] = None
    state: str
    reason: Optional[str] = None
    ports: List[NmapPort] = Field(default_factory=list)
    os_info: Optional[Dict[str, Any]] = None
    uptime: Optional[str] = None
    distance: Optional[int] = None

    def get_open_ports(self) -> List[NmapPort]:
        """Get only open ports."""
        return [port for port in self.ports if port.state == "open"]

    def get_filtered_ports(self) -> List[NmapPort]:
        """Get only filtered ports."""
        return [port for port in self.ports if port.state == "filtered"]

    def get_closed_ports(self) -> List[NmapPort]:
        """Get only closed ports."""
        return [port for port in self.ports if port.state == "closed"]

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class NmapScanResult(BaseModel):
    hosts: List[NmapHost]
    scan_type: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_hosts: int = 0
    hosts_up: int = 0
    hosts_down: int = 0
    scan_completed: bool = True
    error: Optional[str] = None
    scan_metadata: Optional[Dict[str, Any]] = None

    @classmethod
    def create_empty(cls) -> "NmapScanResult":
        """Create empty result for when no hosts are found."""
        return cls(
            hosts=[],
            scan_type="unknown",
            total_hosts=0,
            hosts_up=0,
            hosts_down=0,
            scan_completed=True,
        )

    @classmethod
    def create_error(cls, error_message: str) -> "NmapScanResult":
        """Create error result."""
        return cls(
            hosts=[],
            scan_type="unknown",
            total_hosts=0,
            hosts_up=0,
            hosts_down=0,
            scan_completed=False,
            error=error_message,
        )

    def has_hosts(self) -> bool:
        """Check if scan has any hosts."""
        return len(self.hosts) > 0

    def get_hosts_with_open_ports(self) -> List[NmapHost]:
        """Get hosts that have open ports."""
        return [host for host in self.hosts if host.get_open_ports()]

    def get_all_open_ports(self) -> List[NmapPort]:
        """Get all open ports from all hosts."""
        open_ports = []
        for host in self.hosts:
            open_ports.extend(host.get_open_ports())
        return open_ports

    def get_ports_by_service(self, service: str) -> List[NmapPort]:
        """Get ports filtered by service name."""
        ports = []
        for host in self.hosts:
            ports.extend(
                [port for port in host.ports if service.lower() in port.service.lower()]
            )
        return ports

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")

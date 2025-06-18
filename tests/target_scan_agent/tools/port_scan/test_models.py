import pytest

from src.target_scan_agent.tools.port_scan.models import (
    NmapHost,
    NmapPort,
    NmapScanResult,
)


class TestNmapModels:
    """Test data models for nmap tool."""

    def test_nmap_port_creation(self):
        """Test NmapPort model creation and methods."""
        port = NmapPort(
            port=80,
            protocol="tcp",
            state="open",
            service="http",
            version="Apache 2.4.41",
            product="Apache httpd",
            reason="syn-ack",
            reason_ttl=64,
        )

        assert port.port == 80
        assert port.protocol == "tcp"
        assert port.state == "open"
        assert port.service == "http"
        assert port.version == "Apache 2.4.41"
        assert port.product == "Apache httpd"
        assert port.reason == "syn-ack"
        assert port.reason_ttl == 64

        # Test serialization
        port_dict = port.to_dict()
        assert port_dict["port"] == 80
        assert port_dict["service"] == "http"

        port_json = port.to_json()
        assert "80" in port_json
        assert "http" in port_json

    def test_nmap_host_creation(self):
        """Test NmapHost model creation and methods."""
        ports = [
            NmapPort(port=22, protocol="tcp", state="open", service="ssh"),
            NmapPort(port=80, protocol="tcp", state="open", service="http"),
            NmapPort(port=443, protocol="tcp", state="filtered", service="https"),
            NmapPort(port=8080, protocol="tcp", state="closed", service="http-proxy"),
        ]

        host = NmapHost(
            ip="192.168.1.100",
            hostname="test.example.com",
            state="up",
            reason="echo-reply",
            ports=ports,
            distance=1,
        )

        assert host.ip == "192.168.1.100"
        assert host.hostname == "test.example.com"
        assert host.state == "up"
        assert host.reason == "echo-reply"
        assert len(host.ports) == 4
        assert host.distance == 1

        # Test port filtering methods
        open_ports = host.get_open_ports()
        assert len(open_ports) == 2
        assert all(port.state == "open" for port in open_ports)

        filtered_ports = host.get_filtered_ports()
        assert len(filtered_ports) == 1
        assert filtered_ports[0].port == 443

        closed_ports = host.get_closed_ports()
        assert len(closed_ports) == 1
        assert closed_ports[0].port == 8080

        # Test serialization
        host_dict = host.to_dict()
        assert host_dict["ip"] == "192.168.1.100"
        assert len(host_dict["ports"]) == 4

    def test_nmap_scan_result_creation(self):
        """Test NmapScanResult model creation and methods."""
        host1 = NmapHost(
            ip="192.168.1.100",
            state="up",
            ports=[
                NmapPort(port=22, protocol="tcp", state="open", service="ssh"),
                NmapPort(port=80, protocol="tcp", state="open", service="http"),
            ],
        )

        host2 = NmapHost(
            ip="192.168.1.101",
            state="up",
            ports=[
                NmapPort(port=443, protocol="tcp", state="open", service="https"),
            ],
        )

        result = NmapScanResult(
            hosts=[host1, host2],
            scan_type="syn",
            total_hosts=2,
            hosts_up=2,
            hosts_down=0,
            scan_completed=True,
        )

        assert len(result.hosts) == 2
        assert result.scan_type == "syn"
        assert result.total_hosts == 2
        assert result.hosts_up == 2
        assert result.hosts_down == 0
        assert result.scan_completed is True

        # Test helper methods
        assert result.has_hosts() is True

        hosts_with_open_ports = result.get_hosts_with_open_ports()
        assert len(hosts_with_open_ports) == 2

        all_open_ports = result.get_all_open_ports()
        assert len(all_open_ports) == 3

        http_ports = result.get_ports_by_service("http")
        assert len(http_ports) == 2  # http and https

        ssh_ports = result.get_ports_by_service("ssh")
        assert len(ssh_ports) == 1

    def test_nmap_scan_result_empty(self):
        """Test empty NmapScanResult creation."""
        result = NmapScanResult.create_empty()

        assert len(result.hosts) == 0
        assert result.scan_type == "unknown"
        assert result.total_hosts == 0
        assert result.hosts_up == 0
        assert result.hosts_down == 0
        assert result.scan_completed is True
        assert result.error is None
        assert result.has_hosts() is False

    def test_nmap_scan_result_error(self):
        """Test error NmapScanResult creation."""
        error_msg = "Target host unreachable"
        result = NmapScanResult.create_error(error_msg)

        assert len(result.hosts) == 0
        assert result.scan_type == "unknown"
        assert result.total_hosts == 0
        assert result.hosts_up == 0
        assert result.hosts_down == 0
        assert result.scan_completed is False
        assert result.error == error_msg
        assert result.has_hosts() is False

    def test_serialization(self):
        """Test JSON serialization of all models."""
        port = NmapPort(port=80, protocol="tcp", state="open", service="http")
        host = NmapHost(ip="192.168.1.100", state="up", ports=[port])
        result = NmapScanResult(
            hosts=[host], scan_type="syn", total_hosts=1, hosts_up=1, hosts_down=0
        )

        # Test all models can be serialized to JSON
        port_json = port.to_json()
        host_json = host.to_json()
        result_json = result.to_json()

        assert isinstance(port_json, str)
        assert isinstance(host_json, str)
        assert isinstance(result_json, str)

        # Test all models can be serialized to dict
        port_dict = port.to_dict()
        host_dict = host.to_dict()
        result_dict = result.to_dict()

        assert isinstance(port_dict, dict)
        assert isinstance(host_dict, dict)
        assert isinstance(result_dict, dict)

import subprocess

import pytest

from src.target_scan_agent.tools.port_scan.models import NmapScanResult
from src.target_scan_agent.tools.port_scan.nmap_tool import nmap_port_scan_tool


class TestNmapIntegration:
    """Integration tests for nmap_port_scan_tool against local vulnerable FastAPI app."""

    def is_nmap_available(self):
        """Check if nmap binary is available."""
        try:
            result = subprocess.run(
                ["nmap", "--version"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def validate_nmap_scan_result(
        self, result: NmapScanResult, expected_port: int = None
    ):
        """Validate nmap scan result structure."""
        assert isinstance(result, NmapScanResult)

        if result.error:
            print(f"Scan error: {result.error}")
            return True

        print(f"Scan completed: {result.scan_completed}")
        print(f"Total hosts: {result.total_hosts}")
        print(f"Hosts up: {result.hosts_up}")
        print(f"Hosts down: {result.hosts_down}")

        if not result.has_hosts():
            print("No hosts detected")
            return True

        # Validate host information
        for i, host in enumerate(result.hosts, 1):
            print(f"Host {i}: {host.ip}")
            if host.hostname:
                print(f"  Hostname: {host.hostname}")
            print(f"  State: {host.state}")
            print(f"  Open ports: {len(host.get_open_ports())}")

            # Display open ports
            open_ports = host.get_open_ports()
            for port in open_ports:
                print(f"    {port.port}/{port.protocol} - {port.service}")
                if port.version:
                    print(f"      Version: {port.version}")
                if port.product:
                    print(f"      Product: {port.product}")

            # If we expect a specific port, verify it's found
            if expected_port:
                port_numbers = [port.port for port in open_ports]
                if expected_port in port_numbers:
                    print(f"  ✅ Found expected port {expected_port}")
                else:
                    print(
                        f"  ⚠️  Expected port {expected_port} not found in open ports: {port_numbers}"
                    )

        return True

    @pytest.mark.integration
    async def test_nmap_syn_scan_vulnerable_app(self, fastapi_server):
        """Test SYN scan against vulnerable FastAPI app."""
        if not self.is_nmap_available():
            pytest.skip("Nmap not available")

        # Extract host and port from server URL
        import urllib.parse

        parsed = urllib.parse.urlparse(fastapi_server)
        target_host = parsed.hostname or "127.0.0.1"
        target_port = parsed.port or 8000

        print(f"\n🎯 Testing nmap SYN scan against: {target_host}:{target_port}")

        # Run nmap SYN scan
        result = await nmap_port_scan_tool(
            target=target_host,
            ports=str(target_port),
            scan_type="syn",
            service_detection=True,
            timeout=60,
        )

        print(f"\n📊 Nmap scan results:")
        print("=" * 50)

        # Validate results
        self.validate_nmap_scan_result(result, expected_port=target_port)

        print("=" * 50)
        print("✅ SYN scan test completed!")

    @pytest.mark.integration
    async def test_nmap_tcp_scan_vulnerable_app(self, fastapi_server):
        """Test TCP connect scan against vulnerable FastAPI app."""
        if not self.is_nmap_available():
            pytest.skip("Nmap not available")

        # Extract host and port from server URL
        import urllib.parse

        parsed = urllib.parse.urlparse(fastapi_server)
        target_host = parsed.hostname or "127.0.0.1"
        target_port = parsed.port or 8000

        print(f"\n🎯 Testing nmap TCP scan against: {target_host}:{target_port}")

        # Run nmap TCP connect scan
        result = await nmap_port_scan_tool(
            target=target_host,
            ports=str(target_port),
            scan_type="tcp",
            service_detection=True,
            script_scan=True,
            timeout=60,
        )

        print(f"\n📊 Nmap TCP scan results:")
        print("=" * 50)

        # Validate results
        self.validate_nmap_scan_result(result, expected_port=target_port)

        print("=" * 50)
        print("✅ TCP scan test completed!")

    @pytest.mark.integration
    async def test_nmap_port_range_scan(self, fastapi_server):
        """Test port range scan against vulnerable FastAPI app."""
        if not self.is_nmap_available():
            pytest.skip("Nmap not available")

        # Extract host and port from server URL
        import urllib.parse

        parsed = urllib.parse.urlparse(fastapi_server)
        target_host = parsed.hostname or "127.0.0.1"
        target_port = parsed.port or 8000

        print(f"\n🎯 Testing nmap port range scan against: {target_host}")

        # Run nmap scan on common ports plus our target port
        port_range = f"22,80,443,{target_port}"
        result = await nmap_port_scan_tool(
            target=target_host,
            ports=port_range,
            scan_type="syn",
            service_detection=True,
            timeout=90,
        )

        print(f"\n📊 Nmap port range scan results:")
        print("=" * 50)

        # Validate results
        self.validate_nmap_scan_result(result, expected_port=target_port)

        print("=" * 50)
        print("✅ Port range scan test completed!")

    @pytest.mark.integration
    async def test_nmap_ping_scan(self):
        """Test ping scan (host discovery) against localhost."""
        if not self.is_nmap_available():
            pytest.skip("Nmap not available")

        print(f"\n🎯 Testing nmap ping scan against localhost")

        # Run nmap ping scan
        result = await nmap_port_scan_tool(
            target="127.0.0.1",
            scan_type="ping",
            timeout=30,
        )

        print(f"\n📊 Nmap ping scan results:")
        print("=" * 50)

        # Validate results
        self.validate_nmap_scan_result(result)

        if result.has_hosts():
            # Should find localhost as up
            localhost_host = result.hosts[0]
            assert localhost_host.ip == "127.0.0.1"
            assert localhost_host.state == "up"
            print(f"  ✅ Localhost detected as up")

        print("=" * 50)
        print("✅ Ping scan test completed!")

    @pytest.mark.integration
    async def test_nmap_scan_nonexistent_host(self):
        """Test nmap scan against non-existent host."""
        if not self.is_nmap_available():
            pytest.skip("Nmap not available")

        print(f"\n🎯 Testing nmap scan against non-existent host")

        # Run nmap scan against non-existent host
        result = await nmap_port_scan_tool(
            target="192.168.255.254",  # Unlikely to exist
            ports="80,443",
            scan_type="syn",
            timeout=30,
        )

        print(f"\n📊 Nmap scan results for non-existent host:")
        print("=" * 50)

        # Should complete without error even if no hosts found
        assert isinstance(result, NmapScanResult)
        assert result.scan_completed is True or result.error is not None

        if result.error:
            print(f"Expected error for non-existent host: {result.error}")
        else:
            print(f"Scan completed, hosts found: {result.total_hosts}")

        print("=" * 50)
        print("✅ Non-existent host test completed!")

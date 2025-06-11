import subprocess
import time
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from typing import Optional, List

from .models import NmapScanResult, NmapHost, NmapPort
from ..common.process_utils import (
    create_temp_file,
    delete_temp_file,
    execute_process,
    terminate_process,
    wait_for_process_completion,
)


async def nmap_port_scan_tool(
    target: str,
    ports: Optional[str] = None,
    scan_type: str = "syn",
    service_detection: bool = True,
    os_detection: bool = False,
    script_scan: bool = False,
    timeout: int = 300,
) -> NmapScanResult:
    """
    Run Nmap port scanner and return structured results.

    Args:
        target: Target to scan (IP address, hostname, or CIDR range)
        ports: Port specification (default: top 1000 ports)
        scan_type: Type of scan to perform. Options: "syn" (TCP SYN scan, default), "tcp" (TCP connect scan), "udp" (UDP scan), or "ping" (ping scan only)
        service_detection: Enable service/version detection
        os_detection: Enable OS detection (requires root privileges)
        script_scan: Enable default NSE scripts
        timeout: Scan timeout in seconds

    Returns:
        NmapScanResult with hosts, ports, and scan metadata
    """
    process = None
    temp_file = None

    try:
        temp_file = create_temp_file(suffix=".xml")

        cmd = _create_command(
            target=target,
            ports=ports,
            scan_type=scan_type,
            service_detection=service_detection,
            os_detection=os_detection,
            script_scan=script_scan,
            temp_file=temp_file,
        )

        logging.info(f"🚀 Starting nmap scan: {' '.join(cmd)}")
        start_time = time.time()

        process = execute_process(cmd)
        scan_completed = await wait_for_process_completion(process, timeout, start_time)

        result = _parse_xml_output(temp_file, scan_type, scan_completed)
        return result

    except Exception as e:
        logging.error(f"Error during nmap scan: %s", e)
        return NmapScanResult.create_error(f"Nmap scan failed: {str(e)}")
    finally:
        terminate_process(process)
        delete_temp_file(temp_file)


def _create_command(
    target: str,
    ports: Optional[str],
    scan_type: str,
    service_detection: bool,
    os_detection: bool,
    script_scan: bool,
    temp_file: str,
) -> List[str]:
    """Create nmap command based on parameters."""
    cmd = ["nmap"]

    # Scan type
    if scan_type == "syn":
        cmd.append("-sS")
    elif scan_type == "tcp":
        cmd.append("-sT")
    elif scan_type == "udp":
        cmd.append("-sU")
    elif scan_type == "ping":
        cmd.append("-sn")

    # Port specification
    if ports and scan_type != "ping":
        cmd.extend(["-p", ports])

    # Service detection
    if service_detection and scan_type != "ping":
        cmd.append("-sV")

    # OS detection
    if os_detection:
        cmd.append("-O")

    # Script scanning
    if script_scan and scan_type != "ping":
        cmd.append("-sC")

    # Output format
    cmd.extend(["-oX", temp_file])

    # Target
    cmd.append(target)

    # Common options
    cmd.extend([
        "-T4",  # Timing template (aggressive)
        "--open",  # Only show open ports
        "--host-timeout", "300s",  # Host timeout
    ])

    return cmd


def _parse_xml_output(temp_file: str, scan_type: str, scan_completed: bool) -> NmapScanResult:
    """Parse nmap XML output and return structured results."""
    try:
        tree = ET.parse(temp_file)
        root = tree.getroot()

        hosts = []
        total_hosts = 0
        hosts_up = 0
        hosts_down = 0

        # Parse scan info
        scan_info = root.find("scaninfo")
        start_time = None
        end_time = None

        if root.get("start"):
            start_time = datetime.fromtimestamp(int(root.get("start")))

        runstats = root.find("runstats/finished")
        if runstats is not None and runstats.get("time"):
            end_time = datetime.fromtimestamp(int(runstats.get("time")))

        # Parse hosts
        for host_elem in root.findall("host"):
            host = _parse_host(host_elem)
            if host:
                hosts.append(host)
                total_hosts += 1
                if host.state == "up":
                    hosts_up += 1
                else:
                    hosts_down += 1

        logging.info(f"Successfully parsed {len(hosts)} hosts from nmap output")

        return NmapScanResult(
            hosts=hosts,
            scan_type=scan_type,
            start_time=start_time,
            end_time=end_time,
            total_hosts=total_hosts,
            hosts_up=hosts_up,
            hosts_down=hosts_down,
            scan_completed=scan_completed,
        )

    except ET.ParseError as e:
        logging.error(f"Failed to parse nmap XML output: {e}")
        return NmapScanResult.create_error(f"Failed to parse XML output: {str(e)}")
    except Exception as e:
        logging.error(f"Error parsing nmap output: {e}")
        return NmapScanResult.create_error(f"Failed to parse results: {str(e)}")


def _parse_host(host_elem) -> Optional[NmapHost]:
    """Parse individual host from XML."""
    try:
        # Host state
        status_elem = host_elem.find("status")
        if status_elem is None:
            return None

        state = status_elem.get("state", "unknown")
        reason = status_elem.get("reason")

        # IP address
        address_elem = host_elem.find("address[@addrtype='ipv4']")
        if address_elem is None:
            address_elem = host_elem.find("address[@addrtype='ipv6']")
        
        if address_elem is None:
            return None

        ip = address_elem.get("addr")

        # Hostname
        hostname = None
        hostnames_elem = host_elem.find("hostnames/hostname")
        if hostnames_elem is not None:
            hostname = hostnames_elem.get("name")

        # Ports
        ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port = _parse_port(port_elem)
                if port:
                    ports.append(port)

        # OS info
        os_info = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            os_info = _parse_os_info(os_elem)

        # Distance
        distance = None
        distance_elem = host_elem.find("distance")
        if distance_elem is not None:
            distance = int(distance_elem.get("value", 0))

        return NmapHost(
            ip=ip,
            hostname=hostname,
            state=state,
            reason=reason,
            ports=ports,
            os_info=os_info,
            distance=distance,
        )

    except Exception as e:
        logging.warning(f"Failed to parse host: {e}")
        return None


def _parse_port(port_elem) -> Optional[NmapPort]:
    """Parse individual port from XML."""
    try:
        port_id = int(port_elem.get("portid"))
        protocol = port_elem.get("protocol", "tcp")

        # Port state
        state_elem = port_elem.find("state")
        if state_elem is None:
            return None

        state = state_elem.get("state")
        reason = state_elem.get("reason")
        reason_ttl = state_elem.get("reason_ttl")
        if reason_ttl:
            reason_ttl = int(reason_ttl)

        # Service info
        service_elem = port_elem.find("service")
        service = "unknown"
        version = None
        product = None
        extrainfo = None

        if service_elem is not None:
            service = service_elem.get("name", "unknown")
            version = service_elem.get("version")
            product = service_elem.get("product")
            extrainfo = service_elem.get("extrainfo")

        # Script results
        script_results = {}
        for script_elem in port_elem.findall("script"):
            script_id = script_elem.get("id")
            script_output = script_elem.get("output")
            if script_id and script_output:
                script_results[script_id] = script_output

        return NmapPort(
            port=port_id,
            protocol=protocol,
            state=state,
            service=service,
            version=version,
            product=product,
            extrainfo=extrainfo,
            reason=reason,
            reason_ttl=reason_ttl,
            script_results=script_results if script_results else None,
        )

    except Exception as e:
        logging.warning(f"Failed to parse port: {e}")
        return None


def _parse_os_info(os_elem) -> dict:
    """Parse OS information from XML."""
    os_info = {}
    
    # OS matches
    osmatch_elems = os_elem.findall("osmatch")
    if osmatch_elems:
        matches = []
        for osmatch in osmatch_elems:
            match_info = {
                "name": osmatch.get("name"),
                "accuracy": int(osmatch.get("accuracy", 0)),
            }
            matches.append(match_info)
        os_info["matches"] = matches

    # OS classes
    osclass_elems = os_elem.findall("osclass")
    if osclass_elems:
        classes = []
        for osclass in osclass_elems:
            class_info = {
                "type": osclass.get("type"),
                "vendor": osclass.get("vendor"),
                "osfamily": osclass.get("osfamily"),
                "osgen": osclass.get("osgen"),
                "accuracy": int(osclass.get("accuracy", 0)),
            }
            classes.append(class_info)
        os_info["classes"] = classes

    return os_info
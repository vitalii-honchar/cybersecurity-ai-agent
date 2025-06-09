import time
import logging
from pathlib import Path
from typing import Optional
from pydantic import ValidationError

from .models import FfufScanResult, FfufFinding
from ..common.process_utils import (
    create_temp_file,
    delete_temp_file,
    execute_process,
    terminate_process,
    wait_for_process_completion,
    read_json_file,
    count_lines_in_file,
)


def _get_wordlist_path(wordlist_type: str) -> Optional[str]:
    """Get path to wordlist. Simple lookup with no complex logic."""
    # Find wordlists directory
    possible_paths = [
        Path.cwd() / "wordlists",
        Path(__file__).parent.parent.parent.parent.parent / "wordlists",
        Path.home() / "wordlists",
    ]

    wordlist_base = None
    for path in possible_paths:
        if path.exists():
            wordlist_base = path
            break

    if not wordlist_base:
        return None

    # Simple wordlist mapping - only 3 essential lists
    wordlist_files = {"common": "common.txt", "medium": "medium.txt", "big": "big.txt"}

    wordlist_file = wordlist_files.get(wordlist_type)
    if not wordlist_file:
        return None

    full_path = wordlist_base / wordlist_file
    return str(full_path) if full_path.exists() else None


def _get_scan_timeout(wordlist_size: int) -> int:
    """Get appropriate timeout based on wordlist size."""
    if wordlist_size < 10000:
        return 300  # 5 minutes
    elif wordlist_size < 300000:
        return 1800  # 30 minutes
    else:
        return 3600  # 60 minutes


def _create_ffuf_command(
    target: str,
    wordlist_path: str,
    output_file: str,
    extensions: str
) -> list[str]:
    """Create ffuf command with consistent parameters."""
    cmd = [
        "ffuf",
        "-w", wordlist_path,
        "-u", f"{target.rstrip('/')}/FUZZ",
        "-o", output_file,
        "-of", "json",
        "-c",  # Colorize
        "-t", "50",  # Threads
        "-timeout", "10",
        "-mc", "200,201,204,301,302,307,401,403,500",  # Match interesting codes
        "-fs", "0",  # Filter zero size
        "-ac",  # Auto-calibrate
    ]

    # Add extensions if provided
    if extensions.strip():
        cmd.extend(["-e", extensions])

    return cmd


def _parse_ffuf_results(output_file: str) -> list[FfufFinding]:
    """Parse ffuf JSON output into structured findings."""
    findings = []
    
    try:
        data = read_json_file(output_file)
        results = data.get("results", [])
        
        for result in results:
            try:
                finding = FfufFinding.model_validate(result)
                findings.append(finding)
            except ValidationError as e:
                logging.warning(f"Failed to validate ffuf finding: {e}")
                
    except Exception as e:
        logging.error(f"Failed to parse ffuf results: {e}")
    
    return findings


async def ffuf_directory_scan(
    target: str,
    wordlist_type: str = "common",
    extensions: str = "php,html,js,txt",
    timeout: Optional[int] = None
) -> FfufScanResult:
    """
    Fast web directory discovery using ffuf with structured output.

    Args:
        target: Target URL to scan (e.g., "http://localhost:8000")
        wordlist_type: Choose scanning coverage level - "common", "medium", or "big"
        extensions: File extensions to test, comma-separated
        timeout: Custom timeout in seconds (optional, auto-calculated if not provided)

    Returns:
        FfufScanResult with findings, metadata, and helper methods
    """
    process = None
    temp_file = None
    start_time = time.time()

    try:
        # Validate wordlist
        wordlist_path = _get_wordlist_path(wordlist_type)
        if not wordlist_path:
            return FfufScanResult.create_error(
                f"Wordlist '{wordlist_type}' not found. Available options: common, medium, big",
                target=target,
                wordlist_type=wordlist_type,
                extensions=extensions
            )

        # Get wordlist size
        wordlist_size = count_lines_in_file(wordlist_path)
        
        # Set timeout
        if timeout is None:
            timeout = _get_scan_timeout(wordlist_size)

        logging.info(f"🔄 Starting ffuf scan with {wordlist_size:,} wordlist entries...")

        # Create temp output file
        temp_file = create_temp_file(suffix=".json")

        # Build command
        cmd = _create_ffuf_command(target, wordlist_path, temp_file, extensions)

        logging.info(f"🚀 Starting ffuf scan: {' '.join(cmd)}")

        # Execute process
        process = execute_process(cmd)
        scan_completed = await wait_for_process_completion(process, timeout, start_time)

        # Parse results
        findings = _parse_ffuf_results(temp_file)
        scan_duration = time.time() - start_time

        logging.info(f"Successfully parsed {len(findings)} findings from ffuf output")

        return FfufScanResult(
            findings=findings,
            count=len(findings),
            scan_completed=scan_completed,
            target=target,
            wordlist_type=wordlist_type,
            wordlist_size=wordlist_size,
            extensions=extensions,
            scan_duration=scan_duration
        )

    except FileNotFoundError:
        return FfufScanResult.create_error(
            "ffuf not found. Install with: sudo apt install ffuf or go install github.com/ffuf/ffuf/v2@latest",
            target=target,
            wordlist_type=wordlist_type,
            extensions=extensions
        )
    except Exception as e:
        logging.error(f"Error during ffuf scan: {e}")
        return FfufScanResult.create_error(
            f"ffuf scan failed: {str(e)}",
            target=target,
            wordlist_type=wordlist_type,
            extensions=extensions
        )
    finally:
        terminate_process(process)
        delete_temp_file(temp_file)


# Sync wrapper for backward compatibility
def ffuf_directory_scan_sync(
    target: str,
    wordlist_type: str = "common", 
    extensions: str = "php,html,js,txt"
) -> FfufScanResult:
    """Synchronous wrapper for ffuf_directory_scan."""
    import asyncio
    return asyncio.run(ffuf_directory_scan(target, wordlist_type, extensions))
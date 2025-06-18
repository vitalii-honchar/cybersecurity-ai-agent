import asyncio
import json
import logging
import os
import subprocess
import tempfile
import time
from typing import Optional


def create_temp_file(suffix: str = ".jsonl") -> str:
    """Create temporary file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w+", suffix=suffix, delete=False) as f:
        return f.name


def delete_temp_file(temp_file: Optional[str]):
    """Safely delete temporary file."""
    if temp_file and os.path.exists(temp_file):
        try:
            os.unlink(temp_file)
        except Exception:
            pass


def execute_process(cmd: list[str], cwd: Optional[str] = None) -> subprocess.Popen:
    """Execute subprocess with consistent configuration."""
    if cwd is None:
        cwd = os.path.expanduser("~")

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
    )


def terminate_process(process: Optional[subprocess.Popen]):
    """Safely terminate subprocess."""
    if process and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass


async def wait_for_process_completion(
    process: subprocess.Popen,
    timeout: int,
    start_time: float,
    progress_interval: int = 30,
) -> tuple[bool, str, str]:
    """
    Wait for process completion with timeout and progress logging.

    Args:
        process: The subprocess to monitor
        timeout: Maximum time to wait in seconds
        start_time: When the process was started
        progress_interval: How often to log progress in seconds

    Returns:
        True if process completed successfully, False if timed out
    """
    last_check_time = start_time

    while True:
        poll_result = process.poll()
        if poll_result is not None:
            logging.info(f"✅ Process completed (exit code: {poll_result})")
            # Ignore stdout/stderr
            stdout, stderr = process.communicate()
            return poll_result == 0, stdout, stderr

        elapsed = time.time() - start_time
        if elapsed > timeout:
            logging.info(
                f"⏱️ Timeout reached ({timeout}s), collecting partial results..."
            )
            terminate_process(process)
            stdout, stderr = process.communicate()
            return False, stdout, stderr

        if time.time() - last_check_time > progress_interval:
            logging.info(f"📊 Scan in progress... ({elapsed:.0f}s elapsed)")
            last_check_time = time.time()

        await asyncio.sleep(1)


def read_json_file(file_path: str) -> dict:
    """Read and parse JSON file."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to read JSON file {file_path}: {e}")
        return {}


def count_lines_in_file(file_path: str) -> int:
    """Count non-empty lines in a file."""
    try:
        with open(file_path, "r") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0

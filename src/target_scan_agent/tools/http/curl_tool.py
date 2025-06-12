import subprocess
import time
import logging
import shlex
from target_scan_agent.tools.common.process_utils import (
    wait_for_process_completion,
    terminate_process,
    execute_process,
)
from .models import CurlResult


async def curl_tool(curl_args: str, timeout: int = 60) -> dict:
    """
    Execute curl command with flexible arguments and return structured results.

    This tool provides maximum flexibility by allowing any curl arguments to be passed as a string.
    The -v (verbose) flag is automatically added to capture detailed output.

    Args:
        curl_args: Space-separated curl arguments as a single string
        timeout: Maximum execution time in seconds (default: 60)

    Returns:
        dict: JSON representation with command, content, exit_code, execution_time, and optional error
    """
    process = None

    if not curl_args or not curl_args.strip():
        return CurlResult.create_error(
            "", "No arguments provided to curl command"
        ).to_dict()

    start_time = time.time()
    try:
        # Parse curl arguments from string

        args_list = shlex.split(curl_args)

        # Build curl command with verbose flag
        cmd = ["curl", "-v"] + args_list
        command_str = " ".join(cmd)

        logging.info(f"🚀 Executing curl command: {command_str}")

        # Execute curl command
        process = execute_process(cmd)

        completed, stdout, stderr = await wait_for_process_completion(
            process, timeout, start_time
        )

        execution_time = time.time() - start_time

        if not completed:
            logging.warning(
                f"⚠️ Curl command failed with exit code {process.returncode}"
            )
            return CurlResult.create_error(
                command_str,
                f"Curl command failed with exit code {process.returncode}. Stdout: {stdout}, Stderr: {stderr}",
                process.returncode,
                execution_time,
            ).to_dict()

        logging.info(f"✅ Curl command completed successfully in {execution_time:.2f}s")

        return CurlResult.create_success(
            command_str, f"Stdout: {stdout}, Stderr: {stderr}", execution_time
        ).to_dict()
    except Exception as e:
        logging.error(f"❌ Error executing curl command: {e}")
        return CurlResult.create_error(
            " ".join(["curl", "-v"] + shlex.split(curl_args)) if curl_args else "",
            f"Failed to execute curl command: {str(e)}",
            1,
            time.time() - start_time,
        ).to_dict()
    finally:
        terminate_process(process)

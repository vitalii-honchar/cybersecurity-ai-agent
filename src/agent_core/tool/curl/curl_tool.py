import subprocess
import time
import logging
import shlex
from agent_core.state import Tool
from agent_core.tool.process.process import (
    wait_for_process_completion,
    terminate_process,
    execute_process,
)
from .models import CurlResult


def _balance_quotes(args_string: str) -> str:
    """
    Balance unmatched quotes in curl arguments string.

    Args:
        args_string: The original curl arguments string

    Returns:
        str: Arguments string with balanced quotes
    """
    # Count single and double quotes
    single_quotes = args_string.count("'")
    double_quotes = args_string.count('"')

    # If odd number of quotes, add closing quote at the end
    if single_quotes % 2 == 1:
        args_string += "'"
    if double_quotes % 2 == 1:
        args_string += '"'

    return args_string


def _safe_split_args(args_string: str) -> list[str]:
    """
    Safely split curl arguments with fallback for malformed quotes.

    Args:
        args_string: The curl arguments string to split

    Returns:
        list[str]: List of parsed arguments

    Raises:
        ValueError: If arguments cannot be parsed even with fallbacks
    """
    if not args_string or not args_string.strip():
        return []

    try:
        # First attempt: normal shlex parsing
        return shlex.split(args_string)
    except ValueError as e:
        logging.warning(
            f"Initial shlex parsing failed: {e}. Attempting quote balancing..."
        )

        try:
            # Second attempt: balance quotes and retry
            balanced_args = _balance_quotes(args_string)
            return shlex.split(balanced_args)
        except ValueError:
            logging.warning("Quote balancing failed. Using simple split as fallback...")

            # Final fallback: simple split (less safe but functional)
            # Remove problematic quotes and split on spaces
            cleaned_args = args_string.replace("'", "").replace('"', "")
            return cleaned_args.split()


async def curl_tool(curl_args: str, timeout: int = 60) -> dict:
    """
    Execute curl command with flexible arguments and return structured results.

    This tool provides maximum flexibility by allowing any curl arguments to be passed as a string.
    The -i (include headers) flag is automatically added to capture detailed output.

    IMPORTANT: Always properly quote/escape arguments containing special characters.

    ✅ CORRECT EXAMPLES:

    Basic GET request:
    curl_args = "-X GET http://localhost:8000/api/users"

    POST with data:
    curl_args = "-X POST http://localhost:8000/api/login -d 'username=admin&password=test'"

    Headers and authentication:
    curl_args = "-X GET http://localhost:8000/api/admin -H 'Authorization: Bearer token123'"

    SQL injection testing:
    curl_args = "-X GET 'http://localhost:8000/users?id=1 OR 1=1'"

    Complex payload injection:
    curl_args = "-X POST http://localhost:8000/search -d 'query=test\'; DROP TABLE users; --'"

    File upload testing:
    curl_args = "-X POST http://localhost:8000/upload -F 'file=@/etc/passwd'"

    Cookie-based testing:
    curl_args = "-X GET http://localhost:8000/admin -b 'session=abc123; admin=true'"

    ❌ COMMON MISTAKES TO AVOID:

    Unmatched quotes:
    curl_args = "-X GET http://localhost:8000/users?id=1' AND SLEEP(5) --"  # Missing opening quote

    Unescaped special characters:
    curl_args = "-X GET http://localhost:8000/search?q=test&admin=true"  # Should quote the URL

    Mixed quote types:
    curl_args = "-X POST http://localhost:8000 -d 'data="value"'"  # Confusing quote nesting

    💡 SECURITY TESTING TIPS:

    1. Always quote URLs containing special characters: 'http://example.com/path?param=value'
    2. Use single quotes for payloads containing double quotes: 'payload="malicious"'
    3. Escape single quotes in payloads: 'don\'t break parsing'
    4. For complex payloads, consider using -d @- with heredoc or separate files

    Args:
        curl_args: Space-separated curl arguments as a single string (properly quoted)
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
        # Parse curl arguments from string with robust error handling
        args_list = _safe_split_args(curl_args)

        # Build curl command with include headers flag
        cmd = ["curl", "-i"] + args_list
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

        # Provide helpful error message with examples
        error_msg = f"Failed to execute curl command: {str(e)}"

        if "No closing quotation" in str(e) or "quote" in str(e).lower():
            error_msg += """
            
🔧 QUOTE FORMATTING HELP:

✅ Correct examples:
- curl_args = "-X GET 'http://localhost:8000/api?param=value'"
- curl_args = "-X POST http://localhost:8000 -d 'data=test'"
- curl_args = "-X GET http://localhost:8000 -H 'Content-Type: application/json'"

❌ Your command had unmatched quotes. Common fixes:
- Ensure every opening quote has a matching closing quote
- Use single quotes around URLs with special characters
- Escape quotes inside quoted strings: 'don\'t'
- For complex payloads, avoid mixing quote types
            """

        try:
            safe_args = _safe_split_args(curl_args) if curl_args else []
            command_str = " ".join(["curl", "-i"] + safe_args)
        except:
            command_str = f"curl -i {curl_args}" if curl_args else "curl"

        return CurlResult.create_error(
            command_str,
            error_msg,
            1,
            time.time() - start_time,
        ).to_dict()
    finally:
        terminate_process(process)


CURL_TOOL = Tool(
    name=curl_tool.__name__,
    capabilities=["scan", "attack"],
    description="Execute HTTP requests with custom headers, methods, and payloads. Returns response data including status codes, headers, and body content.",
)

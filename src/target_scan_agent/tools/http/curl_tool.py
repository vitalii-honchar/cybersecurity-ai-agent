import subprocess
import time
import logging
from typing import List

from .models import CurlResult
from ..common.process_utils import execute_process, terminate_process


async def curl_tool(curl_args: str, timeout: int = 60) -> CurlResult:
    """
    Execute curl command with flexible arguments and return structured results.
    
    This tool provides maximum flexibility by allowing any curl arguments to be passed as a string.
    The -v (verbose) flag is automatically added to capture detailed output.
    
    Args:
        curl_args: Space-separated curl arguments as a single string
        timeout: Maximum execution time in seconds (default: 60)
    
    Returns:
        CurlResult with command, content, exit_code, execution_time, and optional error
    """
    process = None
    
    if not curl_args or not curl_args.strip():
        return CurlResult.create_error("", "No arguments provided to curl command")
    
    try:
        # Parse curl arguments from string
        import shlex
        args_list = shlex.split(curl_args)
        
        # Build curl command with verbose flag
        cmd = ["curl", "-v"] + args_list
        command_str = " ".join(cmd)
        
        logging.info(f"🚀 Executing curl command: {command_str}")
        start_time = time.time()
        
        # Execute curl command
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Combine stderr with stdout to capture verbose output
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Wait for completion with timeout
        try:
            stdout, _ = process.communicate(timeout=timeout)
            execution_time = time.time() - start_time
            
            if process.returncode == 0:
                logging.info(f"✅ Curl command completed successfully in {execution_time:.2f}s")
                return CurlResult.create_success(command_str, stdout, execution_time)
            else:
                logging.warning(f"⚠️ Curl command failed with exit code {process.returncode}")
                return CurlResult.create_error(
                    command_str, 
                    f"Curl command failed with exit code {process.returncode}. Output: {stdout}",
                    process.returncode,
                    execution_time
                )
                
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            logging.error(f"⏰ Curl command timed out after {timeout}s")
            process.kill()
            process.communicate()  # Clean up
            return CurlResult.create_error(
                command_str,
                f"Curl command timed out after {timeout} seconds",
                124,  # Standard timeout exit code
                execution_time
            )
            
    except Exception as e:
        execution_time = time.time() - start_time if 'start_time' in locals() else 0.0
        logging.error(f"❌ Error executing curl command: {e}")
        return CurlResult.create_error(
            " ".join(["curl", "-v"] + shlex.split(curl_args)) if curl_args else "",
            f"Failed to execute curl command: {str(e)}",
            1,
            execution_time
        )
    finally:
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()


# Convenience functions for common curl operations
async def curl_get(url: str, headers: List[str] = None, **kwargs) -> CurlResult:
    """Convenience function for GET requests."""
    import shlex
    args = []
    if headers:
        for header in headers:
            args.extend(["-H", header])
    args.append(url)
    return await curl_tool(" ".join(shlex.quote(arg) for arg in args), **kwargs)


async def curl_post(url: str, data: str = None, json_data: str = None, headers: List[str] = None, **kwargs) -> CurlResult:
    """Convenience function for POST requests."""
    import shlex
    args = ["-X", "POST"]
    
    if headers:
        for header in headers:
            args.extend(["-H", header])
    
    if json_data:
        args.extend(["-H", "Content-Type: application/json", "-d", json_data])
    elif data:
        args.extend(["-d", data])
    
    args.append(url)
    return await curl_tool(" ".join(shlex.quote(arg) for arg in args), **kwargs)


async def curl_head(url: str, **kwargs) -> CurlResult:
    """Convenience function for HEAD requests."""
    import shlex
    return await curl_tool(f"-I {shlex.quote(url)}", **kwargs)
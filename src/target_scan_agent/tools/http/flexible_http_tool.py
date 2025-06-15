import asyncio
import httpx
import json
from typing import Optional, Union, Any
import time
from .models import HttpResult


async def flexible_http_tool(
    url: str,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    body: Optional[Union[str, dict[str, Any]]] = None,
    params: Optional[dict[str, str]] = None,
    follow_redirects: bool = True,
    timeout: int = 30,
    include_response_headers: bool = True,
    max_content_length: int = 10000,
    user_agent: str = "SecurityAgent/1.0",
) -> dict:
    """
    Flexible HTTP tool for security testing that returns structured response data for LLM analysis.

    This tool provides comprehensive HTTP request capabilities for penetration testing,
    including support for various attack vectors and security testing scenarios.

    ✅ SECURITY TESTING EXAMPLES:

    Basic vulnerability scanning:
    url="http://target.com/admin", method="GET"

    SQL injection testing:
    url="http://target.com/search", method="POST", body={"query": "1' OR '1'='1"}

    XSS payload testing:
    url="http://target.com/comment", method="POST", body={"comment": "<script>alert('XSS')</script>"}

    Directory traversal:
    url="http://target.com/file", params={"path": "../../../etc/passwd"}

    Authentication bypass:
    headers={"Authorization": "Bearer invalid_token"}

    Header injection testing:
    headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "localhost"}

    Cookie manipulation:
    headers={"Cookie": "session=admin; role=superuser"}

    CSRF testing:
    headers={"Referer": "http://evil.com"}

    Args:
        url: Target URL to request (must start with http:// or https://)
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
        headers: Custom HTTP headers to send (useful for authentication, injection testing)
        body: Request body (string or dict for JSON) - use for payload injection
        params: URL query parameters - use for parameter injection
        follow_redirects: Whether to follow HTTP redirects
        timeout: Request timeout in seconds
        include_response_headers: Whether to include response headers in output
        max_content_length: Maximum response body length to return
        user_agent: User-Agent string (can be customized for evasion)

    Returns:
        dict: Structured response data optimized for LLM analysis and security assessment
    """
    # Validate arguments first
    validation_error = _validate_http_arguments(url, method, timeout)
    if validation_error:
        return HttpResult.create_error(
            url=url,
            method=method,
            error_message=f"Validation Error: {validation_error}",
        ).to_dict()

    # Prepare default headers - LLM can customize user_agent
    default_headers = {
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    # Merge with custom headers
    final_headers = default_headers | (headers or {})

    # Prepare request body
    request_body = None
    match body:
        case dict() as dict_body:
            request_body = json.dumps(dict_body)
            final_headers["Content-Type"] = "application/json"
        case str() as str_body:
            request_body = str_body
        case None:
            request_body = None

    start_time = time.perf_counter()

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=False,  # Allow self-signed certificates for testing
    ) as client:
        try:
            # Make the HTTP request
            response = await client.request(
                method=method.upper(),
                url=url,
                headers=final_headers,
                content=request_body,
                params=params,
            )

            execution_time = time.perf_counter() - start_time

            # Prepare response content (truncated if too long)
            content = response.text or ""
            if len(content) > max_content_length:
                content = (
                    content[:max_content_length]
                    + f"\n... (truncated from {len(response.text)} chars)"
                )

            # Convert headers to dict, only include if requested
            response_headers = (
                dict(response.headers) if include_response_headers else {}
            )

            return HttpResult.create_success(
                url=str(response.url),
                method=method,
                status_code=response.status_code,
                headers=response_headers,
                content=content,
                execution_time=execution_time,
                request_headers=final_headers,
            ).to_dict()

        except httpx.TimeoutException:
            execution_time = time.perf_counter() - start_time
            return HttpResult.create_error(
                url=url,
                method=method,
                error_message=f"Request timed out after {timeout} seconds",
                execution_time=execution_time,
                request_headers=final_headers,
            ).to_dict()
        except httpx.ConnectError as e:
            execution_time = time.perf_counter() - start_time
            return HttpResult.create_error(
                url=url,
                method=method,
                error_message=f"Connection failed: {str(e)}",
                execution_time=execution_time,
                request_headers=final_headers,
            ).to_dict()
        except httpx.HTTPStatusError as e:
            execution_time = time.perf_counter() - start_time
            return HttpResult.create_error(
                url=url,
                method=method,
                error_message=f"HTTP {e.response.status_code} error: {str(e)}",
                execution_time=execution_time,
                request_headers=final_headers,
            ).to_dict()
        except Exception as e:
            execution_time = time.perf_counter() - start_time
            return HttpResult.create_error(
                url=url,
                method=method,
                error_message=f"Unexpected error: {str(e)}",
                execution_time=execution_time,
                request_headers=final_headers,
            ).to_dict()


def _validate_http_arguments(url: str, method: str, timeout: int) -> str | None:
    """
    Validate HTTP tool arguments and return error message if invalid.

    Returns:
        None if valid, error message string if invalid
    """
    VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

    # Validate URL
    if not url or not isinstance(url, str):
        return "'url' must be a non-empty string (e.g., 'http://localhost:8000')"

    if not url.startswith(("http://", "https://")):
        return f"'url' must start with http:// or https://. Got: '{url}'"

    # Validate method
    if not method or not isinstance(method, str):
        return "'method' must be a non-empty string"

    method_upper = method.upper()
    if method_upper not in VALID_METHODS:
        return f"""Invalid HTTP method '{method}'. 

✅ VALID METHODS: {", ".join(sorted(VALID_METHODS))}

📝 EXAMPLES:
- flexible_http_tool(url="http://localhost:8000", method="GET")
- flexible_http_tool(url="http://localhost:8000/login", method="POST")
- flexible_http_tool(url="http://localhost:8000", method="HEAD")"""

    # Validate timeout
    if not isinstance(timeout, int) or timeout <= 0:
        return f"'timeout' must be a positive integer. Got: {timeout}"

    return None  # All validations passed

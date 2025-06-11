import asyncio
import httpx
import json
from typing import Optional, Union, Any
import time


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
) -> str:
    """
    Flexible HTTP tool that returns raw response data for LLM analysis.

    Args:
        url: Target URL to request (must start with http:// or https://)
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
        headers: Custom HTTP headers to send
        body: Request body (string or dict for JSON)
        params: URL query parameters
        follow_redirects: Whether to follow HTTP redirects
        timeout: Request timeout in seconds
        include_response_headers: Whether to include response headers in output
        max_content_length: Maximum response body length to return
        user_agent: User-Agent string

    Returns:
        Raw HTTP response data as text for LLM analysis
    """
    # Validate arguments first
    validation_error = _validate_http_arguments(url, method, timeout)
    if validation_error:
        return f"❌ HTTP TOOL ERROR: {validation_error}"

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

            response_time = round((time.perf_counter() - start_time) * 1000, 2)

            # Build response text for LLM analysis
            result_parts = []

            # Basic request/response info
            result_parts.append(f"HTTP Request: {method.upper()} {response.url}")
            result_parts.append(f"Status Code: {response.status_code}")
            result_parts.append(f"Status Text: {response.reason_phrase}")
            result_parts.append(f"Response Time: {response_time}ms")
            result_parts.append(f"Content Length: {len(response.content)} bytes")

            # Include response headers if requested
            if include_response_headers:
                result_parts.append("\nResponse Headers:")
                for name, value in response.headers.items():
                    result_parts.append(f"{name}: {value}")

            # Include response body (truncated if too long)
            if response.text:
                content = response.text
                if len(content) > max_content_length:
                    content = (
                        content[:max_content_length]
                        + f"\n... (truncated, full length: {len(response.text)} chars)"
                    )

                result_parts.append(f"\nResponse Body:")
                result_parts.append(content)
            else:
                result_parts.append("\nResponse Body: (empty)")

            return "\n".join(result_parts)

        except httpx.TimeoutException:
            return f"Error: Request timed out after {timeout} seconds for {method.upper()} {url}"
        except httpx.ConnectError as e:
            return f"Error: Connection failed to {url} - {str(e)}"
        except httpx.HTTPStatusError as e:
            return f"Error: HTTP {e.response.status_code} - {str(e)}"
        except Exception as e:
            return f"Error: Unexpected error during {method.upper()} {url} - {str(e)}"


def _validate_http_arguments(url: str, method: str, timeout: int) -> str | None:
    """
    Validate HTTP tool arguments and return error message if invalid.
    
    Returns:
        None if valid, error message string if invalid
    """
    VALID_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
    
    # Validate URL
    if not url or not isinstance(url, str):
        return "'url' must be a non-empty string (e.g., 'http://localhost:8000')"
    
    if not url.startswith(('http://', 'https://')):
        return f"'url' must start with http:// or https://. Got: '{url}'"
    
    # Validate method
    if not method or not isinstance(method, str):
        return "'method' must be a non-empty string"
    
    method_upper = method.upper()
    if method_upper not in VALID_METHODS:
        return f"""Invalid HTTP method '{method}'. 

✅ VALID METHODS: {', '.join(sorted(VALID_METHODS))}

📝 EXAMPLES:
- flexible_http_tool(url="http://localhost:8000", method="GET")
- flexible_http_tool(url="http://localhost:8000/login", method="POST")
- flexible_http_tool(url="http://localhost:8000", method="HEAD")"""
    
    # Validate timeout
    if not isinstance(timeout, int) or timeout <= 0:
        return f"'timeout' must be a positive integer. Got: {timeout}"
    
    return None  # All validations passed

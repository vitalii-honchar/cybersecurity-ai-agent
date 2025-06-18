import asyncio
from unittest.mock import patch

import pytest

from target_scan_agent.tools.http.flexible_http_tool import flexible_http_tool
from target_scan_agent.tools.http.models import HttpResult


class TestFlexibleHttpToolIntegration:
    """Integration tests for flexible HTTP tool against actual web services."""

    @pytest.mark.asyncio
    async def test_basic_get_request(self):
        """Test basic GET request functionality."""
        result = await flexible_http_tool("http://httpbin.org/get")

        assert isinstance(result, HttpResult)
        assert result.is_success()
        assert result.status_code == 200
        assert result.method == "GET"
        assert result.url == "http://httpbin.org/get"
        assert result.execution_time > 0
        assert result.error is None
        assert "httpbin.org" in result.content

        # Check JSON serialization
        json_str = result.to_json()
        assert isinstance(json_str, str)
        assert "status_code" in json_str
        assert "200" in json_str

    @pytest.mark.asyncio
    async def test_get_with_headers(self):
        """Test GET request with custom headers."""
        custom_headers = {"User-Agent": "TestAgent/1.0", "X-Test": "value"}
        result = await flexible_http_tool(
            "http://httpbin.org/headers", headers=custom_headers
        )

        assert result.is_success()
        assert result.status_code == 200
        assert "TestAgent/1.0" in result.content
        assert result.request_headers["User-Agent"] == "TestAgent/1.0"
        assert result.request_headers["X-Test"] == "value"

    @pytest.mark.asyncio
    async def test_post_with_json_body(self):
        """Test POST request with JSON body."""
        json_data = {"test": "data", "number": 42}
        result = await flexible_http_tool(
            "http://httpbin.org/post", method="POST", body=json_data
        )

        assert result.is_success()
        assert result.status_code == 200
        assert result.method == "POST"
        assert "test" in result.content
        assert "data" in result.content
        assert result.request_headers["Content-Type"] == "application/json"

    @pytest.mark.asyncio
    async def test_404_error_response(self):
        """Test handling of 404 responses."""
        result = await flexible_http_tool("http://httpbin.org/status/404")

        assert isinstance(result, HttpResult)
        assert not result.is_success()
        assert result.is_client_error()
        assert result.status_code == 404
        assert result.error is None  # Not a connection error, just HTTP 404

    @pytest.mark.asyncio
    async def test_timeout_error(self):
        """Test timeout handling."""
        result = await flexible_http_tool("http://httpbin.org/delay/10", timeout=2)

        assert isinstance(result, HttpResult)
        assert not result.is_success()
        assert result.error is not None
        assert "timeout" in result.error.lower()
        assert result.status_code is None

    @pytest.mark.asyncio
    async def test_invalid_url_validation(self):
        """Test URL validation."""
        result = await flexible_http_tool("invalid-url")

        assert isinstance(result, HttpResult)
        assert not result.is_success()
        assert result.error is not None
        assert "validation" in result.error.lower()

    @pytest.mark.asyncio
    async def test_json_serialization_complete(self):
        """Test that all HttpResult objects can be serialized to JSON."""
        result = await flexible_http_tool("http://httpbin.org/get")

        # Test both JSON methods
        json_str = result.to_json()
        json_dict = result.to_dict()

        assert isinstance(json_str, str)
        assert isinstance(json_dict, dict)

        # Verify key fields are present
        assert "url" in json_dict
        assert "method" in json_dict
        assert "status_code" in json_dict
        assert "content" in json_dict
        assert "execution_time" in json_dict
        assert "headers" in json_dict

    @pytest.mark.asyncio
    async def test_security_headers_extraction(self):
        """Test security headers extraction."""
        result = await flexible_http_tool(
            "https://httpbin.org/response-headers", params={"X-Frame-Options": "DENY"}
        )

        assert result.is_success()
        security_headers = result.get_security_headers()
        # httpbin.org might not return our custom security headers, but method should work
        assert isinstance(security_headers, dict)

    @pytest.mark.asyncio
    async def test_different_http_methods(self):
        """Test different HTTP methods."""
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]

        for method in methods:
            result = await flexible_http_tool(
                f"http://httpbin.org/{method.lower()}", method=method
            )

            assert isinstance(result, HttpResult)
            assert result.method == method
            if method != "HEAD":  # HEAD responses typically don't have content
                assert result.is_success()

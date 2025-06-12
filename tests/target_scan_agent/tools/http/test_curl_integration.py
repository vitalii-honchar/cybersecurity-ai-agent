import pytest
import asyncio
from unittest.mock import patch

from target_scan_agent.tools.http.curl_tool import curl_tool
from target_scan_agent.tools.http.models import CurlResult


class TestCurlToolIntegration:
    """Integration tests for curl tool against actual vulnerable applications."""
    
    @pytest.mark.asyncio
    async def test_basic_get_request(self):
        """Test basic GET request functionality."""
        result = await curl_tool("http://httpbin.org/get")
        
        assert isinstance(result, dict)
        assert result['exit_code'] == 0
        assert result['error'] is None
        assert "httpbin.org" in result['content']
        assert result['execution_time'] > 0
    
    @pytest.mark.asyncio
    async def test_get_with_headers(self):
        """Test GET request with custom headers."""
        result = await curl_tool('-H "User-Agent: TestAgent/1.0" http://httpbin.org/headers')
        
        assert result['exit_code'] == 0
        assert result['error'] is None
        assert "TestAgent/1.0" in result['content']
    
    @pytest.mark.asyncio
    async def test_post_with_json_data(self):
        """Test POST request with JSON data."""
        json_data = '{"test": "data", "number": 123}'
        result = await curl_tool(f'-X POST -H "Content-Type: application/json" -d \'{json_data}\' http://httpbin.org/post')
        
        assert result['exit_code'] == 0
        assert result['error'] is None
        assert "test" in result['content']
        assert "data" in result['content']
        assert "123" in result['content']
    
    @pytest.mark.asyncio
    async def test_authentication(self):
        """Test basic authentication."""
        result = await curl_tool("-u user:passwd http://httpbin.org/basic-auth/user/passwd")
        
        assert result['exit_code'] == 0
        assert result['error'] is None
        assert "authenticated" in result['content']
    
    @pytest.mark.asyncio
    async def test_follow_redirects(self):
        """Test following redirects with -L flag."""
        result = await curl_tool("-L http://httpbin.org/redirect/2")
        
        assert result['exit_code'] == 0
        assert result['error'] is None
        # Should follow redirects and reach the final destination
        assert "httpbin.org/get" in result['content']
    
    @pytest.mark.asyncio
    async def test_head_request(self):
        """Test HEAD request to get only headers."""
        result = await curl_tool("-I http://httpbin.org/get")
        
        assert result['exit_code'] == 0
        assert result['error'] is None
        assert "HTTP/" in result['content']
        assert "Content-Type:" in result['content']
    
    @pytest.mark.asyncio
    async def test_swagger_documentation_retrieval(self):
        """Test retrieving API documentation (Swagger/OpenAPI)."""
        # Using a public API that provides OpenAPI/Swagger docs
        result = await curl_tool("-L -k https://petstore.swagger.io/v2/swagger.json")
        
        assert result['exit_code'] == 0
        assert result['error'] is None
        # Should contain typical Swagger/OpenAPI structure
        assert any(keyword in result['content'].lower() for keyword in ["swagger", "openapi", "paths", "definitions"])
    
    @pytest.mark.asyncio
    async def test_error_handling_invalid_url(self):
        """Test error handling with invalid URL."""
        result = await curl_tool("http://invalid-domain-that-does-not-exist.com")
        
        assert result['exit_code'] != 0
        assert result['error'] is not None
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test timeout handling."""
        # Using httpbin's delay endpoint to test timeout
        result = await curl_tool("http://httpbin.org/delay/5", timeout=2)
        
        assert result['exit_code'] == 124  # Timeout exit code
        assert result['error'] is not None
        assert "timed out" in result['error'].lower()
    
    @pytest.mark.asyncio
    async def test_common_http_methods(self):
        """Test common HTTP methods using curl_tool directly."""
        # Test GET request
        get_result = await curl_tool("http://httpbin.org/get")
        assert get_result['exit_code'] == 0
        assert get_result['error'] is None
        
        # Test POST request with JSON
        post_result = await curl_tool('-X POST -H "Content-Type: application/json" -d \'{"key": "value"}\' http://httpbin.org/post')
        assert post_result['exit_code'] == 0
        assert post_result['error'] is None
        assert "key" in post_result['content']
        
        # Test HEAD request
        head_result = await curl_tool("-I http://httpbin.org/get")
        assert head_result['exit_code'] == 0
        assert head_result['error'] is None
        assert "HTTP/" in head_result['content']
    
    @pytest.mark.asyncio
    async def test_vulnerable_app_testing(self):
        """Test against local vulnerable application scenarios."""
        # Test common vulnerability testing scenarios
        
        # 1. Test for SQL injection detection (using httpbin to simulate)
        sqli_payload = "' OR '1'='1"
        result = await curl_tool(f"-G -d id={sqli_payload} http://httpbin.org/get")
        assert result['exit_code'] == 0
        assert result['error'] is None
        assert sqli_payload in result['content']
        
        # 2. Test directory traversal (using httpbin path endpoint)
        traversal_payload = "../../../etc/passwd"
        result = await curl_tool("http://httpbin.org/status/200")  # Safe endpoint for testing
        assert result['exit_code'] == 0
        assert result['error'] is None
        
        # 3. Test for admin panel discovery simulation
        result = await curl_tool("http://httpbin.org/status/404")  # Simulate not found
        assert result['exit_code'] != 0 or "404" in result['content']
    
    @pytest.mark.asyncio
    async def test_structured_response_format(self):
        """Test that response structure is maintained."""
        result = await curl_tool("http://httpbin.org/get")
        
        # Verify all required fields are present
        assert 'command' in result
        assert 'content' in result
        assert 'exit_code' in result
        assert 'execution_time' in result
        assert 'timestamp' in result
        assert 'error' in result
        
        # Verify command contains curl -v
        assert "curl -v" in result['command']
        
        # Verify content contains verbose output
        assert len(result['content']) > 0
        
        # Test that result is already a dict
        assert isinstance(result, dict)
        assert "command" in result
    
    @pytest.mark.asyncio 
    async def test_no_arguments_error(self):
        """Test error handling when no arguments provided."""
        result = await curl_tool("")
        
        assert result['exit_code'] != 0
        assert result['error'] is not None
        assert "No arguments provided" in result['error']


class TestCurlToolUnit:
    """Unit tests for curl tool with mocked subprocess."""
    
    @pytest.mark.asyncio
    @patch('target_scan_agent.tools.http.curl_tool.subprocess.Popen')
    async def test_successful_execution_mock(self, mock_popen):
        """Test successful curl execution with mocked subprocess."""
        # Setup mock
        mock_process = mock_popen.return_value
        mock_process.communicate.return_value = ("Mock curl output", "")
        mock_process.returncode = 0
        
        result = await curl_tool("http://example.com")
        
        assert result['exit_code'] == 0
        assert result['error'] is None
        assert result['content'] == "Mock curl output"
        assert "curl -v http://example.com" in result['command']
    
    @pytest.mark.asyncio
    @patch('target_scan_agent.tools.http.curl_tool.subprocess.Popen')
    async def test_failed_execution_mock(self, mock_popen):
        """Test failed curl execution with mocked subprocess."""
        # Setup mock for failure
        mock_process = mock_popen.return_value
        mock_process.communicate.return_value = ("Error output", "")
        mock_process.returncode = 1
        
        result = await curl_tool("http://invalid-url")
        
        assert result['exit_code'] == 1
        assert result['error'] is not None
        assert "failed with exit code 1" in result['error']
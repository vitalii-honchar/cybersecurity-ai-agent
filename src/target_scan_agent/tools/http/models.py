from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime


class CurlResult(BaseModel):
    """
    Structured response from curl tool execution.
    Contains the original command and raw output without parsing.
    """
    command: str = Field(description="The original curl command that was executed")
    content: str = Field(description="Raw output from curl execution including headers and response body")
    exit_code: int = Field(description="Exit code from curl command (0 = success)")
    execution_time: float = Field(description="Time taken to execute the command in seconds")
    timestamp: datetime = Field(default_factory=datetime.now, description="When the command was executed")
    error: Optional[str] = Field(default=None, description="Error message if command failed")
    
    @classmethod
    def create_success(cls, command: str, content: str, execution_time: float) -> "CurlResult":
        """Create a successful curl result."""
        return cls(
            command=command,
            content=content,
            exit_code=0,
            execution_time=execution_time
        )
    
    @classmethod
    def create_error(cls, command: str, error_message: str, exit_code: int = 1, execution_time: float = 0.0) -> "CurlResult":
        """Create an error curl result."""
        return cls(
            command=command,
            content="",
            exit_code=exit_code,
            execution_time=execution_time,
            error=error_message
        )
    
    def is_success(self) -> bool:
        """Check if the curl command was successful."""
        return self.exit_code == 0 and self.error is None
    
    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode='json')


class HttpResult(BaseModel):
    """
    Structured response from HTTP request execution.
    Contains parsed HTTP response data for LLM analysis.
    """
    url: str = Field(description="The URL that was requested")
    method: str = Field(description="HTTP method used (GET, POST, etc.)")
    status_code: Optional[int] = Field(default=None, description="HTTP response status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    content: str = Field(default="", description="Response body content")
    content_type: str = Field(default="", description="Content-Type header value")
    content_length: Optional[int] = Field(default=None, description="Content-Length if available")
    execution_time: float = Field(description="Time taken to execute the request in seconds")
    timestamp: datetime = Field(default_factory=datetime.now, description="When the request was executed")
    error: Optional[str] = Field(default=None, description="Error message if request failed")
    request_headers: Dict[str, str] = Field(default_factory=dict, description="Headers sent with the request")
    
    @classmethod
    def create_success(
        cls, 
        url: str, 
        method: str, 
        status_code: int, 
        headers: Dict[str, str], 
        content: str, 
        execution_time: float,
        request_headers: Optional[Dict[str, str]] = None
    ) -> "HttpResult":
        """Create a successful HTTP result."""
        content_type = headers.get('content-type', headers.get('Content-Type', ''))
        content_length = None
        if 'content-length' in headers:
            try:
                content_length = int(headers['content-length'])
            except (ValueError, TypeError):
                pass
        elif 'Content-Length' in headers:
            try:
                content_length = int(headers['Content-Length'])
            except (ValueError, TypeError):
                pass
        
        return cls(
            url=url,
            method=method.upper(),
            status_code=status_code,
            headers=headers,
            content=content,
            content_type=content_type,
            content_length=content_length,
            execution_time=execution_time,
            request_headers=request_headers or {}
        )
    
    @classmethod
    def create_error(
        cls, 
        url: str, 
        method: str, 
        error_message: str, 
        execution_time: float = 0.0,
        request_headers: Optional[Dict[str, str]] = None
    ) -> "HttpResult":
        """Create an error HTTP result."""
        return cls(
            url=url,
            method=method.upper(),
            execution_time=execution_time,
            error=error_message,
            request_headers=request_headers or {}
        )
    
    def is_success(self) -> bool:
        """Check if the HTTP request was successful."""
        return self.error is None and self.status_code is not None and 200 <= self.status_code < 300
    
    def is_client_error(self) -> bool:
        """Check if response is a client error (4xx)."""
        return self.status_code is not None and 400 <= self.status_code < 500
    
    def is_server_error(self) -> bool:
        """Check if response is a server error (5xx)."""
        return self.status_code is not None and 500 <= self.status_code < 600
    
    def is_redirect(self) -> bool:
        """Check if response is a redirect (3xx)."""
        return self.status_code is not None and 300 <= self.status_code < 400
    
    def get_security_headers(self) -> Dict[str, str]:
        """Extract security-related headers."""
        security_headers = {}
        for header, value in self.headers.items():
            header_lower = header.lower()
            if any(sec_header in header_lower for sec_header in [
                'x-frame-options', 'x-content-type-options', 'x-xss-protection',
                'strict-transport-security', 'content-security-policy', 
                'x-permitted-cross-domain-policies', 'referrer-policy'
            ]):
                security_headers[header] = value
        return security_headers
    
    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode='json')
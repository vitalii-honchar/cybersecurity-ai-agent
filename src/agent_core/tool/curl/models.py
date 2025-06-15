from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime


class CurlResult(BaseModel):
    """
    Structured response from curl tool execution.
    Contains the original command and raw output without parsing.
    """

    command: str = Field(description="The original curl command that was executed")
    content: str = Field(
        description="Raw output from curl execution including headers and response body"
    )
    exit_code: int = Field(description="Exit code from curl command (0 = success)")
    execution_time: float = Field(
        description="Time taken to execute the command in seconds"
    )
    timestamp: datetime = Field(
        default_factory=datetime.now, description="When the command was executed"
    )
    error: Optional[str] = Field(
        default=None, description="Error message if command failed"
    )

    @classmethod
    def create_success(
        cls, command: str, content: str, execution_time: float
    ) -> "CurlResult":
        """Create a successful curl result."""
        return cls(
            command=command, content=content, exit_code=0, execution_time=execution_time
        )

    @classmethod
    def create_error(
        cls,
        command: str,
        error_message: str,
        exit_code: int = 1,
        execution_time: float = 0.0,
    ) -> "CurlResult":
        """Create an error curl result."""
        return cls(
            command=command,
            content="",
            exit_code=exit_code,
            execution_time=execution_time,
            error=error_message,
        )

    def is_success(self) -> bool:
        """Check if the curl command was successful."""
        return self.exit_code == 0 and self.error is None

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")
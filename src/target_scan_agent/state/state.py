import operator
from langgraph.graph import MessagesState
from pydantic import BaseModel, Field
from typing import Annotated, Literal
from datetime import timedelta


class Target(BaseModel):
    description: str = Field(description="A description of the target to be scanned.")
    url: str = Field(description="The URL of the target to be scanned.")

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


SeverityLevel = Literal["info", "low", "medium", "high", "critical"]


class TargetScanToolResult(BaseModel):
    result: str = Field(description="The raw result of the tool execution.")
    tool_name: str | None = Field(
        default=None,
        description="The name of the tool that was called",
    )
    tool_arguments: dict | None = Field(
        default=None,
        description="The arguments passed to the tool when it was called",
    )
    tool_call_id: str = Field(
        description="Unique identifier for the tool call to avoid duplicates"
    )

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class TargetScanOutput(BaseModel):
    summary: str | None = Field(
        default=None,
        description="A summary of the scan results, including any vulnerabilities or insights found.",
    )

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class ToolsCalls(BaseModel):
    nuclei_calls_count: int = Field(
        default=0,
        description="Number of nuclei scans performed.",
    )
    nuclei_calls_count_max: int = Field(
        default=3,
        description="Maximum number of nuclei scans allowed.",
    )

    ffuf_calls_count: int = Field(
        default=0,
        description="Number of ffuf directory scans performed.",
    )
    ffuf_calls_count_max: int = Field(
        default=3,
        description="Maximum number of ffuf directory scans allowed.",
    )

    curl_calls_count: int = Field(
        default=0,
        description="Number of curl commands executed.",
    )
    curl_calls_count_max: int = Field(
        default=20,
        description="Maximum number of curl commands allowed.",
    )


class TargetScanState(MessagesState):
    context: str
    target: Target
    tools_calls: ToolsCalls
    timeout: timedelta
    results: Annotated[list[TargetScanToolResult], operator.add]
    summary: str | None
    call_count: int
    max_calls: int  # max recursion calls

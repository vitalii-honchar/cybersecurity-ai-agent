import operator
from langgraph.graph import MessagesState
from pydantic import BaseModel, Field
from typing import Annotated, Literal
from datetime import timedelta
from .tools import Tool, ToolName


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
    limits: dict[ToolName, int] = Field(
        description="A dictionary mapping tool names to their call limits."
    )
    calls: dict[ToolName, int] = Field(
        default={},
        description="A dictionary mapping tool names to the number of times they have been called.",
    )


class TargetScanState(MessagesState):
    target: Target
    tools: list[Tool]
    tools_calls: ToolsCalls
    timeout: timedelta
    results: Annotated[list[TargetScanToolResult], operator.add]
    scan_results: Annotated[list[str], operator.add]
    attack_results: Annotated[list[str], operator.add]
    summary: str | None
    call_count: int
    max_calls: int

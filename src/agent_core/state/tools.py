from datetime import timedelta
from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field

ToolCapability = Literal["scan", "attack"]


class Tool(BaseModel):
    name: str = Field(description="The name of the tool")
    capabilities: List[ToolCapability] = Field(
        description="The capabilities of the tool"
    )
    description: str = Field(description="A description of what the tool does")

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


class Tools(BaseModel):
    tools: List[Tool] = Field(
        description="A list of tools available for the agent to use"
    )

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


class ToolsUsage(BaseModel):
    limits: Dict[str, int] = Field(
        description="A dictionary mapping tool names to their call limits."
    )
    usage: Dict[str, int] = Field(
        default_factory=dict,
        description="A dictionary mapping tool names to the number of times they have been called.",
    )
    tools_timeouts: Dict[str, timedelta] | None = Field(
        default=None,
        description="A dictionary mapping tool names to their timeout durations.",
    )
    default_timeout: timedelta = Field(
        default=timedelta(minutes=5),
        description="The default timeout duration for tools if not specified.",
    )
    default_limit: int = Field(
        default=3,
        description="The default limit for tool calls if not specified in limits.",
    )

    def increment_usage(self, tool_name: str):
        if tool_name not in self.usage:
            self.usage[tool_name] = 0
        self.usage[tool_name] += 1

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

    def is_limit_reached(self, tools: list[str]) -> bool:
        return all([self._is_limit_reached(tool_name) for tool_name in tools])

    def _is_limit_reached(self, tool_name: str) -> bool:
        return self.usage.get(tool_name, 0) >= self._get_limit(tool_name)

    def _get_limit(self, tool_name: str) -> int:
        return self.limits.get(tool_name, self.default_limit)


class ToolResult(BaseModel):
    result: str = Field(description="The raw result of the tool execution.")
    tool_name: str | None = Field(
        default=None,
        description="The name of the tool that was called",
    )
    tool_capabilities: List[ToolCapability] | None = Field(
        default=None,
        description="The capabilities of the tool that was called",
    )
    tool_arguments: Dict[str, Any] | None = Field(
        default=None,
        description="The arguments passed to the tool when it was called",
    )
    tool_call_id: str = Field(
        description="Unique identifier for the tool call to avoid duplicates"
    )

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

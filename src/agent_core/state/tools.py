from pydantic import BaseModel, Field
from datetime import timedelta

ToolType = str
ToolName = str


class Tool(BaseModel):
    name: ToolName = Field(description="The name of the tool")
    type: ToolType = Field(description="The type of the tool")
    description: str = Field(description="A description of what the tool does")

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


class Tools(BaseModel):
    tools: list[Tool] = Field(
        description="A list of tools available for the agent to use"
    )

    def get_tools(self, tool_type: ToolType) -> list[Tool]:
        return [tool for tool in self.tools if tool.type == tool_type]

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


class ToolsUsage(BaseModel):
    limits: dict[ToolName, int] = Field(
        description="A dictionary mapping tool names to their call limits."
    )
    usage: dict[ToolName, int] = Field(
        default_factory=dict,
        description="A dictionary mapping tool names to the number of times they have been called.",
    )
    tools_timeouts: dict[ToolName, timedelta] | None = Field(
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

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

    def is_limit_reached(self, tools: list[ToolName]) -> bool:
        return all([self._is_limit_reached(tool_name) for tool_name in tools])

    def _is_limit_reached(self, tool_name: ToolName) -> bool:
        return self.usage.get(tool_name, 0) >= self._get_limit(tool_name)

    def _get_limit(self, tool_name: ToolName) -> int:
        return self.limits.get(tool_name, self.default_limit)


class ToolResult(BaseModel):
    result: str = Field(description="The raw result of the tool execution.")
    tool_name: ToolName | None = Field(
        default=None,
        description="The name of the tool that was called",
    )
    tool_type: ToolType | None = Field(
        default=None,
        description="The type of the tool that was called",
    )
    tool_arguments: dict | None = Field(
        default=None,
        description="The arguments passed to the tool when it was called",
    )
    tool_call_id: str = Field(
        description="Unique identifier for the tool call to avoid duplicates"
    )

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

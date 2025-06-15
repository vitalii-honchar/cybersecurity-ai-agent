from pydantic import BaseModel, Field

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


class ToolsUsage(BaseModel):
    limits: dict[ToolName, int] = Field(
        description="A dictionary mapping tool names to their call limits."
    )
    usage: dict[ToolName, int] = Field(
        default={},
        description="A dictionary mapping tool names to the number of times they have been called.",
    )

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

    def is_limit_reached(self, tools: list[ToolName]) -> bool:
        return all([self._is_limit_reached(tool_name) for tool_name in tools])

    def _is_limit_reached(self, tool_name: ToolName) -> bool:
        return self.usage.get(tool_name, 0) >= self.limits.get(tool_name, 0)

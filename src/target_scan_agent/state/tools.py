from typing import Literal

from pydantic import BaseModel, Field

ToolType = Literal["scan", "attack"]
ToolName = str


class Tool(BaseModel):
    name: ToolName = Field(description="The name of the tool")
    type: ToolType = Field(description="The type of the tool")
    description: str = Field(description="A description of what the tool does")

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


FfufTool = Tool(
    name="ffuf_directory_scan",
    type="scan",
    description="A tool for performing directory scans using ffuf",
)

CurlTool = Tool(
    name="curl_tool",
    type="attack",
    description="A tool for executing curl commands to interact with web services",
)

FlexibleHttpTool = Tool(
    name="flexible_http_tool",
    type="attack",
    description="A flexible HTTP tool for security testing and penetration testing with structured response data optimized for LLM analysis",
)


def get_scan_tools(tools: list[Tool]) -> list[Tool]:
    return get_tools(tools, "scan")


def get_attack_tools(tools: list[Tool]) -> list[Tool]:
    return get_tools(tools, "attack")


def get_tools(tools: list[Tool], tool_type: ToolType) -> list[Tool]:
    """Get tools by type."""
    return [tool for tool in tools if tool.type == tool_type]

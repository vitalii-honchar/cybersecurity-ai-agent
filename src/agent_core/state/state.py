import operator
from langgraph.graph import MessagesState
from agent_core.state.tools import ToolsUsage, ToolResult, Tools
from pydantic import BaseModel, Field
from typing import Annotated
from agent_core.state.target import Target


class ReActUsage(BaseModel):
    limit: int = Field(
        description="The maximum number of recursion executions for ReAct node."
    )
    usage: int = Field(
        default=0,
        description="The current number of recursion executions for ReAct node.",
    )

    def is_limit_reached(self) -> bool:
        return self.usage >= self.limit

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


class ReActAgentState(MessagesState):
    usage: ReActUsage
    tools_usage: ToolsUsage
    tools: Tools
    results: Annotated[list[ToolResult], operator.add]
    target: Target

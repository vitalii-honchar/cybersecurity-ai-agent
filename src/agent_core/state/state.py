from langgraph.graph import MessagesState
from agent_core.state.tools import ToolsUsage
from pydantic import BaseModel, Field


class ReActUsage(BaseModel):
    limit: int = Field(
        description="The maximum number of recursion executions for ReAct node."
    )
    usage: int = Field(
        default=0,
        description="The current number of recursion executions for ReAct node.",
    )

    tools_usage: ToolsUsage = Field(
        description="The usage limits and counts for tools used in the ReAct node."
    )


class ReActAgentState(MessagesState):
    usage: ReActUsage

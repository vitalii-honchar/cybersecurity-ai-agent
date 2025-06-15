from agent_core.state import (
    ReActAgentState,
    Target,
    ToolType,
)
from langchain_core.runnables import Runnable
from langchain_core.language_models import LanguageModelInput
from langchain_core.messages import SystemMessage, BaseMessage, AIMessage
from target_scan_agent.state import get_tools
from dataclasses import dataclass
from abc import ABC, abstractmethod
import json
import logging

system_prompt = """
You are an agent that should act as specified in escaped content <BEHAVIOR></BEHAVIOR>.

TOOLS AVAILABLE TO USE:
{tools}

TOOLS USAGE LIMITS:
{tools_usage}

TOOLS CALLING LIMITS:
{calling_limits}

PREVIOUS TOOLS EXECUTION RESULTS:
{tools_results}

<BEHAVIOR>
{behavior}
</BEHAVIOR>
"""


class ReActNode[StateT: ReActAgentState](ABC):

    def __init__(self, llm_with_tools: Runnable[LanguageModelInput, BaseMessage]):
        self.llm_with_tools = llm_with_tools

    def __call__(self, state: StateT):
        prompt = system_prompt.format(
            tools=json.dumps(state["tools"].to_dict()),
            tools_usage=json.dumps(state["tools_usage"].to_dict()),
            calling_limits=json.dumps(state["usage"].to_dict()),
            tools_results=json.dumps([r.to_dict() for r in state.get("results", [])]),
            behavior=self.get_system_prompt(state),
        )
        system_message = SystemMessage(prompt)

        res = self.llm_with_tools.invoke([system_message])
        return {"messages": [res]}

    @abstractmethod
    def get_system_prompt(self, state: StateT) -> str:
        pass

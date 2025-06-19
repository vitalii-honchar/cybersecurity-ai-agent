import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from langchain_core.language_models import LanguageModelInput
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage
from langchain_core.runnables import Runnable

from agent_core.state import ReActAgentState
from target_scan_agent.state import get_tools

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

    def __call__(self, state: StateT) -> dict:
        prompt = system_prompt.format(
            tools=json.dumps(state["tools"].to_dict()),
            tools_usage=json.dumps(state["tools_usage"].to_dict()),
            calling_limits=json.dumps(state["usage"].to_dict()),
            tools_results=json.dumps([r.to_dict() for r in state.get("results", [])]),
            behavior=self.get_system_prompt(state),
        )
        system_message = SystemMessage(prompt)

        res = self.llm_with_tools.invoke([system_message])

        logging.debug(
            "[ReActNode] Executed LLM request: state = %s, response = %s", state, res
        )
        return {"messages": [res]}

    @abstractmethod
    def get_system_prompt(self, state: StateT) -> str:
        pass

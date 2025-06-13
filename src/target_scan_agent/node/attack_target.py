from target_scan_agent.state import (
    TargetScanState,
)
from langchain_core.runnables import Runnable
from langchain_core.language_models import LanguageModelInput
from langchain_core.messages import SystemMessage, BaseMessage
from target_scan_agent.state import get_scan_tools
from dataclasses import dataclass
import json

system_prompt = """
You are a cybersecurity penetration testing agent. 
Your mission is to perform a security attack of the target system.

TARGET DETAILS:
- URL: {target}
- Description: {description}

EXECUTION REQUIREMENTS:
- Perform only the attack operations to get the most valuable information about a system.
- Use all available tool calls.
- Document all findings with evidence.

CURRENT TOOL USAGE STATUS:
- Command timeout: {timeout} seconds per tool execution

TOOLS LIMITS:
{tools_calls}

AVAILABLE TOOLS:
{tools}

PREVIOUS TOOL RESULTS (may contains scan tools which are not allowed to be used by you):
{tools_results}
"""


@dataclass
class AttackTargetNode:

    llm_with_tools: Runnable[LanguageModelInput, BaseMessage]

    def __call__(self, state: TargetScanState):
        target = state["target"]
        timeout = state["timeout"]
        tools_calls = state["tools_calls"]
        tools_results = [r.to_dict() for r in state.get("results", [])]
        available_tools = [t.to_dict() for t in get_scan_tools(state["tools"])]

        prompt = system_prompt.format(
            target=target.url,
            description=target.description,
            timeout=timeout,
            tools_calls=json.dumps(tools_calls.calls),
            tools=json.dumps(available_tools),
            tools_results=json.dumps(tools_results),
        )
        system_message = SystemMessage(prompt)
        res = self.llm_with_tools.invoke([system_message])
        return {
            "messages": [res],
        }

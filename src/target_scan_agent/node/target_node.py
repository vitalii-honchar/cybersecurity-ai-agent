import json
import logging
from dataclasses import dataclass

from langchain_core.language_models import LanguageModelInput
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage
from langchain_core.runnables import Runnable

from target_scan_agent.state import (
    TargetScanState,
    Tool,
    ToolType,
    get_tools,
)


@dataclass
class TargetNode:
    llm_with_tools: Runnable[LanguageModelInput, BaseMessage]
    system_prompt: str
    tools_type: ToolType

    def __call__(self, state: TargetScanState):
        target = state["target"]
        timeout = state["timeout"]
        tools_calls = state["tools_calls"]
        available_tools = [
            t.to_dict() for t in get_tools(state["tools"], self.tools_type)
        ]
        scan_results = state.get("scan_results", [])
        attack_results = state.get("attack_results", [])
        tools_results = [r.to_dict() for r in state.get("results", [])]

        context = {
            "available_tools": available_tools,
            "scan_results": scan_results,
            "attack_results": attack_results,
            "tools_results": tools_results,
        }

        prompt = self.system_prompt.format(
            target=target.url,
            description=target.description,
            timeout=timeout.seconds,
            tools_calls=json.dumps(tools_calls.to_dict()),
            context=json.dumps(context),
        )
        system_message = SystemMessage(prompt)

        new_state = {}
        res = self.llm_with_tools.invoke([system_message])

        new_state["messages"] = [res]
        logging.info("TargetNode response: %s", res)
        if isinstance(res, AIMessage) and len(res.tool_calls) == 0:
            if self.tools_type == "attack":
                new_state["attack_results"] = [res.content]
            else:
                new_state["scan_results"] = [res.content]

        return new_state

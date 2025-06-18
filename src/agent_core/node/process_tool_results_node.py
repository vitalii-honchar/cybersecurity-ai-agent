from langchain_core.messages import (
    ToolMessage,
    AnyMessage,
    AIMessage,
)
from agent_core.state import ReActAgentState, ToolResult


class ProcessToolResultsNode[StateT: ReActAgentState]:

    def __call__(self, state: StateT) -> dict:
        messages = state["messages"]
        tools_usage = state["tools_usage"]
        new_results = []

        results = state.get("results", [])

        call_id_to_result = {
            result.tool_call_id: result for result in results if result.tool_call_id
        }

        reversed_messages = list(reversed(messages))
        for msg in reversed_messages:
            if isinstance(msg, ToolMessage):
                if msg.tool_call_id not in call_id_to_result:
                    if msg.name is not None:
                        tools_usage.increment_usage(msg.name)

                    new_results.append(
                        ToolResult(
                            result=str(msg.content),
                            tool_name=msg.name,
                            tool_arguments=self._find_tool_call_args(
                                reversed_messages, msg.tool_call_id
                            ),
                            tool_call_id=msg.tool_call_id,
                        )
                    )

        return {
            "results": list(reversed(new_results)),
            "tools_calls": tools_usage,
        }

    def _find_tool_call_args(
        self, messages: list[AnyMessage], tool_call_id: str
    ) -> dict | None:
        for msg in messages:
            if isinstance(msg, AIMessage):
                for tool_call in msg.tool_calls:
                    if tool_call.get("id") == tool_call_id:
                        return tool_call.get("args")

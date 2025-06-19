from langchain_core.runnables.config import RunnableConfig

from attack_agent.graph import create_attack_graph
from cybersecurity_agent.state import CybersecurityAgentState
from agent_core.state import ReActUsage, Tools, ToolsUsage
from agent_core.tool import CURL_TOOL


class AttackAgentNode:
    def __init__(
        self,
        react_usage_limit: int = 25,
        curl_tool_limit: int = 20,
    ):
        # Create compiled sub-graph as recommended by research assistant pattern
        self.attack_graph = create_attack_graph()
        self.react_usage_limit = react_usage_limit
        self.curl_tool_limit = curl_tool_limit

    async def __call__(self, state: CybersecurityAgentState) -> dict:
        # Create fresh attack agent state with configurable limits
        attack_state = {
            "target": state["target"],
            "scan_summary": state["scan_summary"],
            "usage": ReActUsage(limit=self.react_usage_limit),
            "tools_usage": ToolsUsage(
                limits={
                    CURL_TOOL.name: self.curl_tool_limit,
                }
            ),
            "tools": Tools(tools=[CURL_TOOL]),
        }

        # Execute attack agent with unique thread ID for state isolation
        config = RunnableConfig(
            max_concurrency=10,
            recursion_limit=25,
            configurable={"thread_id": f"attack_{hash(str(state['target']))}"},
        )

        # Use simple synchronous invocation instead of streaming
        final_state = await self.attack_graph.ainvoke(attack_state, config)

        # Extract attack summary from final state
        attack_summary = final_state.get("attack_summary")

        return {"attack_summary": attack_summary}

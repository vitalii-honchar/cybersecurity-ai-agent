from langchain_core.runnables.config import RunnableConfig

from scan_agent.graph import create_scan_graph
from cybersecurity_agent.state import CybersecurityAgentState
from agent_core.state import ReActUsage, Tools, ToolsUsage
from agent_core.tool import CURL_TOOL, FFUF_TOOL


class ScanAgentNode:
    def __init__(
        self,
        react_usage_limit: int = 25,
        ffuf_tool_limit: int = 2,
        curl_tool_limit: int = 5,
    ):
        self.scan_graph = create_scan_graph()
        self.react_usage_limit = react_usage_limit
        self.ffuf_tool_limit = ffuf_tool_limit
        self.curl_tool_limit = curl_tool_limit

    async def __call__(self, state: CybersecurityAgentState) -> dict:
        # Create fresh scan agent state with configurable limits
        scan_state = {
            "target": state["target"],
            "usage": ReActUsage(limit=self.react_usage_limit),
            "tools_usage": ToolsUsage(
                limits={
                    FFUF_TOOL.name: self.ffuf_tool_limit,
                    CURL_TOOL.name: self.curl_tool_limit,
                }
            ),
            "tools": Tools(tools=[FFUF_TOOL, CURL_TOOL]),
        }

        # Execute scan agent with unique thread ID for state isolation
        config = RunnableConfig(
            max_concurrency=10,
            recursion_limit=25,
            configurable={"thread_id": f"scan_{hash(str(state['target']))}"},
        )

        # Use simple synchronous invocation instead of streaming
        final_state = await self.scan_graph.ainvoke(scan_state, config)

        # Extract scan summary from final state
        scan_summary = final_state.get("summary")

        return {"scan_summary": scan_summary}


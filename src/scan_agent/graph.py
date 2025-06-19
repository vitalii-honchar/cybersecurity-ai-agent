from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode

from agent_core.edge import ToolRouterEdge
from agent_core.node import ProcessToolResultsNode
from agent_core.tool import ffuf_directory_scan, curl_tool
from scan_agent.node import ScanNode
from scan_agent.node.summary_node import SummaryNode
from scan_agent.state import ScanAgentState


def create_scan_graph() -> CompiledStateGraph:
    llm = ChatOpenAI(model="gpt-4.1-2025-04-14", temperature=0.3)
    tools = [ffuf_directory_scan, curl_tool]
    llm_with_tools = llm.bind_tools(tools, parallel_tool_calls=True)

    scan_node = ScanNode(llm_with_tools=llm_with_tools)
    summary_node = SummaryNode(llm=llm)
    process_tool_results_node = ProcessToolResultsNode[ScanAgentState]()

    tools_router = ToolRouterEdge[ScanAgentState](
        origin_node="scan_node",
        end_node="summary_node",
        tools_node="scan_tools",
    )

    builder = StateGraph(ScanAgentState)

    builder.add_node("scan_node", scan_node)
    builder.add_node("summary_node", summary_node)
    builder.add_node("scan_tools", ToolNode(tools))
    builder.add_node("process_tool_results_node", process_tool_results_node)

    builder.add_edge(START, "scan_node")
    builder.add_edge("scan_tools", "process_tool_results_node")
    builder.add_edge("process_tool_results_node", "scan_node")
    builder.add_edge("summary_node", END)

    builder.add_conditional_edges("scan_node", tools_router)

    return builder.compile(checkpointer=MemorySaver())

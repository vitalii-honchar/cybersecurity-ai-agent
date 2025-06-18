from langchain_openai import ChatOpenAI
from langgraph.graph import START, StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver
from scan_agent.state import ScanAgentState, ToolTypeScan
from agent_core.edge import ToolRouterEdge
from agent_core.node import ProcessToolResultsNode
from scan_agent.node import ScanNode
from agent_core.tool import ffuf_directory_scan


def create_scan_graph() -> CompiledStateGraph:
    llm = ChatOpenAI(model="gpt-4.1-2025-04-14", temperature=0.3)
    tools = [ffuf_directory_scan]
    llm_with_tools = llm.bind_tools([], parallel_tool_calls=True)

    scan_node = ScanNode(llm_with_tools=llm_with_tools)
    process_tool_results_node = ProcessToolResultsNode[ScanAgentState]()

    tools_router = ToolRouterEdge[ScanAgentState](
        origin_node="scan_node",
        end_node=END,
        tools_node="scan_tools",
    )

    builder = StateGraph(ScanAgentState)

    builder.add_node("scan_node", scan_node)
    builder.add_node("scan_tools", ToolNode(tools))
    builder.add_node("process_tool_results_node", process_tool_results_node)

    builder.add_edge(START, "scan_node")
    builder.add_edge("scan_tools", "process_tool_results_node")
    builder.add_edge("process_tool_results_node", "scan_node")

    builder.add_conditional_edges("scan_node", tools_router)

    return builder.compile(checkpointer=MemorySaver())

from langgraph.graph import START, StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from target_scan_agent.state import TargetScanState
from target_scan_agent.node import (
    AssistantNode,
    ProcessToolResultNode,
    GenerateReportNode,
)
from langchain_openai import ChatOpenAI
from target_scan_agent.tools import (
    flexible_http_tool,
    curl_tool,
    nuclei_scan_tool,
    ffuf_directory_scan,
    nmap_port_scan_tool,
)
from target_scan_agent.edge import ToolRouterEdge
from langchain_core.messages import AIMessage


def track_tool_calls(state: TargetScanState):
    """Track and increment tool call count based on tool messages"""
    # Count ToolMessage instances in the recent messages to track actual tool executions
    from langchain_core.messages import ToolMessage
    
    current_count = state.get("call_count", 0)
    messages = state.get("messages", [])
    
    # Count tool messages (actual tool executions)
    tool_message_count = sum(1 for msg in messages if isinstance(msg, ToolMessage))
    
    return {"call_count": tool_message_count}


def create_graph() -> CompiledStateGraph:
    llm = ChatOpenAI(model="gpt-4o", temperature=0)

    # tools
    tools = [nuclei_scan_tool, ffuf_directory_scan, curl_tool]
    llm_with_tools = llm.bind_tools(tools, parallel_tool_calls=True)

    # nodes init
    assistant_node = AssistantNode(llm_with_tools=llm_with_tools)
    process_tool_result_node = ProcessToolResultNode(llm=llm)
    generate_report_node = GenerateReportNode(llm=llm)

    # edges init
    tool_router = ToolRouterEdge()

    # graph init
    builder = StateGraph(TargetScanState)

    # nodes
    builder.add_node("assistant", assistant_node.assistant)
    builder.add_node("track_calls", track_tool_calls)
    builder.add_node("tools", ToolNode(tools))
    builder.add_node("process_results", process_tool_result_node.process_tool_results)
    builder.add_node("generate_report", generate_report_node.generate_report)

    # edges
    builder.add_edge(START, "assistant")
    builder.add_conditional_edges("assistant", tool_router.route)
    builder.add_edge("tools", "track_calls")
    builder.add_edge("track_calls", "process_results")
    builder.add_edge("process_results", "assistant")
    builder.add_edge("generate_report", END)

    return builder.compile()

from langgraph.graph import START, StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver
from target_scan_agent.state import TargetScanState
from target_scan_agent.node import (
    AssistantNode,
    ProcessToolResultNode,
    GenerateReportNode,
    ScanTargetNode,
    AttackTargetNode,
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


def create_graph() -> CompiledStateGraph:
    llm = ChatOpenAI(model="gpt-4o", temperature=0)

    # tools
    attack_tools = [ffuf_directory_scan, curl_tool]
    scan_tools = [ffuf_directory_scan]

    llm_with_attack_tools = llm.bind_tools(attack_tools, parallel_tool_calls=True)
    llm_with_scan_tools = llm.bind_tools(scan_tools, parallel_tool_calls=True)

    # nodes init
    process_tool_result_node = ProcessToolResultNode(llm=llm)
    generate_report_node = GenerateReportNode(llm=llm)
    scan_target_node = ScanTargetNode(llm_with_tools=llm_with_scan_tools)
    attack_target_node = AttackTargetNode(llm_with_tools=llm_with_attack_tools)

    # edges init
    scan_tools_router = ToolRouterEdge(
        end_node="attack_target_node", tools_node="scan_tools"
    )
    attack_tools_router = ToolRouterEdge(
        end_node="generate_report", tools_node="attack_tools"
    )

    # graph init
    builder = StateGraph(TargetScanState)

    # nodes
    builder.add_node("scan_target_node", scan_target_node)
    builder.add_node("attack_target_node", attack_target_node)
    builder.add_node("scan_tools", ToolNode(scan_tools))
    builder.add_node("attack_tools", ToolNode(attack_tools))
    builder.add_node(
        "process_scan_results", process_tool_result_node.process_tool_results
    )
    builder.add_node(
        "process_attack_results", process_tool_result_node.process_tool_results
    )
    builder.add_node("generate_report", generate_report_node.generate_report)

    # edges
    builder.add_edge(START, "scan_target_node")
    builder.add_conditional_edges("scan_target_node", scan_tools_router)
    builder.add_conditional_edges("attack_target_node", attack_tools_router)

    builder.add_edge("scan_tools", "process_scan_results")
    builder.add_edge("process_scan_results", "scan_target_node")

    builder.add_edge("attack_tools", "process_attack_results")
    builder.add_edge("process_attack_results", "attack_target_node")
    
    builder.add_edge("generate_report", END)

    # Add memory checkpointer for state persistence
    memory = MemorySaver()
    return builder.compile(checkpointer=memory)

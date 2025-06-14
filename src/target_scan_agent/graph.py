from langgraph.graph import START, StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
import asyncio
from concurrent.futures import ThreadPoolExecutor
from langgraph.checkpoint.memory import MemorySaver
from target_scan_agent.state import TargetScanState
from target_scan_agent.node import (
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
from langchain_core.runnables.config import RunnableConfig
from target_scan_agent.edge import ToolRouterEdge
from langchain_core.messages import AIMessage
from typing import Any
from pprint import pprint
import json


def create_graph() -> CompiledStateGraph:
    llm = ChatOpenAI(model="gpt-4o", temperature=0.3)

    # tools
    attack_tools = [ffuf_directory_scan, curl_tool, flexible_http_tool]
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
        origin_node="scan_target_node",
        tools_type="scan",
        end_node="attack_target_node",
        tools_node="scan_tools",
    )
    attack_tools_router = ToolRouterEdge(
        origin_node="attack_target_node",
        tools_type="attack",
        end_node="generate_report",
        tools_node="attack_tools",
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


def extract_event_details(event):
    """Extract detailed information from graph event"""
    details = {}

    for node_or_edge_name, event_data in event.items():
        details["node_or_edge_name"] = node_or_edge_name
        details["event_data"] = event_data

        # Extract message content if available
        if "messages" in event_data:
            messages = event_data["messages"]
            if messages:
                last_message = messages[-1] if isinstance(messages, list) else messages
                details["message_content"] = getattr(
                    last_message, "content", "No content available"
                )

                # Extract tool calling information
                if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                    details["tool_calls"] = []
                    for tool_call in last_message.tool_calls:
                        tool_info = {
                            "tool_name": tool_call.get("name", "Unknown"),
                            "tool_arguments": tool_call.get("args", {}),
                            "tool_call_id": tool_call.get("id", "No ID"),
                        }
                        details["tool_calls"].append(tool_info)
                else:
                    details["tool_calls"] = None
            else:
                details["message_content"] = "No messages available"
                details["tool_calls"] = None
        else:
            details["message_content"] = "No message field in event data"
            details["tool_calls"] = None

        # Extract any state information
        state_info = {}
        for key, value in event_data.items():
            if key != "messages":
                state_info[key] = (
                    str(type(value).__name__) + f" ({len(str(value))} chars)"
                )
        details["state_info"] = state_info

    return details


def print_event_details(event_details):
    """Print event details in a formatted way"""
    print(f"🔍 NODE/EDGE: {event_details['node_or_edge_name']}")
    print(f"📝 MESSAGE CONTENT:")

    # Handle long content by truncating
    content = event_details["message_content"]
    if len(content) > 500:
        content = content[:500] + "... [TRUNCATED]"
    print(f"   {content}")

    print(f"🔧 TOOL CALLING:")
    if event_details["tool_calls"]:
        for i, tool_call in enumerate(event_details["tool_calls"], 1):
            print(f"   Tool {i}:")
            print(f"     Name: {tool_call['tool_name']}")
            print(
                f"     Arguments: {json.dumps(tool_call['tool_arguments'], indent=6)}"
            )
            print(f"     Call ID: {tool_call['tool_call_id']}")
    else:
        print("   No tool calls")

    print(f"📊 CURRENT STATE INFO:")
    for key, value_info in event_details["state_info"].items():
        print(f"   {key}: {value_info}")


async def run_graph(
    graph: CompiledStateGraph, state: dict[str, Any] | None, config: RunnableConfig
) -> dict[str, Any] | Any | None:
    res = None
    """Run the graph with the initial state and print event details."""
    async for event in graph.astream(state, config=config):
        # event_details = extract_event_details(event)
        # print_event_details(event_details)
        pprint(event, indent=2)
        print("-" * 80)
        res = event

    return res

from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from scan_agent.graph import create_scan_graph
from attack_agent.graph import create_attack_graph
from cybersecurity_agent.node import ScanAgentNode, AttackAgentNode, CybersecuritySummaryNode
from cybersecurity_agent.state import CybersecurityAgentState


def create_cybersecurity_graph(
    scan_react_limit: int = 25,
    scan_ffuf_limit: int = 2,
    scan_curl_limit: int = 5,
    attack_react_limit: int = 25,
    attack_curl_limit: int = 10,
) -> CompiledStateGraph:
    llm = ChatOpenAI(model="gpt-4.1-2025-04-14", temperature=0.3)
    
    # Use parameterized wrapper nodes with configurable limits
    scan_agent_node = ScanAgentNode(
        react_usage_limit=scan_react_limit,
        ffuf_tool_limit=scan_ffuf_limit,
        curl_tool_limit=scan_curl_limit,
    )
    attack_agent_node = AttackAgentNode(
        react_usage_limit=attack_react_limit,
        curl_tool_limit=attack_curl_limit,
    )
    cybersecurity_summary_node = CybersecuritySummaryNode(llm=llm)

    # Build the graph
    builder = StateGraph(CybersecurityAgentState)

    # Add nodes that use compiled sub-graphs internally
    builder.add_node("scan_agent", scan_agent_node)
    builder.add_node("attack_agent", attack_agent_node)
    builder.add_node("cybersecurity_summary", cybersecurity_summary_node)

    # Define the workflow: scan -> attack -> summary
    builder.add_edge(START, "scan_agent")
    builder.add_edge("scan_agent", "attack_agent")
    builder.add_edge("attack_agent", "cybersecurity_summary")
    builder.add_edge("cybersecurity_summary", END)

    return builder.compile(checkpointer=MemorySaver())
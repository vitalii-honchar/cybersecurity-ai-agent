from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode

from agent_core.edge import ToolRouterEdge
from agent_core.node import ProcessToolResultsNode
from agent_core.tool import curl_tool
from attack_agent.node import AttackNode
from attack_agent.node.attack_summary_node import AttackSummaryNode
from attack_agent.state import AttackAgentState


def create_attack_graph() -> CompiledStateGraph:
    llm = ChatOpenAI(model="gpt-4.1-2025-04-14", temperature=0.3)
    tools = [curl_tool]
    llm_with_tools = llm.bind_tools(tools, parallel_tool_calls=True)

    attack_node = AttackNode(llm_with_tools=llm_with_tools)
    attack_summary_node = AttackSummaryNode(llm=llm)
    process_tool_results_node = ProcessToolResultsNode[AttackAgentState]()

    tools_router = ToolRouterEdge[AttackAgentState](
        origin_node="attack_node",
        end_node="attack_summary_node",
        tools_node="attack_tools",
    )

    builder = StateGraph(AttackAgentState)

    builder.add_node("attack_node", attack_node)
    builder.add_node("attack_summary_node", attack_summary_node)
    builder.add_node("attack_tools", ToolNode(tools))
    builder.add_node("process_tool_results_node", process_tool_results_node)

    builder.add_edge(START, "attack_node")
    builder.add_edge("attack_tools", "process_tool_results_node")
    builder.add_edge("process_tool_results_node", "attack_node")
    builder.add_edge("attack_summary_node", END)

    builder.add_conditional_edges("attack_node", tools_router)

    return builder.compile(checkpointer=MemorySaver())
import operator
from agent_core.state import ReActAgentState, Target, ToolType


ToolTypeScan = ToolType("scan")


class ScanAgentState(ReActAgentState):
    target: Target

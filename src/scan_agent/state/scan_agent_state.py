import operator
from agent_core.state import ReActAgentState, Target


class ScanAgentState(ReActAgentState):
    target: Target

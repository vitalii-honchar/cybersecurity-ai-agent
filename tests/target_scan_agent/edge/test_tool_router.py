from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage

from target_scan_agent.edge.tool_router import ToolRouterEdge
from target_scan_agent.state import TargetScanState, ToolsCalls


class TestToolRouterEdge:
    """Test tool router edge logic with different scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.router = ToolRouterEdge()

    def test_route_to_tools_when_available(self):
        """Test routing to tools when tools are available and requested."""
        # Create a mock AI message with tool calls
        ai_message = Mock(spec=AIMessage)
        ai_message.tool_calls = [{"name": "nuclei_scan_tool"}]

        # Create state with available tools
        state = {
            "messages": [ai_message],
            "call_count": 5,
            "max_calls": 20,
            "tools_calls": ToolsCalls(
                nuclei_calls_count=1,
                nuclei_calls_count_max=3,
                ffuf_calls_count=0,
                ffuf_calls_count_max=3,
                curl_calls_count=5,
                curl_calls_count_max=20,
            ),
        }

        result = self.router.route(state)
        assert result == "tools"

    def test_route_to_report_when_max_calls_reached(self):
        """Test routing to report when global max_calls is reached."""
        ai_message = Mock(spec=AIMessage)
        ai_message.tool_calls = [{"name": "nuclei_scan_tool"}]

        state = {
            "messages": [ai_message],
            "call_count": 20,
            "max_calls": 20,
            "tools_calls": ToolsCalls(),
        }

        result = self.router.route(state)
        assert result == "generate_report"

    def test_route_to_report_when_all_tools_exhausted(self):
        """Test routing to report when all individual tools have reached limits."""
        ai_message = Mock(spec=AIMessage)
        ai_message.tool_calls = [{"name": "nuclei_scan_tool"}]

        state = {
            "messages": [ai_message],
            "call_count": 10,
            "max_calls": 20,
            "tools_calls": ToolsCalls(
                nuclei_calls_count=3,
                nuclei_calls_count_max=3,
                ffuf_calls_count=3,
                ffuf_calls_count_max=3,
                curl_calls_count=20,
                curl_calls_count_max=20,
            ),
        }

        result = self.router.route(state)
        assert result == "generate_report"

    def test_route_to_report_when_no_tool_calls(self):
        """Test routing to report when LLM doesn't request tool calls."""
        ai_message = Mock(spec=AIMessage)
        ai_message.tool_calls = []  # No tool calls

        state = {
            "messages": [ai_message],
            "call_count": 5,
            "max_calls": 20,
            "tools_calls": ToolsCalls(),
        }

        result = self.router.route(state)
        assert result == "generate_report"

    def test_has_tools_available_true(self):
        """Test has_tools_available returns True when tools are available."""
        state = {
            "call_count": 5,
            "max_calls": 20,
            "tools_calls": ToolsCalls(
                nuclei_calls_count=1,
                nuclei_calls_count_max=3,
                ffuf_calls_count=0,
                ffuf_calls_count_max=3,
                curl_calls_count=5,
                curl_calls_count_max=20,
            ),
        }

        result = self.router.has_tools_available(state)
        assert result is True

    def test_has_tools_available_false_global_limit(self):
        """Test has_tools_available returns False when global limit reached."""
        state = {"call_count": 20, "max_calls": 20, "tools_calls": ToolsCalls()}

        result = self.router.has_tools_available(state)
        assert result is False

    def test_has_tools_available_false_all_tools_exhausted(self):
        """Test has_tools_available returns False when all tools exhausted."""
        state = {
            "call_count": 10,
            "max_calls": 20,
            "tools_calls": ToolsCalls(
                nuclei_calls_count=3,
                nuclei_calls_count_max=3,
                ffuf_calls_count=3,
                ffuf_calls_count_max=3,
                curl_calls_count=20,
                curl_calls_count_max=20,
            ),
        }

        result = self.router.has_tools_available(state)
        assert result is False

    def test_partial_tool_availability(self):
        """Test behavior when some tools are exhausted but others available."""
        ai_message = Mock(spec=AIMessage)
        ai_message.tool_calls = [{"name": "curl_tool"}]  # Only curl requested

        state = {
            "messages": [ai_message],
            "call_count": 10,
            "max_calls": 20,
            "tools_calls": ToolsCalls(
                nuclei_calls_count=3,  # Nuclei exhausted
                nuclei_calls_count_max=3,
                ffuf_calls_count=3,  # Ffuf exhausted
                ffuf_calls_count_max=3,
                curl_calls_count=10,  # Curl still available
                curl_calls_count_max=20,
            ),
        }

        # Should still route to tools since curl is available and requested
        result = self.router.route(state)
        assert result == "tools"

    def test_proper_state_initialization(self):
        """Test behavior with properly initialized state (as provided by assistant)."""
        ai_message = Mock(spec=AIMessage)
        ai_message.tool_calls = [{"name": "nuclei_scan_tool"}]

        state = {
            "messages": [ai_message],
            "call_count": 5,
            "max_calls": 20,
            "tools_calls": ToolsCalls(),  # Assistant always provides this
        }

        result = self.router.route(state)
        assert result == "tools"  # Should work with fresh ToolsCalls

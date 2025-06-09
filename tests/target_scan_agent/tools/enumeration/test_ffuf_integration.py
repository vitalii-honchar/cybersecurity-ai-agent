import pytest
import subprocess
from src.target_scan_agent.tools.enumeration.ffuf import ffuf_directory_scan
from src.target_scan_agent.tools.enumeration.models import FfufScanResult


class TestFfufIntegration:
    """Integration tests for ffuf_directory_scan against local vulnerable FastAPI app."""

    def is_ffuf_available(self):
        """Check if ffuf binary is available."""
        try:
            result = subprocess.run(
                ["ffuf", "-h"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def validate_ffuf_scan_result(self, result: FfufScanResult):
        """Validate ffuf scan result structure."""
        assert isinstance(result, FfufScanResult)
        
        if result.error:
            print(f"Scan error: {result.error}")
            return True
            
        print(f"Scan completed: {result.scan_completed}")
        print(f"Target: {result.target}")
        print(f"Wordlist: {result.wordlist_type} ({result.wordlist_size:,} entries)")
        print(f"Extensions: {result.extensions}")
        print(f"Total findings: {result.count}")
        
        if result.scan_duration:
            print(f"Scan duration: {result.scan_duration:.2f} seconds")

        if not result.has_findings():
            print("No findings detected")
            return True

        # Test helper methods
        accessible_findings = result.get_accessible_findings()
        forbidden_findings = result.get_forbidden_findings()
        interesting_findings = result.get_interesting_findings()
        status_summary = result.get_status_summary()
        
        print(f"Accessible findings (200): {len(accessible_findings)}")
        print(f"Forbidden findings (403): {len(forbidden_findings)}")
        print(f"Interesting findings: {len(interesting_findings)}")
        print(f"Status summary: {status_summary}")
        
        # Display findings by category
        for i, finding in enumerate(result.findings[:5], 1):  # Show first 5
            print(f"Finding {i}: {finding.url}")
            print(f"  Status: {finding.status}")
            print(f"  Size: {finding.size_formatted}")
            print(f"  Interesting: {finding.is_interesting}")
            print(f"  Accessible: {finding.is_accessible}")
            
        if result.count > 5:
            print(f"... and {result.count - 5} more findings")
            
        # Test specific helper methods
        admin_panels = result.get_admin_panels()
        config_files = result.get_potential_config_files()
        largest_findings = result.get_largest_findings(3)
        
        if admin_panels:
            print(f"Potential admin panels: {len(admin_panels)}")
            for panel in admin_panels:
                print(f"  - {panel.url}")
                
        if config_files:
            print(f"Potential config files: {len(config_files)}")
            for config in config_files:
                print(f"  - {config.url}")
                
        if largest_findings:
            print(f"Largest responses:")
            for finding in largest_findings:
                print(f"  - {finding.url} ({finding.size_formatted})")
        
        return True

    @pytest.mark.integration
    async def test_ffuf_scan_vulnerable_app(self, fastapi_server):
        """Happy case test: Scan vulnerable FastAPI app with ffuf."""
        if not self.is_ffuf_available():
            pytest.skip("ffuf not available")

        print(f"\n🎯 Testing ffuf scan against vulnerable app at: {fastapi_server}")

        # Run ffuf scan against our vulnerable FastAPI app with small wordlist
        result = await ffuf_directory_scan(
            target=fastapi_server, 
            wordlist_type="common",  # Use common wordlist for faster testing
            extensions="html,json,txt"  # Limited extensions for faster scan
        )

        print(f"\n📊 ffuf scan results:")
        print("=" * 50)

        # Basic validation
        assert isinstance(result, FfufScanResult)

        # Validate and display results
        self.validate_ffuf_scan_result(result)

        # Validate result structure
        assert result.target == fastapi_server
        assert result.wordlist_type == "common"
        assert result.extensions == "html,json,txt"
        assert isinstance(result.count, int)
        assert isinstance(result.scan_completed, bool)
        
        # Test that helper methods work without errors
        _ = result.get_status_summary()
        _ = result.get_interesting_findings()
        _ = result.get_accessible_findings()
        _ = result.has_findings()

        print("=" * 50)
        print("✅ Test completed successfully!")

    @pytest.mark.integration
    async def test_ffuf_scan_nonexistent_wordlist(self):
        """Test error handling for non-existent wordlist."""
        if not self.is_ffuf_available():
            pytest.skip("ffuf not available")

        print(f"\n🎯 Testing ffuf with invalid wordlist...")

        result = await ffuf_directory_scan(
            target="http://example.com",
            wordlist_type="nonexistent",
            extensions="php"
        )

        print(f"\n📊 ffuf error handling:")
        print("=" * 50)

        # Should return error result
        assert isinstance(result, FfufScanResult)
        assert result.error is not None
        assert "not found" in result.error.lower()
        assert result.count == 0
        assert len(result.findings) == 0
        assert result.scan_completed == False

        print(f"Error message: {result.error}")
        print("=" * 50)
        print("✅ Error handling test completed successfully!")

    @pytest.mark.integration 
    def test_ffuf_result_model_properties(self):
        """Test that Pydantic models work correctly with sample data."""
        from src.target_scan_agent.tools.enumeration.models import FfufFinding, FfufScanResult
        
        # Test FfufFinding model
        finding_data = {
            "url": "http://example.com/admin",
            "status": 200,
            "length": 1234,
            "words": 56,
            "lines": 78,
            "content-type": "text/html",
            "redirectlocation": ""
        }
        
        finding = FfufFinding.model_validate(finding_data)
        assert finding.url == "http://example.com/admin"
        assert finding.status == 200
        assert finding.is_accessible == True
        assert finding.is_interesting == True
        assert finding.is_forbidden == False
        assert "1.2 KB" in finding.size_formatted
        
        # Test FfufScanResult model
        result = FfufScanResult(
            findings=[finding],
            count=1,
            target="http://example.com",
            wordlist_type="common",
            wordlist_size=4681,
            extensions="php,html"
        )
        
        assert result.has_findings() == True
        assert len(result.get_accessible_findings()) == 1
        assert len(result.get_forbidden_findings()) == 0
        assert result.get_status_summary() == {200: 1}
        
        print("✅ Pydantic model validation test completed successfully!")
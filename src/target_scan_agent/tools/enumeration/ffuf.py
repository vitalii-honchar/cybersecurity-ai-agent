# src/target_scan_agent/tools/enumeration/ffuf.py
"""
FFUF directory enumeration tool with inline wordlist management
"""

import subprocess
import json
import tempfile
import os
from pathlib import Path
from typing import Optional


def _get_wordlist_path(wordlist_type: str) -> Optional[str]:
    """Get path to wordlist. Simple lookup with no complex logic."""

    # Find wordlists directory
    possible_paths = [
        Path.cwd() / "wordlists",
        Path(__file__).parent.parent.parent.parent.parent / "wordlists",
        Path.home() / "wordlists",
    ]

    wordlist_base = None
    for path in possible_paths:
        if path.exists():
            wordlist_base = path
            break

    if not wordlist_base:
        return None

    # Simple wordlist mapping - only 3 essential lists
    wordlist_files = {"common": "common.txt", "medium": "medium.txt", "big": "big.txt"}

    wordlist_file = wordlist_files.get(wordlist_type)
    if not wordlist_file:
        return None

    full_path = wordlist_base / wordlist_file
    return str(full_path) if full_path.exists() else None


def ffuf_directory_scan(
    target: str, wordlist_type: str = "common", extensions: str = "php,html,js,txt"
) -> str:
    """
    Fast web directory discovery using ffuf with 3 proven wordlists.

    Discovers hidden directories, files, and endpoints on web applications using
    SecLists wordlists optimized for different coverage levels.

    Args:
        target: Target URL to scan (e.g., "http://localhost:8000").
            Must include protocol (http/https). No trailing slash needed.
        wordlist_type: Choose scanning coverage level - "common", "medium", or "big".
            "common" (4,681 entries, 3-5 minutes) - RECOMMENDED START.
            Standard comprehensive directory discovery using SecLists common.txt.
            "medium" (220,546 entries, 20-30 minutes) - deeper coverage.
            Very thorough directory discovery using SecLists medium list.
            "big" (1,273,833 entries, 60+ minutes) - exhaustive scan.
            Maximum coverage using SecLists big list for comprehensive testing.
        extensions: File extensions to test, comma-separated. Examples: "php,html,js,txt", "json,xml,config", "bak,old". Use empty string to scan directories only.

    Usage Strategy:
        1. Start with "common" (5m) - catches 90% of findable content
        2. If results found, try "medium" (30m) for deeper coverage
        3. Use "big" (60m+) only for comprehensive final scans

    Performance Guide:
        - common: ~5 minutes, finds most important content
        - medium: ~30 minutes, comprehensive coverage
        - big: ~60+ minutes, exhaustive brute force

    What This Finds:
        - Admin panels: /admin, /dashboard, /panel, /wp-admin
        - APIs: /api, /api/v1, /graphql, /swagger, /rest
        - Config files: config.php, .env, web.config, settings.json
        - Debug endpoints: /debug, /admin/debug, phpinfo.php
        - Sensitive files: robots.txt, sitemap.xml, backup files
        - Hidden directories: /backup, /test, /dev, /staging

    Example Results:
        http://localhost:8000/admin [200] 1,234 bytes
        http://localhost:8000/api [403] 567 bytes (Forbidden - exists!)
        http://localhost:8000/config.php [200] 890 bytes

    Returns:
        Formatted results showing discovered endpoints with status codes and sizes.
    """
    try:
        # Get wordlist path
        wordlist_path = _get_wordlist_path(wordlist_type)
        if not wordlist_path:
            return f"""❌ Wordlist '{wordlist_type}' not found!

Available options: common, medium, big

💡 Make sure wordlists are installed in ./wordlists/ directory
   Run: ./install_wordlists.sh
   
Try: wordlist_type="common" (recommended)"""

        # Get wordlist size for user info
        try:
            with open(wordlist_path, "r") as f:
                wordlist_size = sum(1 for line in f if line.strip())
        except:
            wordlist_size = 0

        # Create temp output file
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as f:
            output_file = f.name

        # Build ffuf command
        cmd = [
            "ffuf",
            "-w",
            wordlist_path,
            "-u",
            f"{target.rstrip('/')}/FUZZ",
            "-o",
            output_file,
            "-of",
            "json",
            "-c",  # Colorize
            "-t",
            "50",  # Threads
            "-timeout",
            "10",
            "-mc",
            "200,201,204,301,302,307,401,403,500",  # Match interesting codes
            "-fs",
            "0",  # Filter zero size
            "-ac",  # Auto-calibrate
        ]

        # Add extensions if provided
        if extensions.strip():
            cmd.extend(["-e", extensions])

        # Set timeout based on wordlist size
        if wordlist_size < 10000:
            timeout = 300  # 5 minutes
        elif wordlist_size < 300000:
            timeout = 1800  # 30 minutes
        else:
            timeout = 3600  # 60 minutes

        # Run ffuf scan
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        # Parse results
        findings = []
        if os.path.exists(output_file):
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings = data.get("results", [])
                os.unlink(output_file)
            except Exception as e:
                return f"❌ ffuf scan completed but failed to parse results: {str(e)}"

        # Handle no results
        if not findings:
            time_estimates = {
                "common": "3-5 minutes",
                "medium": "20-30 minutes",
                "big": "60+ minutes",
            }
            return f"""ffuf scan found no accessible endpoints.

🎯 Scan completed:
   Target: {target}
   Wordlist: {wordlist_type} ({wordlist_size:,} entries, {time_estimates.get(wordlist_type, 'unknown')})
   Extensions: {extensions if extensions else 'directories only'}

💡 Next steps:
   - Try different wordlist: "medium" for more coverage
   - Test different extensions: "json,xml,config" or "bak,old,tmp"
   - Check target accessibility: curl {target}/
   - Use nuclei_scan_tool for vulnerability testing
   - Try manual endpoint testing with flexible_http_tool"""

        # Format results
        output = [
            f"🔍 FFUF Directory Discovery Results",
            f"🎯 Target: {target}",
            f"📋 Wordlist: {wordlist_type} ({wordlist_size:,} entries)",
            f"🔧 Extensions: {extensions if extensions else 'directories only'}",
            "=" * 70,
        ]

        # Group by status code
        status_groups = {}
        for finding in findings:
            status = finding.get("status")
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(finding)

        # Show results by priority (most important first)
        priority_statuses = [200, 201, 204, 403, 401, 500, 302, 301, 307]
        for status in priority_statuses:
            if status in status_groups:
                items = status_groups[status]
                output.append(f"\n📊 HTTP {status} ({len(items)} found):")

                for item in items[:10]:  # Show max 10 per status
                    url = item.get("url", "")
                    length = item.get("length", 0)
                    size_str = f"{length:,} bytes" if length else "unknown size"

                    # Add helpful context for status codes
                    context = ""
                    if status == 403:
                        context = " (Forbidden - exists but access denied!)"
                    elif status == 401:
                        context = " (Authentication required)"
                    elif status == 500:
                        context = " (Server error - potential vulnerability!)"
                    elif status in [301, 302, 307]:
                        context = " (Redirect - follow up manually)"

                    output.append(f"  ✅ {url} - {size_str}{context}")

                if len(items) > 10:
                    output.append(
                        f"  ... and {len(items) - 10} more {status} responses"
                    )

        # Summary and next steps
        total_findings = len(findings)
        interesting_findings = [
            f for f in findings if f.get("status") in [200, 403, 401, 500]
        ]

        output.append(f"\n💡 Summary: {total_findings} endpoints discovered")

        if interesting_findings:
            output.append("🎯 Recommended next steps:")
            output.append("  1. Test discovered endpoints with nuclei_scan_tool")
            output.append(
                "  2. Manual inspection of 200/500 responses for sensitive data"
            )
            output.append(
                "  3. Use api_endpoint_tester for SQL injection and XSS testing"
            )

            if any(f.get("status") == 403 for f in findings):
                output.append(
                    "  4. 403 Forbidden endpoints may have bypass opportunities"
                )

            if wordlist_type == "common" and len(interesting_findings) > 0:
                output.append(
                    f"  5. Consider running wordlist_type='medium' for deeper coverage"
                )

        return "\n".join(output)

    except subprocess.TimeoutExpired:
        time_estimates = {
            "common": "5 minutes",
            "medium": "30 minutes",
            "big": "60+ minutes",
        }
        return f"⏱️ ffuf scan timed out after {time_estimates.get(wordlist_type, 'unknown time')}. This is normal for '{wordlist_type}' wordlist."
    except FileNotFoundError:
        return """❌ ffuf not found. Install with:
        
Ubuntu/Debian: sudo apt install ffuf
Go install: go install github.com/ffuf/ffuf/v2@latest
Kali Linux: apt install ffuf"""
    except Exception as e:
        return f"❌ ffuf scan failed: {str(e)}"

#!/usr/bin/env python3
"""
SHADOW Vulnerability Scanner - Intelligent routing wrapper.

Routing:
1. Run nuclei (if available) for broad template-based scanning
2. Run Python phase3 modules for deep testing
3. Merge findings by severity

Usage (CLI):
    python C_scan_vulns.py -t https://example.com -o results/
    python C_scan_vulns.py -t https://example.com --severity critical,high

Usage (importable):
    from C_wrappers.C_scan_vulns import VulnScanner
    scanner = VulnScanner(target="https://example.com")
    result = await scanner.run()
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils import setup_logging, normalize_url, timestamp_now, ensure_dir
from C_wrappers.C_tool_router import ToolRouter, UnifiedResult

logger = setup_logging("scan_vulns")


class VulnScanner:
    """
    Intelligent vulnerability scanning with nuclei + Python deep testing.

    Nuclei: Broad template-based scanning (CVEs, misconfigs, exposures)
    Python: Deep-dive per-vulnerability-class testing
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        severity: str = "critical,high,medium",
        templates: Optional[str] = None,
        deep: bool = False,
        timeout: int = 900,
        rate_limit: int = 150,
        proxy: Optional[str] = None,
        cookie: Optional[str] = None,
    ):
        self.target = normalize_url(target)
        self.output_dir = Path(output_dir)
        self.severity = severity
        self.templates = templates
        self.deep = deep
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.cookie = cookie
        self.router = ToolRouter()

    async def run(self) -> UnifiedResult:
        """Run vulnerability scanning with nuclei + Python modules."""
        logger.info(f"Starting vulnerability scan for: {self.target}")
        result = UnifiedResult(tool_used="vuln_scanner", target=self.target)
        all_findings: List[Dict[str, Any]] = []
        tools_used = []

        # 1. Run nuclei (PRIMARY for broad scanning)
        if self.router.is_available("nuclei"):
            nuclei_findings = await self._run_nuclei()
            all_findings.extend(nuclei_findings)
            tools_used.append(f"nuclei ({len(nuclei_findings)} findings)")
            logger.info(f"nuclei found {len(nuclei_findings)} issues")

        # 2. Run nikto supplement (if deep mode)
        if self.deep and self.router.is_available("nikto"):
            nikto_findings = await self._run_nikto()
            all_findings.extend(nikto_findings)
            tools_used.append(f"nikto ({len(nikto_findings)} findings)")

        # 3. Run Python phase3 modules for deep testing
        python_findings = await self._run_python_modules()
        all_findings.extend(python_findings)
        if python_findings:
            tools_used.append(f"python_phase3 ({len(python_findings)} findings)")

        # Deduplicate and sort by severity
        deduped = self._deduplicate_findings(all_findings)
        sorted_findings = self._sort_by_severity(deduped)

        result.findings = sorted_findings
        result.tool_used = " + ".join(tools_used) if tools_used else "none"
        result.parsed_data = {
            "total_findings": len(sorted_findings),
            "tools_used": tools_used,
            "severity_breakdown": self._severity_breakdown(sorted_findings),
        }

        logger.info(f"Total findings: {len(sorted_findings)}")
        return result

    async def _run_nuclei(self) -> List[Dict[str, Any]]:
        """Run nuclei template-based scanning."""
        args = [
            "-u", self.target,
            "-severity", self.severity,
            "-json",
            "-silent",
            "-rate-limit", str(self.rate_limit),
        ]

        if self.templates:
            args += ["-t", self.templates]

        if self.proxy:
            args += ["-proxy", self.proxy]

        if self.cookie:
            args += ["-header", f"Cookie: {self.cookie}"]

        tool_result = await self.router.run_tool(
            "nuclei", args, target=self.target, timeout=self.timeout
        )

        if not tool_result.raw_output:
            return []

        # Parse nuclei JSONL output
        parsed = ToolRouter.parse_nuclei_jsonl(tool_result.raw_output)

        findings = []
        for item in parsed:
            findings.append({
                "title": item.get("name", "Unknown"),
                "severity": item.get("severity", "info"),
                "url": item.get("url", self.target),
                "description": item.get("description", ""),
                "template_id": item.get("template_id", ""),
                "matched_at": item.get("matched_at", ""),
                "tags": item.get("tags", []),
                "reference": item.get("reference", []),
                "tool": "nuclei",
            })

        return findings

    async def _run_nikto(self) -> List[Dict[str, Any]]:
        """Run nikto for server misconfiguration scanning."""
        args = [
            "-h", self.target,
            "-Format", "json",
            "-nointeractive",
        ]

        if self.proxy:
            args += ["-useproxy", self.proxy]

        tool_result = await self.router.run_tool(
            "nikto", args, target=self.target, timeout=self.timeout
        )

        findings = []
        if tool_result.raw_output:
            try:
                data = json.loads(tool_result.raw_output)
                for vuln in data.get("vulnerabilities", []):
                    findings.append({
                        "title": vuln.get("msg", "Nikto Finding"),
                        "severity": "medium",
                        "url": vuln.get("url", self.target),
                        "description": vuln.get("msg", ""),
                        "osvdb_id": vuln.get("OSVDB", ""),
                        "tool": "nikto",
                    })
            except json.JSONDecodeError:
                # Parse text output
                for line in tool_result.raw_output.strip().splitlines():
                    if "+ " in line and "OSVDB" in line:
                        findings.append({
                            "title": line.strip(),
                            "severity": "info",
                            "url": self.target,
                            "tool": "nikto",
                        })

        return findings

    async def _run_python_modules(self) -> List[Dict[str, Any]]:
        """Run Python phase3 testing modules for deep vulnerability testing."""
        findings = []

        # List of Python-only testers to run
        modules = [
            ("phase3_testing.injection.ssti_tester", "SSTITester"),
            ("phase3_testing.injection.xxe_tester", "XXETester"),
            ("phase3_testing.ssrf_tester", "SSRFTester"),
            ("phase3_testing.csrf_tester", "CSRFTester"),
        ]

        if self.deep:
            modules.extend([
                ("phase3_testing.injection.command_injection", "CommandInjectionTester"),
                ("phase3_testing.file_upload", "FileUploadTester"),
                ("phase3_testing.business_logic", "BusinessLogicTester"),
            ])

        for module_path, class_name in modules:
            try:
                module = __import__(module_path, fromlist=[class_name])
                tester_class = getattr(module, class_name)

                # Filter init params
                import inspect
                sig = inspect.signature(tester_class.__init__)
                valid_params = set(sig.parameters.keys()) - {"self"}
                kwargs = {}
                if "target" in valid_params:
                    kwargs["target"] = self.target
                if "output_dir" in valid_params:
                    kwargs["output_dir"] = str(self.output_dir)
                if "proxy" in valid_params and self.proxy:
                    kwargs["proxy"] = self.proxy

                tester = tester_class(**kwargs)

                # Run tester
                scan_result = None
                for method_name in ["test", "scan", "run"]:
                    if hasattr(tester, method_name):
                        scan_result = await getattr(tester, method_name)()
                        break

                if scan_result and hasattr(scan_result, "findings"):
                    for finding in scan_result.findings:
                        fd = finding.to_dict() if hasattr(finding, "to_dict") else {}
                        fd["tool"] = f"python_{class_name}"
                        findings.append(fd)

                logger.debug(f"Python module {class_name}: {len(scan_result.findings) if scan_result and hasattr(scan_result, 'findings') else 0} findings")

            except Exception as e:
                logger.debug(f"Python module {class_name} failed: {e}")

        return findings

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings by URL + title."""
        seen = set()
        deduped = []
        for f in findings:
            key = (f.get("url", ""), f.get("title", ""), f.get("parameter", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def _sort_by_severity(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by severity (critical -> info)."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5),
        )

    def _severity_breakdown(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings per severity level."""
        breakdown: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in breakdown:
                breakdown[sev] += 1
        return breakdown


async def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Vulnerability Scanner - nuclei + Python deep testing",
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--severity", default="critical,high,medium",
                        help="Severity filter (comma-separated)")
    parser.add_argument("--templates", help="Nuclei template path/tag")
    parser.add_argument("--deep", action="store_true", help="Deep scan with all Python modules")
    parser.add_argument("--rate-limit", type=int, default=150, help="Nuclei rate limit")
    parser.add_argument("--timeout", type=int, default=900, help="Timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    ensure_dir(args.output)

    scanner = VulnScanner(
        target=args.target,
        output_dir=args.output,
        severity=args.severity,
        templates=args.templates,
        deep=args.deep,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        proxy=args.proxy,
        cookie=args.cookie,
    )

    result = await scanner.run()

    if args.json:
        print(result.to_json())
    else:
        breakdown = result.parsed_data.get("severity_breakdown", {})
        print(f"\nVulnerability Scan: {len(result.findings)} findings")
        print(f"Tool used: {result.tool_used}")
        print(f"Breakdown: C={breakdown.get('critical',0)} H={breakdown.get('high',0)} "
              f"M={breakdown.get('medium',0)} L={breakdown.get('low',0)} I={breakdown.get('info',0)}\n")
        for finding in result.findings[:30]:
            sev = finding.get("severity", "?").upper()
            title = finding.get("title", "Unknown")
            url = finding.get("url", "")
            tool = finding.get("tool", "")
            print(f"  [{sev}] {title} ({tool})")
            print(f"         {url}")


if __name__ == "__main__":
    asyncio.run(main())

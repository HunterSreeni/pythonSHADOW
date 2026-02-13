#!/usr/bin/env python3
"""
SHADOW XSS Tester - Intelligent routing wrapper.

Routing:
1. Primary: Python xss_tester.py (context-aware, filter bypass)
2. Supplement: nuclei XSS templates
3. Combine results

Usage (CLI):
    python C_test_xss.py -t "https://example.com/search?q=test" -o results/

Usage (importable):
    from C_wrappers.C_test_xss import XSSWrapper
    tester = XSSWrapper(target="https://example.com/search?q=test")
    result = await tester.run()
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils import setup_logging, normalize_url, timestamp_now, ensure_dir
from C_wrappers.C_tool_router import ToolRouter, UnifiedResult

logger = setup_logging("test_xss")


class XSSWrapper:
    """
    Intelligent XSS testing with Python context-aware engine + nuclei templates.

    Python xss_tester.py is PRIMARY (context detection, encoding mutations).
    nuclei XSS templates supplement with known pattern matching.
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        timeout: int = 300,
        proxy: Optional[str] = None,
        cookie: Optional[str] = None,
        use_nuclei: bool = True,
    ):
        self.target = normalize_url(target)
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.proxy = proxy
        self.cookie = cookie
        self.use_nuclei = use_nuclei
        self.router = ToolRouter()

    async def run(self) -> UnifiedResult:
        """Run XSS testing with Python + nuclei."""
        logger.info(f"Starting XSS testing for: {self.target}")
        result = UnifiedResult(tool_used="xss_wrapper", target=self.target)
        all_findings: List[Dict[str, Any]] = []
        tools_used = []

        # 1. PRIMARY: Python xss_tester.py
        python_findings = await self._run_python_xss()
        all_findings.extend(python_findings)
        tools_used.append(f"python_xss_tester ({len(python_findings)} findings)")

        # 2. SUPPLEMENT: nuclei XSS templates
        if self.use_nuclei and self.router.is_available("nuclei"):
            nuclei_findings = await self._run_nuclei_xss()
            # Only add new findings not already found by Python
            new_nuclei = self._filter_duplicates(nuclei_findings, python_findings)
            all_findings.extend(new_nuclei)
            tools_used.append(f"nuclei_xss ({len(new_nuclei)} new)")

        result.findings = all_findings
        result.tool_used = " + ".join(tools_used)
        result.parsed_data = {
            "total_findings": len(all_findings),
            "tools_used": tools_used,
        }

        return result

    async def _run_python_xss(self) -> List[Dict[str, Any]]:
        """Run Python xss_tester.py for context-aware XSS testing."""
        findings = []
        try:
            from phase3_testing.injection.xss_tester import XSSTester

            tester = XSSTester(
                target=self.target,
                output_dir=str(self.output_dir),
                proxy=self.proxy,
            )

            scan_result = None
            for method_name in ["test", "scan", "run"]:
                if hasattr(tester, method_name):
                    scan_result = await getattr(tester, method_name)()
                    break

            if scan_result and hasattr(scan_result, "findings"):
                for finding in scan_result.findings:
                    fd = finding.to_dict() if hasattr(finding, "to_dict") else {}
                    fd["tool"] = "python_xss_tester"
                    findings.append(fd)

        except Exception as e:
            logger.error(f"Python XSS tester failed: {e}")

        return findings

    async def _run_nuclei_xss(self) -> List[Dict[str, Any]]:
        """Run nuclei with XSS-specific templates."""
        args = [
            "-u", self.target,
            "-tags", "xss",
            "-json",
            "-silent",
        ]

        if self.proxy:
            args += ["-proxy", self.proxy]
        if self.cookie:
            args += ["-header", f"Cookie: {self.cookie}"]

        tool_result = await self.router.run_tool(
            "nuclei", args, target=self.target, timeout=self.timeout
        )

        findings = []
        if tool_result.raw_output:
            parsed = ToolRouter.parse_nuclei_jsonl(tool_result.raw_output)
            for item in parsed:
                findings.append({
                    "title": item.get("name", "XSS"),
                    "severity": item.get("severity", "medium"),
                    "url": item.get("url", self.target),
                    "description": item.get("description", ""),
                    "template_id": item.get("template_id", ""),
                    "tool": "nuclei",
                })

        return findings

    def _filter_duplicates(
        self, new_findings: List[Dict], existing: List[Dict]
    ) -> List[Dict]:
        """Remove findings that duplicate existing ones."""
        existing_urls = {(f.get("url", ""), f.get("parameter", "")) for f in existing}
        return [
            f for f in new_findings
            if (f.get("url", ""), f.get("parameter", "")) not in existing_urls
        ]


async def main():
    parser = argparse.ArgumentParser(
        description="SHADOW XSS Tester - Python context-aware + nuclei templates",
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL with parameters")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip nuclei supplement")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    ensure_dir(args.output)

    tester = XSSWrapper(
        target=args.target,
        output_dir=args.output,
        timeout=args.timeout,
        proxy=args.proxy,
        cookie=args.cookie,
        use_nuclei=not args.no_nuclei,
    )

    result = await tester.run()

    if args.json:
        print(result.to_json())
    else:
        print(f"\nXSS Testing: {len(result.findings)} findings")
        print(f"Tool used: {result.tool_used}\n")
        for finding in result.findings:
            sev = finding.get("severity", "?").upper()
            title = finding.get("title", "XSS")
            param = finding.get("parameter", "?")
            print(f"  [{sev}] {title} (param: {param})")


if __name__ == "__main__":
    asyncio.run(main())

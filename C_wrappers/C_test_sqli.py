#!/usr/bin/env python3
"""
SHADOW SQL Injection Tester - Intelligent routing wrapper.

Routing:
1. Screen with Python sqli_tester.py (fast detection)
2. If SQLi found -> escalate to sqlmap for exploitation
3. Combine screening + exploitation results

Usage (CLI):
    python C_test_sqli.py -t "https://example.com/search?q=test" -o results/
    python C_test_sqli.py -t "https://example.com/search?q=test" --exploit --level 5

Usage (importable):
    from C_wrappers.C_test_sqli import SQLiWrapper
    tester = SQLiWrapper(target="https://example.com/search?q=test")
    result = await tester.run()
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils import setup_logging, normalize_url, timestamp_now, ensure_dir
from C_wrappers.C_tool_router import ToolRouter, UnifiedResult

logger = setup_logging("test_sqli")


class SQLiWrapper:
    """
    Intelligent SQL injection testing with screen/exploit routing.

    Phase 1 (Screen): Python sqli_tester.py for fast detection
    Phase 2 (Exploit): sqlmap for confirmed SQLi exploitation
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        exploit: bool = True,
        level: int = 1,
        risk: int = 1,
        batch: bool = True,
        tamper: Optional[str] = None,
        timeout: int = 300,
        proxy: Optional[str] = None,
        cookie: Optional[str] = None,
        data: Optional[str] = None,
        method: str = "GET",
    ):
        self.target = normalize_url(target)
        self.output_dir = Path(output_dir)
        self.exploit = exploit
        self.level = level
        self.risk = risk
        self.batch = batch
        self.tamper = tamper
        self.timeout = timeout
        self.proxy = proxy
        self.cookie = cookie
        self.data = data
        self.method = method.upper()
        self.router = ToolRouter()

    async def run(self) -> UnifiedResult:
        """Run SQLi testing: screen with Python, exploit with sqlmap."""
        logger.info(f"Starting SQLi testing for: {self.target}")
        result = UnifiedResult(tool_used="sqli_wrapper", target=self.target)

        # Phase 1: Screen with Python
        screen_vulns = await self._screen_with_python()
        result.parsed_data["screening"] = {
            "tool": "python_sqli_tester",
            "vulnerabilities_found": len(screen_vulns),
            "details": screen_vulns,
        }

        if screen_vulns:
            logger.info(f"Screening found {len(screen_vulns)} potential SQLi vulnerabilities")

            # Phase 2: Escalate to sqlmap if available and exploitation requested
            if self.exploit and self.router.is_available("sqlmap"):
                sqlmap_results = await self._exploit_with_sqlmap(screen_vulns)
                result.parsed_data["exploitation"] = {
                    "tool": "sqlmap",
                    "results": sqlmap_results,
                }
                result.tool_used = "python_sqli_tester + sqlmap"

                # Merge findings
                for vuln in sqlmap_results:
                    result.findings.append(vuln)
            else:
                result.tool_used = "python_sqli_tester"
                # Use screening results as findings
                for vuln in screen_vulns:
                    result.findings.append(vuln)

                if self.exploit and not self.router.is_available("sqlmap"):
                    logger.warning("sqlmap not available for exploitation phase")
                    result.errors.append("sqlmap not available - screening only")
        else:
            logger.info("No SQLi vulnerabilities detected in screening phase")
            result.tool_used = "python_sqli_tester (clean)"

        return result

    async def _screen_with_python(self) -> List[Dict[str, Any]]:
        """Screen for SQLi using Python sqli_tester.py."""
        vulns = []
        try:
            from phase3_testing.injection.sqli_tester import SQLiTester

            tester = SQLiTester(
                target=self.target,
                output_dir=str(self.output_dir),
                proxy=self.proxy,
            )

            if hasattr(tester, "test"):
                scan_result = await tester.test()
            elif hasattr(tester, "scan"):
                scan_result = await tester.scan()
            elif hasattr(tester, "run"):
                scan_result = await tester.run()
            else:
                logger.warning("SQLiTester has no standard entry point")
                return []

            if hasattr(scan_result, "findings"):
                for finding in scan_result.findings:
                    vuln_dict = finding.to_dict() if hasattr(finding, "to_dict") else {}
                    vulns.append(vuln_dict)

            # Also extract from vulnerabilities attribute
            if hasattr(tester, "vulnerabilities"):
                for vuln in tester.vulnerabilities:
                    vuln_dict = vuln.to_dict() if hasattr(vuln, "to_dict") else {}
                    if vuln_dict and vuln_dict not in vulns:
                        vulns.append(vuln_dict)

        except Exception as e:
            logger.error(f"Python SQLi screening failed: {e}")

        return vulns

    async def _exploit_with_sqlmap(self, screen_vulns: List[Dict]) -> List[Dict[str, Any]]:
        """Exploit confirmed SQLi with sqlmap."""
        results = []

        # Determine injectable parameters from screening
        injectable_params = set()
        for vuln in screen_vulns:
            param = vuln.get("parameter", "")
            if param:
                injectable_params.add(param)

        if not injectable_params:
            # No specific params identified, run sqlmap on full URL
            sqlmap_result = await self._run_sqlmap(self.target)
            if sqlmap_result:
                results.extend(sqlmap_result)
        else:
            # Run sqlmap on each injectable parameter
            for param in injectable_params:
                logger.info(f"Exploiting parameter '{param}' with sqlmap")
                sqlmap_result = await self._run_sqlmap(self.target, parameter=param)
                if sqlmap_result:
                    results.extend(sqlmap_result)

        return results

    async def _run_sqlmap(
        self, url: str, parameter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Run sqlmap against a specific URL/parameter."""
        output_dir = self.router.get_temp_file(suffix="")
        os.unlink(output_dir)  # sqlmap creates the directory

        args = [
            "-u", url,
            "--batch",
            "--level", str(self.level),
            "--risk", str(self.risk),
            "--output-dir", output_dir,
            "--forms" if self.method == "POST" and not self.data else "",
        ]

        # Remove empty strings
        args = [a for a in args if a]

        if parameter:
            args += ["-p", parameter]

        if self.cookie:
            args += ["--cookie", self.cookie]

        if self.data:
            args += ["--data", self.data]

        if self.proxy:
            args += ["--proxy", self.proxy]

        if self.tamper:
            args += ["--tamper", self.tamper]

        # Add timeout
        args += ["--timeout", str(min(self.timeout, 30))]

        tool_result = await self.router.run_tool(
            "sqlmap", args, target=url, timeout=self.timeout
        )

        findings = []

        if tool_result.raw_output:
            # Parse sqlmap text output for key findings
            output = tool_result.raw_output

            # Check for confirmed injection
            if "injectable" in output.lower() or "parameter" in output.lower():
                finding = {
                    "title": f"SQL Injection Confirmed{f' ({parameter})' if parameter else ''}",
                    "severity": "high",
                    "url": url,
                    "parameter": parameter or "",
                    "tool": "sqlmap",
                    "evidence": "",
                }

                # Extract DB type
                for db_type in ["MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle", "SQLite"]:
                    if db_type.lower() in output.lower():
                        finding["database_type"] = db_type
                        break

                # Extract injection types found
                injection_types = []
                for inj_type in ["boolean-based", "time-based", "error-based", "UNION query", "stacked queries"]:
                    if inj_type.lower() in output.lower():
                        injection_types.append(inj_type)
                if injection_types:
                    finding["injection_types"] = injection_types
                    finding["evidence"] = f"Injection types: {', '.join(injection_types)}"

                # Check for database enumeration success
                if "available databases" in output.lower():
                    finding["severity"] = "critical"
                    finding["title"] = f"SQL Injection - Database Enumeration{f' ({parameter})' if parameter else ''}"

                findings.append(finding)

        # Cleanup temp dir
        try:
            import shutil
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
        except Exception:
            pass

        return findings


async def main():
    parser = argparse.ArgumentParser(
        description="SHADOW SQLi Tester - Screen with Python, exploit with sqlmap",
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL with parameters")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--no-exploit", action="store_true", help="Screen only, no sqlmap exploitation")
    parser.add_argument("--level", type=int, default=1, help="sqlmap level (1-5)")
    parser.add_argument("--risk", type=int, default=1, help="sqlmap risk (1-3)")
    parser.add_argument("--tamper", help="sqlmap tamper script(s)")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--data", help="POST data")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    ensure_dir(args.output)

    tester = SQLiWrapper(
        target=args.target,
        output_dir=args.output,
        exploit=not args.no_exploit,
        level=args.level,
        risk=args.risk,
        tamper=args.tamper,
        timeout=args.timeout,
        proxy=args.proxy,
        cookie=args.cookie,
        data=args.data,
        method=args.method,
    )

    result = await tester.run()

    if args.json:
        print(result.to_json())
    else:
        print(f"\nSQLi Testing: {len(result.findings)} findings")
        print(f"Tool used: {result.tool_used}\n")
        for finding in result.findings:
            title = finding.get("title", "SQLi")
            severity = finding.get("severity", "?")
            param = finding.get("parameter", "?")
            print(f"  [{severity.upper()}] {title} (param: {param})")


if __name__ == "__main__":
    asyncio.run(main())

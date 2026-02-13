#!/usr/bin/env python3
"""
SHADOW Subdomain Scanner - Intelligent routing wrapper.

Routing:
1. Try subfinder (PRIMARY, fast passive enum)
2. Try amass as supplement (active + passive)
3. Fall back to Python subdomain_enum.py
4. Merge all results, deduplicate

Usage (CLI):
    python C_scan_subdomains.py -t example.com -o results/
    python C_scan_subdomains.py -t example.com --deep

Usage (importable):
    from C_wrappers.C_scan_subdomains import SubdomainScanner
    scanner = SubdomainScanner(target="example.com")
    result = await scanner.run()
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils import setup_logging, extract_domain, timestamp_now, ensure_dir
from core.result_manager import ScanResult, Finding, Severity
from C_wrappers.C_tool_router import ToolRouter, UnifiedResult

logger = setup_logging("scan_subdomains")


class SubdomainScanner:
    """
    Intelligent subdomain enumeration with Kali/Python routing.

    Priority: subfinder -> amass -> Python subdomain_enum.py
    Merges all results and deduplicates.
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        deep: bool = False,
        wordlist: Optional[str] = None,
        timeout: int = 300,
        proxy: Optional[str] = None,
    ):
        self.target = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.deep = deep
        self.wordlist = wordlist
        self.timeout = timeout
        self.proxy = proxy
        self.router = ToolRouter()
        self.all_subdomains: Set[str] = set()

    async def run(self) -> UnifiedResult:
        """Run subdomain enumeration with intelligent routing."""
        logger.info(f"Starting subdomain enumeration for: {self.target}")
        result = UnifiedResult(tool_used="subdomain_scanner", target=self.target)
        tools_used = []

        # 1. Try subfinder (PRIMARY)
        if self.router.is_available("subfinder"):
            subfinder_subs = await self._run_subfinder()
            self.all_subdomains.update(subfinder_subs)
            tools_used.append(f"subfinder ({len(subfinder_subs)} found)")
            logger.info(f"subfinder found {len(subfinder_subs)} subdomains")

        # 2. Try amass as supplement (if deep scan)
        if self.deep and self.router.is_available("amass"):
            amass_subs = await self._run_amass()
            new_from_amass = amass_subs - self.all_subdomains
            self.all_subdomains.update(amass_subs)
            tools_used.append(f"amass ({len(new_from_amass)} new)")
            logger.info(f"amass found {len(new_from_amass)} new subdomains")

        # 3. Fall back to / supplement with Python subdomain_enum.py
        if not self.all_subdomains or self.deep:
            python_subs = await self._run_python_enum()
            new_from_python = python_subs - self.all_subdomains
            self.all_subdomains.update(python_subs)
            tools_used.append(f"python_subdomain_enum ({len(new_from_python)} new)")
            logger.info(f"Python enum found {len(new_from_python)} new subdomains")

        # Build result
        sorted_subs = sorted(self.all_subdomains)
        result.tool_used = " + ".join(tools_used) if tools_used else "none"
        result.findings = [
            {"subdomain": sub, "type": "subdomain"} for sub in sorted_subs
        ]
        result.parsed_data = {
            "subdomains": sorted_subs,
            "total": len(sorted_subs),
            "tools_used": tools_used,
        }
        result.raw_output = "\n".join(sorted_subs)

        logger.info(f"Total unique subdomains: {len(sorted_subs)}")
        return result

    async def _run_subfinder(self) -> Set[str]:
        """Run subfinder for passive subdomain enumeration."""
        args = ["-d", self.target, "-silent"]
        if self.timeout:
            args += ["-timeout", str(min(self.timeout, 60))]

        tool_result = await self.router.run_tool(
            "subfinder", args, target=self.target, timeout=self.timeout
        )

        if not tool_result.success:
            logger.warning(f"subfinder failed: {tool_result.errors}")
            return set()

        return {
            line.strip().lower()
            for line in tool_result.raw_output.strip().splitlines()
            if line.strip() and self.target in line.strip().lower()
        }

    async def _run_amass(self) -> Set[str]:
        """Run amass for active+passive subdomain enumeration."""
        args = ["enum", "-passive", "-d", self.target]

        tool_result = await self.router.run_tool(
            "amass", args, target=self.target, timeout=self.timeout * 2
        )

        if not tool_result.success:
            logger.warning(f"amass failed: {tool_result.errors}")
            return set()

        return {
            line.strip().lower()
            for line in tool_result.raw_output.strip().splitlines()
            if line.strip() and self.target in line.strip().lower()
        }

    async def _run_python_enum(self) -> Set[str]:
        """Fall back to Python subdomain_enum.py."""
        try:
            from phase1_recon.subdomain_enum import SubdomainEnumerator

            enumerator = SubdomainEnumerator(
                target=self.target,
                output_dir=str(self.output_dir),
                proxy=self.proxy,
                timeout=min(self.timeout, 30),
            )

            if hasattr(enumerator, "enumerate"):
                scan_result = await enumerator.enumerate()
            elif hasattr(enumerator, "scan"):
                scan_result = await enumerator.scan()
            elif hasattr(enumerator, "run"):
                scan_result = await enumerator.run()
            else:
                logger.warning("SubdomainEnumerator has no standard entry point")
                return set()

            # Extract subdomains from findings
            subs = set()
            if hasattr(scan_result, "findings"):
                for finding in scan_result.findings:
                    if hasattr(finding, "url") and finding.url:
                        subs.add(finding.url.lower())
                    if hasattr(finding, "metadata"):
                        sub = finding.metadata.get("subdomain", "")
                        if sub:
                            subs.add(sub.lower())

            # Also check if enumerator has discovered_subdomains
            if hasattr(enumerator, "subdomains"):
                for sub in enumerator.subdomains:
                    if hasattr(sub, "name"):
                        subs.add(sub.name.lower())
                    elif isinstance(sub, str):
                        subs.add(sub.lower())

            return subs

        except Exception as e:
            logger.error(f"Python subdomain_enum fallback failed: {e}")
            return set()


async def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Subdomain Scanner - Kali/Python intelligent routing",
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--deep", action="store_true", help="Deep scan (use all tools)")
    parser.add_argument("--wordlist", help="Custom wordlist for DNS bruteforce")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    ensure_dir(args.output)

    scanner = SubdomainScanner(
        target=args.target,
        output_dir=args.output,
        deep=args.deep,
        wordlist=args.wordlist,
        timeout=args.timeout,
        proxy=args.proxy,
    )

    result = await scanner.run()

    if args.json:
        print(result.to_json())
    else:
        print(f"\nSubdomain Enumeration: {result.parsed_data.get('total', 0)} found")
        print(f"Tools used: {result.tool_used}\n")
        for sub in result.parsed_data.get("subdomains", []):
            print(f"  {sub}")


if __name__ == "__main__":
    asyncio.run(main())

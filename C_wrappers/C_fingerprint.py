#!/usr/bin/env python3
"""
SHADOW Technology Fingerprinter - Intelligent routing wrapper.

Routing:
1. Try whatweb first (1800+ plugins)
2. Try wafw00f for WAF detection
3. Fall back to Python tech_fingerprint.py
4. Merge tech stack results

Usage (CLI):
    python C_fingerprint.py -t https://example.com -o results/

Usage (importable):
    from C_wrappers.C_fingerprint import TechFingerprinter
    fp = TechFingerprinter(target="https://example.com")
    result = await fp.run()
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

logger = setup_logging("fingerprint")


class TechFingerprinter:
    """
    Intelligent technology fingerprinting with Kali/Python routing.

    Priority: whatweb -> wafw00f -> Python tech_fingerprint.py
    Merges all results into unified tech stack.
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        aggression: int = 3,
        timeout: int = 120,
        proxy: Optional[str] = None,
    ):
        self.target = normalize_url(target)
        self.output_dir = Path(output_dir)
        self.aggression = aggression
        self.timeout = timeout
        self.proxy = proxy
        self.router = ToolRouter()

    async def run(self) -> UnifiedResult:
        """Run technology fingerprinting with intelligent routing."""
        logger.info(f"Starting tech fingerprinting for: {self.target}")
        result = UnifiedResult(tool_used="tech_fingerprinter", target=self.target)
        technologies: Dict[str, Dict[str, Any]] = {}  # name -> details
        waf_detected: List[str] = []
        tools_used = []

        # 1. whatweb (PRIMARY, 1800+ plugins)
        if self.router.is_available("whatweb"):
            whatweb_techs = await self._run_whatweb()
            for tech in whatweb_techs:
                name = tech.get("name", "")
                if name:
                    technologies[name.lower()] = tech
            tools_used.append(f"whatweb ({len(whatweb_techs)} techs)")

        # 2. wafw00f (WAF detection)
        if self.router.is_available("wafw00f"):
            wafs = await self._run_wafw00f()
            waf_detected.extend(wafs)
            tools_used.append(f"wafw00f ({len(wafs)} WAFs)")

        # 3. Python tech_fingerprint.py (supplement/fallback)
        python_techs = await self._run_python_fingerprint()
        for tech in python_techs:
            name = tech.get("name", "")
            if name and name.lower() not in technologies:
                technologies[name.lower()] = tech
        if python_techs:
            tools_used.append(f"python_fingerprint ({len(python_techs)} techs)")

        # Build result
        tech_list = sorted(technologies.values(), key=lambda t: t.get("name", ""))
        result.findings = tech_list
        result.tool_used = " + ".join(tools_used) if tools_used else "none"
        result.parsed_data = {
            "technologies": tech_list,
            "waf_detected": waf_detected,
            "total_technologies": len(tech_list),
            "tools_used": tools_used,
        }

        logger.info(f"Found {len(tech_list)} technologies, {len(waf_detected)} WAFs")
        return result

    async def _run_whatweb(self) -> List[Dict[str, Any]]:
        """Run whatweb for deep technology fingerprinting."""
        args = [
            self.target,
            f"--aggression={self.aggression}",
            "--log-json=-",
            "--color=never",
        ]

        if self.proxy:
            args += ["--proxy", self.proxy]

        tool_result = await self.router.run_tool(
            "whatweb", args, target=self.target, timeout=self.timeout
        )

        technologies = []
        if tool_result.raw_output:
            parsed = ToolRouter.parse_whatweb_json(tool_result.raw_output)
            for result_item in parsed:
                for tech in result_item.get("technologies", []):
                    technologies.append(tech)

        return technologies

    async def _run_wafw00f(self) -> List[str]:
        """Run wafw00f for WAF detection."""
        args = [self.target, "-o-", "-f", "json"]

        if self.proxy:
            args += ["-p", self.proxy]

        tool_result = await self.router.run_tool(
            "wafw00f", args, target=self.target, timeout=60
        )

        wafs = []
        if tool_result.raw_output:
            try:
                data = json.loads(tool_result.raw_output)
                if isinstance(data, list):
                    for item in data:
                        waf = item.get("firewall", "")
                        if waf and waf.lower() != "none":
                            wafs.append(waf)
                elif isinstance(data, dict):
                    waf = data.get("firewall", "")
                    if waf and waf.lower() != "none":
                        wafs.append(waf)
            except json.JSONDecodeError:
                # Parse text output
                for line in tool_result.raw_output.strip().splitlines():
                    if "is behind" in line.lower():
                        parts = line.split("is behind")
                        if len(parts) > 1:
                            wafs.append(parts[1].strip().rstrip("."))

        return wafs

    async def _run_python_fingerprint(self) -> List[Dict[str, Any]]:
        """Fall back to Python tech_fingerprint.py."""
        technologies = []
        try:
            from phase1_recon.tech_fingerprint import TechFingerprinter as PyFingerprinter

            fp = PyFingerprinter(
                target=self.target,
                output_dir=str(self.output_dir),
                proxy=self.proxy,
            )

            scan_result = None
            for method_name in ["scan", "run", "fingerprint"]:
                if hasattr(fp, method_name):
                    scan_result = await getattr(fp, method_name)()
                    break

            if scan_result and hasattr(scan_result, "findings"):
                for finding in scan_result.findings:
                    fd = finding.to_dict() if hasattr(finding, "to_dict") else {}
                    technologies.append({
                        "name": fd.get("title", ""),
                        "version": fd.get("metadata", {}).get("version", ""),
                        "source": "python_fingerprint",
                    })

        except Exception as e:
            logger.error(f"Python fingerprint fallback failed: {e}")

        return technologies


async def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Tech Fingerprinter - whatweb + wafw00f + Python",
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--aggression", type=int, default=3,
                        help="whatweb aggression level (1-4)")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    ensure_dir(args.output)

    fp = TechFingerprinter(
        target=args.target,
        output_dir=args.output,
        aggression=args.aggression,
        timeout=args.timeout,
        proxy=args.proxy,
    )

    result = await fp.run()

    if args.json:
        print(result.to_json())
    else:
        print(f"\nTechnology Fingerprinting Results")
        print(f"Tool used: {result.tool_used}\n")

        wafs = result.parsed_data.get("waf_detected", [])
        if wafs:
            print(f"WAF Detected: {', '.join(wafs)}\n")

        print("Technologies:")
        for tech in result.findings:
            name = tech.get("name", "Unknown")
            version = tech.get("version", "")
            version_str = f" v{version}" if version else ""
            print(f"  - {name}{version_str}")


if __name__ == "__main__":
    asyncio.run(main())

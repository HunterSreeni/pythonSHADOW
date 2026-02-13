#!/usr/bin/env python3
"""
SHADOW Parameter Discovery - Intelligent routing wrapper.

Routing:
1. Try ffuf parameter fuzzing mode first (PRIMARY)
2. Fall back to Python parameter_discovery.py
3. Merge results

Usage (CLI):
    python C_discover_params.py -t https://example.com/page -o results/

Usage (importable):
    from C_wrappers.C_discover_params import ParamDiscoverer
    discoverer = ParamDiscoverer(target="https://example.com/page")
    result = await discoverer.run()
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils import setup_logging, normalize_url, timestamp_now, ensure_dir
from C_wrappers.C_tool_router import ToolRouter, UnifiedResult

logger = setup_logging("discover_params")


class ParamDiscoverer:
    """
    Intelligent parameter discovery with Kali/Python routing.

    Priority: ffuf (parameter mode) -> Python parameter_discovery.py
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        wordlist: Optional[str] = None,
        method: str = "GET",
        threads: int = 50,
        timeout: int = 300,
        proxy: Optional[str] = None,
    ):
        self.target = normalize_url(target)
        self.output_dir = Path(output_dir)
        self.method = method.upper()
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.router = ToolRouter()
        self.wordlist = wordlist or self.router.get_wordlist("parameters")
        self.all_params: Set[str] = set()

    async def run(self) -> UnifiedResult:
        """Run parameter discovery with intelligent routing."""
        logger.info(f"Starting parameter discovery for: {self.target}")
        result = UnifiedResult(tool_used="param_discoverer", target=self.target)
        tools_used = []

        # 1. Try ffuf parameter mode
        if self.wordlist and self.router.is_available("ffuf"):
            ffuf_params = await self._run_ffuf()
            self.all_params.update(ffuf_params)
            tools_used.append(f"ffuf ({len(ffuf_params)} found)")

        # 2. Supplement/fallback with Python
        python_params = await self._run_python_discovery()
        new_params = python_params - self.all_params
        self.all_params.update(python_params)
        tools_used.append(f"python_param_discovery ({len(new_params)} new)")

        sorted_params = sorted(self.all_params)
        result.findings = [
            {"parameter": p, "type": "discovered_parameter"} for p in sorted_params
        ]
        result.tool_used = " + ".join(tools_used)
        result.parsed_data = {
            "parameters": sorted_params,
            "total": len(sorted_params),
            "tools_used": tools_used,
        }
        result.raw_output = "\n".join(sorted_params)

        logger.info(f"Total unique parameters: {len(sorted_params)}")
        return result

    async def _run_ffuf(self) -> Set[str]:
        """Run ffuf in parameter fuzzing mode."""
        json_file = self.router.get_temp_file(suffix=".json")

        # Build URL with FUZZ as parameter name
        if self.method == "GET":
            fuzz_url = f"{self.target.rstrip('/')}?FUZZ=shadow_test_value"
            args = [
                "-u", fuzz_url,
                "-w", self.wordlist,
                "-t", str(self.threads),
                "-o", json_file,
                "-of", "json",
                "-s",
                "-fs", "0",  # Filter size 0 (no content change)
            ]
        else:
            args = [
                "-u", self.target,
                "-w", self.wordlist,
                "-X", "POST",
                "-d", "FUZZ=shadow_test_value",
                "-t", str(self.threads),
                "-o", json_file,
                "-of", "json",
                "-s",
            ]

        if self.proxy:
            args += ["-x", self.proxy]

        tool_result = await self.router.run_tool(
            "ffuf", args, target=self.target, timeout=self.timeout
        )

        params = set()
        try:
            if os.path.exists(json_file):
                with open(json_file, "r") as f:
                    json_data = f.read()
                parsed = ToolRouter.parse_ffuf_json(json_data)
                for item in parsed:
                    param = item.get("input", "")
                    if param:
                        params.add(param)
        except Exception as e:
            logger.warning(f"Failed to parse ffuf output: {e}")
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)

        return params

    async def _run_python_discovery(self) -> Set[str]:
        """Fall back to Python parameter_discovery.py."""
        params = set()
        try:
            from phase2_discovery.parameter_discovery import ParameterDiscovery

            discoverer = ParameterDiscovery(
                target=self.target,
                output_dir=str(self.output_dir),
                proxy=self.proxy,
            )

            scan_result = None
            for method_name in ["scan", "run", "discover"]:
                if hasattr(discoverer, method_name):
                    scan_result = await getattr(discoverer, method_name)()
                    break

            if scan_result and hasattr(scan_result, "findings"):
                for finding in scan_result.findings:
                    param = getattr(finding, "parameter", None)
                    if param:
                        params.add(param)
                    if hasattr(finding, "metadata"):
                        p = finding.metadata.get("parameter", "")
                        if p:
                            params.add(p)

        except Exception as e:
            logger.error(f"Python parameter discovery failed: {e}")

        return params


async def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Parameter Discovery - ffuf + Python intelligent routing",
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-w", "--wordlist", help="Custom parameter wordlist")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    ensure_dir(args.output)

    discoverer = ParamDiscoverer(
        target=args.target,
        output_dir=args.output,
        wordlist=args.wordlist,
        method=args.method,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
    )

    result = await discoverer.run()

    if args.json:
        print(result.to_json())
    else:
        print(f"\nParameter Discovery: {result.parsed_data.get('total', 0)} parameters found")
        print(f"Tool used: {result.tool_used}\n")
        for param in result.parsed_data.get("parameters", []):
            print(f"  {param}")


if __name__ == "__main__":
    asyncio.run(main())

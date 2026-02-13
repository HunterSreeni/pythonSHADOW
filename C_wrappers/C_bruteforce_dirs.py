#!/usr/bin/env python3
"""
SHADOW Directory Bruteforcer - Intelligent routing wrapper.

Routing:
1. Try ffuf first (PRIMARY, with JSON output)
2. Try gobuster as alternative
3. Fall back to Python directory_bruteforce.py
4. Merge results

Usage (CLI):
    python C_bruteforce_dirs.py -t https://example.com -o results/
    python C_bruteforce_dirs.py -t https://example.com -w /path/to/wordlist

Usage (importable):
    from C_wrappers.C_bruteforce_dirs import DirBruteforcer
    bruter = DirBruteforcer(target="https://example.com")
    result = await bruter.run()
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

logger = setup_logging("bruteforce_dirs")


class DirBruteforcer:
    """
    Intelligent directory bruteforcing with Kali/Python routing.

    Priority: ffuf -> gobuster -> Python directory_bruteforce.py
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        wordlist: Optional[str] = None,
        extensions: Optional[str] = None,
        threads: int = 50,
        timeout: int = 600,
        status_codes: str = "200,201,204,301,302,307,308,401,403,405",
        proxy: Optional[str] = None,
    ):
        self.target = normalize_url(target)
        self.output_dir = Path(output_dir)
        self.extensions = extensions
        self.threads = threads
        self.timeout = timeout
        self.status_codes = status_codes
        self.proxy = proxy
        self.router = ToolRouter()
        self.wordlist = wordlist or self.router.get_wordlist("directories")

    async def run(self) -> UnifiedResult:
        """Run directory bruteforcing with intelligent routing."""
        logger.info(f"Starting directory bruteforce for: {self.target}")

        if not self.wordlist:
            return UnifiedResult(
                tool_used="none",
                target=self.target,
                errors=["No wordlist available. Install SecLists or provide a wordlist."],
                exit_code=-1,
            )

        decision = self.router.select_tool(
            primary="ffuf",
            fallbacks=["gobuster", "dirb"],
            category="directory_bruteforce",
        )

        if decision.chosen_tool == "ffuf":
            result = await self._run_ffuf()
        elif decision.chosen_tool == "gobuster":
            result = await self._run_gobuster()
        elif decision.chosen_tool == "dirb":
            result = await self._run_dirb()
        else:
            result = await self._run_python_bruteforce()

        result.routing_decision = decision
        return result

    async def _run_ffuf(self) -> UnifiedResult:
        """Run ffuf with JSON output."""
        json_file = self.router.get_temp_file(suffix=".json")

        # Build target URL with FUZZ keyword
        target_url = self.target.rstrip("/") + "/FUZZ"

        args = [
            "-u", target_url,
            "-w", self.wordlist,
            "-mc", self.status_codes,
            "-t", str(self.threads),
            "-o", json_file,
            "-of", "json",
            "-s",  # Silent mode
        ]

        if self.extensions:
            args += ["-e", self.extensions]

        if self.proxy:
            args += ["-x", self.proxy]

        tool_result = await self.router.run_tool(
            "ffuf", args, target=self.target, timeout=self.timeout
        )

        # Parse JSON output
        try:
            if os.path.exists(json_file):
                with open(json_file, "r") as f:
                    json_data = f.read()
                parsed = ToolRouter.parse_ffuf_json(json_data)
                tool_result.findings = parsed
                tool_result.parsed_data = {
                    "results": parsed,
                    "total": len(parsed),
                }
        except Exception as e:
            logger.warning(f"Failed to parse ffuf output: {e}")
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)

        return tool_result

    async def _run_gobuster(self) -> UnifiedResult:
        """Run gobuster dir mode."""
        args = [
            "dir",
            "-u", self.target,
            "-w", self.wordlist,
            "-t", str(self.threads),
            "-s", self.status_codes,
            "-q",  # Quiet mode
            "--no-error",
        ]

        if self.extensions:
            args += ["-x", self.extensions]

        if self.proxy:
            args += ["--proxy", self.proxy]

        tool_result = await self.router.run_tool(
            "gobuster", args, target=self.target, timeout=self.timeout
        )

        # Parse gobuster output (line-based)
        if tool_result.raw_output:
            findings = []
            for line in tool_result.raw_output.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("="):
                    continue
                # gobuster format: /path (Status: 200) [Size: 1234]
                parts = line.split()
                if parts:
                    path = parts[0]
                    status = 0
                    length = 0
                    if "(Status:" in line:
                        try:
                            status = int(line.split("Status:")[1].split(")")[0].strip())
                        except (ValueError, IndexError):
                            pass
                    if "[Size:" in line:
                        try:
                            length = int(line.split("Size:")[1].split("]")[0].strip())
                        except (ValueError, IndexError):
                            pass
                    findings.append({
                        "url": self.target.rstrip("/") + path,
                        "input": path.lstrip("/"),
                        "status": status,
                        "length": length,
                    })
            tool_result.findings = findings
            tool_result.parsed_data = {"results": findings, "total": len(findings)}

        return tool_result

    async def _run_dirb(self) -> UnifiedResult:
        """Run dirb as last Kali fallback."""
        args = [self.target, self.wordlist, "-S"]  # Silent

        if self.proxy:
            args += ["-p", self.proxy]

        tool_result = await self.router.run_tool(
            "dirb", args, target=self.target, timeout=self.timeout
        )

        # Parse dirb output
        if tool_result.raw_output:
            findings = []
            for line in tool_result.raw_output.strip().splitlines():
                line = line.strip()
                if line.startswith("+ ") or line.startswith("==> DIRECTORY:"):
                    url = line.replace("+ ", "").replace("==> DIRECTORY: ", "").strip()
                    # Extract status code if present
                    status = 200
                    if "(CODE:" in url:
                        try:
                            status = int(url.split("CODE:")[1].split(")")[0].strip())
                            url = url.split(" (CODE:")[0].strip()
                        except (ValueError, IndexError):
                            pass
                    findings.append({
                        "url": url,
                        "status": status,
                        "input": url.replace(self.target, "").strip("/"),
                    })
            tool_result.findings = findings
            tool_result.parsed_data = {"results": findings, "total": len(findings)}

        return tool_result

    async def _run_python_bruteforce(self) -> UnifiedResult:
        """Fall back to Python directory_bruteforce.py."""
        result = UnifiedResult(tool_used="python_directory_bruteforce", target=self.target)

        try:
            from phase2_discovery.directory_bruteforce import DirectoryBruteforcer

            bruter = DirectoryBruteforcer(
                target=self.target,
                output_dir=str(self.output_dir),
                proxy=self.proxy,
            )

            if hasattr(bruter, "scan"):
                scan_result = await bruter.scan()
            elif hasattr(bruter, "run"):
                scan_result = await bruter.run()
            else:
                result.errors.append("DirectoryBruteforcer has no standard entry point")
                return result

            if hasattr(scan_result, "findings"):
                for finding in scan_result.findings:
                    result.findings.append(
                        finding.to_dict() if hasattr(finding, "to_dict") else {"description": str(finding)}
                    )
            result.parsed_data = scan_result.to_dict() if hasattr(scan_result, "to_dict") else {}

        except Exception as e:
            logger.error(f"Python directory bruteforce fallback failed: {e}")
            result.errors.append(str(e))

        return result


async def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Directory Bruteforcer - Kali/Python intelligent routing",
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist path")
    parser.add_argument("-e", "--extensions", help="File extensions (e.g., 'php,html,js')")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds")
    parser.add_argument("--status-codes", default="200,201,204,301,302,307,308,401,403,405",
                        help="Status codes to match")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    ensure_dir(args.output)

    bruter = DirBruteforcer(
        target=args.target,
        output_dir=args.output,
        wordlist=args.wordlist,
        extensions=args.extensions,
        threads=args.threads,
        timeout=args.timeout,
        status_codes=args.status_codes,
        proxy=args.proxy,
    )

    result = await bruter.run()

    if args.json:
        print(result.to_json())
    else:
        print(f"\nDirectory Bruteforce: {len(result.findings)} paths found")
        if result.routing_decision:
            print(f"Tool used: {result.routing_decision.chosen_tool}\n")
        for item in result.findings[:50]:
            url = item.get("url", item.get("input", "?"))
            status = item.get("status", "?")
            length = item.get("length", "?")
            print(f"  [{status}] {url} (size: {length})")
        if len(result.findings) > 50:
            print(f"  ... and {len(result.findings) - 50} more")


if __name__ == "__main__":
    asyncio.run(main())

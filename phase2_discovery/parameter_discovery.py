#!/usr/bin/env python3
"""
Hidden parameter discovery module for finding undocumented parameters.

Usage:
    python parameter_discovery.py --target https://example.com/page --output results/
"""

import argparse
import asyncio
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir, read_lines

logger = setup_logging("parameter_discovery")


@dataclass
class DiscoveredParameter:
    """Represents a discovered parameter."""

    name: str
    url: str
    method: str = "GET"
    location: str = "query"  # query, body, header
    evidence: str = ""
    response_diff: Dict[str, Any] = field(default_factory=dict)
    interesting: bool = False
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "method": self.method,
            "location": self.location,
            "evidence": self.evidence[:200] if self.evidence else "",
            "response_diff": self.response_diff,
            "interesting": self.interesting,
            "reason": self.reason,
        }


class ParameterDiscovery:
    """
    Hidden parameter discovery using multiple techniques.

    Features:
    - Response comparison (size, status, reflection)
    - Arjun wrapper for fast discovery
    - Header parameter fuzzing
    - Body parameter fuzzing (JSON, form)
    - Smart parameter value testing
    """

    # Common parameter names to test
    COMMON_PARAMS = [
        "id", "page", "q", "search", "query", "s", "keyword",
        "user", "username", "name", "email", "password", "pass",
        "token", "key", "api_key", "apikey", "auth", "session",
        "redirect", "url", "next", "return", "callback", "goto",
        "file", "path", "dir", "folder", "filename", "document",
        "action", "cmd", "command", "exec", "run", "do",
        "debug", "test", "admin", "dev", "mode", "type",
        "format", "output", "view", "template", "layout",
        "sort", "order", "filter", "limit", "offset", "skip",
        "include", "exclude", "fields", "select", "columns",
        "lang", "language", "locale", "country", "region",
        "size", "width", "height", "quality", "resize",
        "v", "version", "ver", "ref", "source", "utm_source",
        "category", "cat", "tag", "tags", "label", "group",
        "date", "start", "end", "from", "to", "year", "month",
        "status", "state", "active", "enabled", "disabled",
        "role", "permission", "access", "level", "privilege",
        "data", "json", "xml", "content", "body", "payload",
        "callback", "jsonp", "cors", "origin", "referer",
    ]

    # Interesting parameters that warrant special attention
    INTERESTING_PARAMS = [
        "debug", "test", "admin", "root", "sudo", "internal",
        "password", "secret", "token", "key", "auth", "session",
        "redirect", "url", "next", "return", "goto", "callback",
        "file", "path", "include", "require", "load", "read",
        "cmd", "command", "exec", "run", "shell", "system",
        "sql", "query", "where", "order", "union", "select",
        "template", "render", "view", "layout", "theme",
        "role", "permission", "privilege", "access", "level",
        "config", "setting", "option", "env", "environment",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        wordlist: Optional[str] = None,
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 10,
        threads: int = 30,
        methods: Optional[List[str]] = None,
        test_values: Optional[List[str]] = None,
        use_arjun: bool = True,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.wordlist = wordlist
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.methods = methods or ["GET"]
        self.test_values = test_values or ["1", "true", "test", "admin"]
        self.use_arjun = use_arjun and self._tool_exists("arjun")
        self.verbose = verbose

        self.discovered: Dict[str, DiscoveredParameter] = {}
        self.baseline_response: Optional[HTTPResponse] = None
        self.baseline_metrics: Dict[str, Any] = {}

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def discover(self) -> ScanResult:
        """Run parameter discovery and return results."""
        result = ScanResult(
            tool="parameter_discovery",
            target=self.target,
            config={
                "wordlist": self.wordlist,
                "threads": self.threads,
                "methods": self.methods,
                "use_arjun": self.use_arjun,
            },
        )

        logger.info(f"Starting parameter discovery for: {self.target}")

        try:
            # Get baseline response
            await self._get_baseline()

            if self.use_arjun:
                # Use Arjun for parameter discovery
                await self._run_arjun()
            else:
                # Use native parameter fuzzing
                params = self._load_parameters()
                await self._native_discovery(params)

            # Test header parameters
            await self._discover_header_params()

            # Additional JSON body parameter discovery
            if "POST" in self.methods:
                await self._discover_json_params()

            # Calculate statistics
            result.stats = {
                "total_discovered": len(self.discovered),
                "query_params": sum(1 for p in self.discovered.values() if p.location == "query"),
                "body_params": sum(1 for p in self.discovered.values() if p.location == "body"),
                "header_params": sum(1 for p in self.discovered.values() if p.location == "header"),
                "interesting_params": sum(1 for p in self.discovered.values() if p.interesting),
            }

            # Add findings
            for param in self.discovered.values():
                severity = Severity.MEDIUM if param.interesting else Severity.LOW

                # Higher severity for potentially dangerous params
                if any(p in param.name.lower() for p in ["debug", "admin", "cmd", "exec", "file", "path"]):
                    severity = Severity.HIGH

                result.add_finding(Finding(
                    title=f"Hidden Parameter Found: {param.name}",
                    severity=severity,
                    description=f"Discovered hidden {param.location} parameter via fuzzing",
                    url=param.url,
                    parameter=param.name,
                    metadata={
                        "method": param.method,
                        "location": param.location,
                        "interesting": param.interesting,
                        "reason": param.reason,
                        "response_diff": param.response_diff,
                    },
                    evidence=param.evidence,
                ))

        except Exception as e:
            result.add_error(f"Discovery error: {e}")
            logger.error(f"Discovery error: {e}")

        result.finalize()
        return result

    async def _get_baseline(self):
        """Get baseline response for comparison."""
        logger.info("Getting baseline response...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=2,
        ) as client:
            self.baseline_response = await client.get(self.target)

            self.baseline_metrics = {
                "status": self.baseline_response.status,
                "length": len(self.baseline_response.body),
                "headers_count": len(self.baseline_response.headers),
                "word_count": len(self.baseline_response.body.split()),
                "line_count": self.baseline_response.body.count('\n'),
            }

        logger.info(f"Baseline: status={self.baseline_metrics['status']}, length={self.baseline_metrics['length']}")

    async def _run_arjun(self):
        """Run Arjun for parameter discovery."""
        logger.info("Running Arjun...")

        output_file = self.output_dir / f"arjun_{self.target_domain}.json"

        cmd = [
            "arjun",
            "-u", self.target,
            "-oJ", str(output_file),
            "-t", str(self.threads),
            "--stable",
        ]

        if self.proxy:
            cmd.extend(["--proxy", self.proxy])

        if self.wordlist:
            cmd.extend(["-w", self.wordlist])

        for method in self.methods:
            if method.upper() == "GET":
                cmd.append("-m")
                cmd.append("GET")
            elif method.upper() == "POST":
                cmd.append("-m")
                cmd.append("POST")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

            if output_file.exists():
                await self._parse_arjun_output(output_file)

        except asyncio.TimeoutError:
            logger.warning("Arjun timed out")
        except Exception as e:
            logger.error(f"Arjun error: {e}")
            # Fall back to native
            logger.info("Falling back to native parameter discovery...")
            params = self._load_parameters()
            await self._native_discovery(params)

    async def _parse_arjun_output(self, output_file: Path):
        """Parse Arjun JSON output."""
        try:
            with open(output_file) as f:
                data = json.load(f)

            for url, params in data.items():
                for param in params:
                    param_name = param if isinstance(param, str) else param.get("name", "")
                    if param_name:
                        discovered = DiscoveredParameter(
                            name=param_name,
                            url=url,
                            method="GET",
                            location="query",
                            interesting=self._is_interesting_param(param_name),
                            reason=self._get_interesting_reason(param_name),
                        )
                        self.discovered[f"{url}:{param_name}"] = discovered

            logger.info(f"Arjun found {len(self.discovered)} parameters")

        except Exception as e:
            logger.error(f"Error parsing Arjun output: {e}")

    async def _native_discovery(self, params: List[str]):
        """Native parameter discovery via response comparison."""
        logger.info(f"Starting native discovery with {len(params)} parameters...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
            rate_limit=self.threads,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def test_parameter(param: str, method: str):
                async with semaphore:
                    for test_value in self.test_values:
                        try:
                            # Build URL with parameter
                            if method == "GET":
                                test_url = self._add_param_to_url(self.target, param, test_value)
                                response = await client.get(test_url)
                            else:
                                response = await client.post(
                                    self.target,
                                    data={param: test_value},
                                )

                            # Compare with baseline
                            diff = self._compare_response(response)

                            if diff["is_different"]:
                                discovered = DiscoveredParameter(
                                    name=param,
                                    url=self.target,
                                    method=method,
                                    location="query" if method == "GET" else "body",
                                    evidence=f"Test value '{test_value}' caused response change",
                                    response_diff=diff,
                                    interesting=self._is_interesting_param(param),
                                    reason=self._get_interesting_reason(param),
                                )
                                key = f"{self.target}:{param}:{method}"
                                self.discovered[key] = discovered

                                if self.verbose:
                                    logger.info(f"Found: {param} ({method}) - {diff}")
                                break

                        except Exception as e:
                            logger.debug(f"Error testing {param}: {e}")

            tasks = []
            for method in self.methods:
                for param in params:
                    tasks.append(test_parameter(param, method))

            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Native discovery found {len(self.discovered)} parameters")

    async def _discover_header_params(self):
        """Discover hidden header parameters."""
        logger.info("Testing header parameters...")

        header_params = [
            "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
            "X-Forwarded-Host", "X-Host", "X-Custom-IP-Authorization",
            "X-Debug", "X-Debug-Mode", "X-Test", "X-Admin",
            "X-Token", "X-Auth", "X-Api-Key", "X-Access-Token",
            "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
            "X-HTTP-Method-Override", "X-Method-Override",
            "X-Requested-With", "X-Custom-Header",
            "True-Client-IP", "Client-IP", "CF-Connecting-IP",
            "Fastly-Client-IP", "X-Cluster-Client-IP",
        ]

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def test_header(header: str):
                async with semaphore:
                    test_values = ["127.0.0.1", "localhost", "true", "1", "admin"]
                    for test_value in test_values:
                        try:
                            response = await client.get(
                                self.target,
                                headers={header: test_value},
                            )

                            diff = self._compare_response(response)
                            if diff["is_different"]:
                                discovered = DiscoveredParameter(
                                    name=header,
                                    url=self.target,
                                    method="GET",
                                    location="header",
                                    evidence=f"Header value '{test_value}' caused response change",
                                    response_diff=diff,
                                    interesting=True,
                                    reason="Header parameter affects response",
                                )
                                self.discovered[f"{self.target}:header:{header}"] = discovered
                                break

                        except Exception as e:
                            logger.debug(f"Error testing header {header}: {e}")

            tasks = [test_header(h) for h in header_params]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _discover_json_params(self):
        """Discover hidden JSON body parameters."""
        logger.info("Testing JSON body parameters...")

        # Get subset of interesting parameters for JSON testing
        json_params = [p for p in self.COMMON_PARAMS if p in self.INTERESTING_PARAMS] + self.INTERESTING_PARAMS[:20]

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def test_json_param(param: str):
                async with semaphore:
                    for test_value in ["1", "true", "test"]:
                        try:
                            response = await client.post(
                                self.target,
                                json={param: test_value},
                                headers={"Content-Type": "application/json"},
                            )

                            diff = self._compare_response(response)
                            if diff["is_different"]:
                                discovered = DiscoveredParameter(
                                    name=param,
                                    url=self.target,
                                    method="POST",
                                    location="body",
                                    evidence=f"JSON param with value '{test_value}' caused response change",
                                    response_diff=diff,
                                    interesting=self._is_interesting_param(param),
                                    reason=self._get_interesting_reason(param),
                                )
                                self.discovered[f"{self.target}:json:{param}"] = discovered
                                break

                        except Exception as e:
                            logger.debug(f"Error testing JSON param {param}: {e}")

            tasks = [test_json_param(p) for p in json_params]
            await asyncio.gather(*tasks, return_exceptions=True)

    def _compare_response(self, response: HTTPResponse) -> Dict[str, Any]:
        """Compare response with baseline and return differences."""
        diff = {
            "is_different": False,
            "status_changed": False,
            "length_diff": 0,
            "reflection": False,
        }

        if not self.baseline_response:
            return diff

        # Status code change
        if response.status != self.baseline_metrics["status"]:
            diff["is_different"] = True
            diff["status_changed"] = True
            diff["old_status"] = self.baseline_metrics["status"]
            diff["new_status"] = response.status

        # Significant length change (> 5%)
        length_diff = abs(len(response.body) - self.baseline_metrics["length"])
        diff["length_diff"] = length_diff

        if length_diff > self.baseline_metrics["length"] * 0.05 and length_diff > 50:
            diff["is_different"] = True

        # Check for value reflection
        for test_value in self.test_values:
            if test_value in response.body and test_value not in self.baseline_response.body:
                diff["is_different"] = True
                diff["reflection"] = True
                break

        return diff

    def _add_param_to_url(self, url: str, param: str, value: str) -> str:
        """Add parameter to URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

    def _load_parameters(self) -> List[str]:
        """Load parameters from wordlist or use defaults."""
        if self.wordlist and Path(self.wordlist).exists():
            params = read_lines(self.wordlist)
            logger.info(f"Loaded {len(params)} parameters from wordlist")
            return params

        # Check default wordlist
        default_wordlist = Path(__file__).parent.parent / "config" / "wordlists" / "parameters.txt"
        if default_wordlist.exists():
            params = read_lines(str(default_wordlist))
            logger.info(f"Loaded {len(params)} parameters from default wordlist")
            return params

        return self.COMMON_PARAMS

    def _is_interesting_param(self, param: str) -> bool:
        """Check if parameter is interesting."""
        param_lower = param.lower()
        return any(p in param_lower for p in self.INTERESTING_PARAMS)

    def _get_interesting_reason(self, param: str) -> str:
        """Get reason why parameter is interesting."""
        param_lower = param.lower()
        for p in self.INTERESTING_PARAMS:
            if p in param_lower:
                return f"Contains '{p}' pattern"
        return ""

    def _tool_exists(self, tool: str) -> bool:
        """Check if a tool is available in PATH."""
        try:
            subprocess.run(["which", tool], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"parameters_{self.target_domain}")

        # Save parameters list
        txt_path = self.output_dir / f"parameters_{self.target_domain}.txt"
        with open(txt_path, "w") as f:
            for param in sorted(set(p.name for p in self.discovered.values())):
                f.write(f"{param}\n")
        paths["txt"] = str(txt_path)

        # Save detailed JSON
        detailed_path = self.output_dir / f"parameters_{self.target_domain}_detailed.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "total": len(self.discovered),
                    "parameters": [p.to_dict() for p in self.discovered.values()],
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="Hidden parameter discovery"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-w", "--wordlist", help="Parameter wordlist")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=30, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-m", "--methods", default="GET", help="HTTP methods (comma-separated)")
    parser.add_argument("--no-arjun", action="store_true", help="Disable Arjun (use native)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    methods = [m.strip().upper() for m in args.methods.split(",")]

    discovery = ParameterDiscovery(
        target=args.target,
        output_dir=args.output,
        wordlist=args.wordlist,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        methods=methods,
        use_arjun=not args.no_arjun,
        verbose=args.verbose,
    )

    result = await discovery.discover()
    paths = discovery.save_results(result)

    print(f"\n{'='*60}")
    print(f"Parameter Discovery Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Parameters Found: {len(discovery.discovered)}")
    print(f"Interesting Parameters: {result.stats.get('interesting_params', 0)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    # Show interesting parameters
    interesting = [p for p in discovery.discovered.values() if p.interesting]
    if interesting:
        print(f"\n*** INTERESTING PARAMETERS ***")
        for param in interesting[:10]:
            print(f"  {param.name} ({param.location}) - {param.reason}")


if __name__ == "__main__":
    asyncio.run(main())

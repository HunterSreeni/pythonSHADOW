#!/usr/bin/env python3
"""
Race Condition testing module.

Usage:
    python race_condition.py --target https://example.com/api/transfer --output results/
"""

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("race_condition")


@dataclass
class RaceConditionVuln:
    """Represents a race condition vulnerability."""

    url: str
    vuln_type: str
    description: str
    evidence: str
    successful_requests: int = 0
    total_requests: int = 0
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "successful_requests": self.successful_requests,
            "total_requests": self.total_requests,
            "confidence": self.confidence,
        }


@dataclass
class RaceResult:
    """Result from a single race request."""

    status: int
    body: str
    response_time: float
    request_index: int


class RaceConditionTester:
    """
    Race Condition vulnerability tester.

    Features:
    - Time-of-check to time-of-use (TOCTOU) testing
    - Parallel request race conditions
    - Double-spending detection
    - Coupon/promo code reuse
    - Account balance manipulation
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        auth_header: Optional[str] = None,
        concurrent_requests: int = 10,
        request_data: Optional[Dict] = None,
        request_method: str = "POST",
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.auth_header = auth_header
        self.concurrent_requests = concurrent_requests
        self.request_data = request_data or {}
        self.request_method = request_method.upper()
        self.verbose = verbose

        self.vulnerabilities: List[RaceConditionVuln] = []
        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

        self.race_results: List[RaceResult] = []

    async def test(self) -> ScanResult:
        """Run race condition tests."""
        result = ScanResult(
            tool="race_condition",
            target=self.target,
            config={
                "timeout": self.timeout,
                "concurrent_requests": self.concurrent_requests,
            },
        )

        logger.info(f"Starting race condition testing for: {self.target}")

        try:
            # Run parallel request race
            await self._test_parallel_race()

            # Analyze results
            self._analyze_results()

            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
                "total_requests": len(self.race_results),
                "successful_requests": sum(1 for r in self.race_results if 200 <= r.status < 300),
            }

            for vuln in self.vulnerabilities:
                severity_map = {
                    "high": Severity.HIGH,
                    "critical": Severity.CRITICAL,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }
                severity = severity_map.get(vuln.confidence, Severity.HIGH)

                result.add_finding(Finding(
                    title=f"Race Condition: {vuln.vuln_type}",
                    severity=severity,
                    description=vuln.description,
                    url=vuln.url,
                    evidence=vuln.evidence,
                    metadata={
                        "successful_requests": vuln.successful_requests,
                        "total_requests": vuln.total_requests,
                    },
                    cwe_id="CWE-362",
                    remediation="Implement proper locking mechanisms, use database transactions, or implement idempotency keys.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _test_parallel_race(self):
        """Test for race conditions using parallel requests."""
        logger.info(f"Launching {self.concurrent_requests} parallel requests...")

        headers = {}
        if self.auth_header:
            headers["Authorization"] = self.auth_header

        # Create barrier for synchronized start
        barrier = asyncio.Barrier(self.concurrent_requests)

        async def make_request(index: int) -> RaceResult:
            """Make a single request after barrier synchronization."""
            async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
                # Wait for all requests to be ready
                await barrier.wait()

                start_time = time.time()

                try:
                    if self.request_method == "POST":
                        response = await client.post(
                            self.target,
                            headers=headers,
                            data=self.request_data
                        )
                    elif self.request_method == "PUT":
                        response = await client.put(
                            self.target,
                            headers=headers,
                            data=self.request_data
                        )
                    elif self.request_method == "DELETE":
                        response = await client.delete(
                            self.target,
                            headers=headers
                        )
                    else:
                        response = await client.get(
                            self.target,
                            headers=headers
                        )

                    response_time = time.time() - start_time

                    return RaceResult(
                        status=response.status,
                        body=response.body[:500],
                        response_time=response_time,
                        request_index=index,
                    )

                except Exception as e:
                    response_time = time.time() - start_time
                    return RaceResult(
                        status=0,
                        body=str(e),
                        response_time=response_time,
                        request_index=index,
                    )

        # Launch all requests simultaneously
        tasks = [make_request(i) for i in range(self.concurrent_requests)]
        self.race_results = await asyncio.gather(*tasks)

        logger.info(f"Completed {len(self.race_results)} requests")

    def _analyze_results(self):
        """Analyze race condition test results."""
        logger.info("Analyzing race condition results...")

        if not self.race_results:
            return

        # Count successful responses
        successful = [r for r in self.race_results if 200 <= r.status < 300]
        failed = [r for r in self.race_results if r.status >= 400]
        errors = [r for r in self.race_results if r.status == 0]

        logger.info(f"Results: {len(successful)} success, {len(failed)} failed, {len(errors)} errors")

        # Analyze for race conditions
        # Pattern 1: Multiple successes when only one should succeed
        if len(successful) > 1:
            # Check if responses indicate the same action was performed multiple times
            unique_responses = set(r.body for r in successful)

            if len(unique_responses) == 1:
                # All successful responses are identical
                vuln = RaceConditionVuln(
                    url=self.target,
                    vuln_type="duplicate_action",
                    description=f"Race condition detected: {len(successful)} identical successful responses",
                    evidence=f"All {len(successful)} requests returned identical success responses",
                    successful_requests=len(successful),
                    total_requests=len(self.race_results),
                    confidence="high",
                )
                self.vulnerabilities.append(vuln)
                logger.info("Detected duplicate action race condition")

            else:
                # Different success responses might indicate inconsistent state
                vuln = RaceConditionVuln(
                    url=self.target,
                    vuln_type="inconsistent_state",
                    description=f"Potential race condition: {len(successful)} successes with {len(unique_responses)} unique responses",
                    evidence=f"Responses varied, indicating possible inconsistent state handling",
                    successful_requests=len(successful),
                    total_requests=len(self.race_results),
                    confidence="medium",
                )
                self.vulnerabilities.append(vuln)
                logger.info("Detected potential inconsistent state")

        # Pattern 2: Check for timing-based vulnerabilities
        if successful:
            response_times = [r.response_time for r in successful]
            avg_time = sum(response_times) / len(response_times)
            min_time = min(response_times)
            max_time = max(response_times)

            # Large variance in response times can indicate lock contention
            if max_time > min_time * 3 and len(successful) > 3:
                vuln = RaceConditionVuln(
                    url=self.target,
                    vuln_type="timing_variance",
                    description="High timing variance suggests lock contention or race window",
                    evidence=f"Response times: min={min_time:.3f}s, max={max_time:.3f}s, avg={avg_time:.3f}s",
                    successful_requests=len(successful),
                    total_requests=len(self.race_results),
                    confidence="low",
                )
                self.vulnerabilities.append(vuln)
                logger.info("Detected timing variance pattern")

        # Pattern 3: Check for financial/counter indicators in responses
        financial_indicators = [
            "balance", "amount", "total", "credit", "debit",
            "points", "count", "quantity", "stock", "inventory",
        ]

        for result in successful:
            body_lower = result.body.lower()
            if any(ind in body_lower for ind in financial_indicators):
                # Found financial-related response
                if len(successful) > 1:
                    vuln = RaceConditionVuln(
                        url=self.target,
                        vuln_type="potential_double_spending",
                        description="Race condition on financial/counter operation detected",
                        evidence=f"Financial indicators in response with {len(successful)} successes",
                        successful_requests=len(successful),
                        total_requests=len(self.race_results),
                        confidence="high",
                    )
                    self.vulnerabilities.append(vuln)
                    logger.info("Detected potential double-spending vulnerability")
                    break

        # Pattern 4: All requests succeeded (no proper concurrency control)
        if len(successful) == len(self.race_results) and len(self.race_results) > 5:
            vuln = RaceConditionVuln(
                url=self.target,
                vuln_type="no_concurrency_control",
                description="No concurrency control detected - all parallel requests succeeded",
                evidence=f"All {len(self.race_results)} requests returned success",
                successful_requests=len(successful),
                total_requests=len(self.race_results),
                confidence="medium",
            )
            self.vulnerabilities.append(vuln)
            logger.info("No concurrency control detected")

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"race_condition_{self.target_domain}")

        vuln_path = self.output_dir / f"race_condition_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp_now(),
                "concurrent_requests": self.concurrent_requests,
                "results_summary": {
                    "total": len(self.race_results),
                    "successful": sum(1 for r in self.race_results if 200 <= r.status < 300),
                    "failed": sum(1 for r in self.race_results if r.status >= 400),
                    "errors": sum(1 for r in self.race_results if r.status == 0),
                },
                "individual_results": [
                    {
                        "index": r.request_index,
                        "status": r.status,
                        "response_time": r.response_time,
                        "body_preview": r.body[:100],
                    }
                    for r in self.race_results
                ],
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            }, f, indent=2)
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Race Condition tester")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-m", "--method", default="POST", help="HTTP method")
    parser.add_argument("-d", "--data", help="Request data as JSON string")
    parser.add_argument("-n", "--concurrent", type=int, default=10, help="Number of concurrent requests")
    parser.add_argument("--auth-header", help="Authorization header value")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    request_data = {}
    if args.data:
        try:
            request_data = json.loads(args.data)
        except json.JSONDecodeError:
            # Try key=value format
            for pair in args.data.split("&"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    request_data[key] = value

    tester = RaceConditionTester(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        auth_header=args.auth_header,
        concurrent_requests=args.concurrent,
        request_data=request_data,
        request_method=args.method,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"Race Condition Testing Complete")
    print(f"{'='*60}")
    print(f"Total Requests: {len(tester.race_results)}")
    print(f"Vulnerabilities: {len(tester.vulnerabilities)}")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""
Insecure Direct Object Reference (IDOR) testing module.

Usage:
    python idor_tester.py --target https://example.com/api/user/123 --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("idor_tester")


@dataclass
class IDORVulnerability:
    """Represents a discovered IDOR vulnerability."""

    url: str
    parameter: str
    method: str
    original_value: str
    test_value: str
    evidence: str
    response_diff: Dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"
    data_exposed: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "original_value": self.original_value,
            "test_value": self.test_value,
            "evidence": self.evidence[:500] if self.evidence else "",
            "response_diff": self.response_diff,
            "confidence": self.confidence,
            "data_exposed": self.data_exposed,
        }


class IDORTester:
    """
    Insecure Direct Object Reference vulnerability tester.

    Features:
    - Numeric ID manipulation
    - UUID/GUID testing
    - Horizontal privilege escalation
    - Vertical privilege escalation
    - Response comparison analysis
    """

    # Common ID parameter names
    ID_PARAMS = [
        "id", "user_id", "userId", "uid", "user",
        "account_id", "accountId", "account",
        "profile_id", "profileId", "profile",
        "order_id", "orderId", "order",
        "doc_id", "docId", "document_id", "documentId",
        "file_id", "fileId", "file",
        "invoice_id", "invoiceId", "invoice",
        "item_id", "itemId", "item",
        "record_id", "recordId", "record",
        "ref", "reference", "ref_id",
        "no", "number", "num",
    ]

    # Test values for numeric IDs
    NUMERIC_TEST_VALUES = [
        "1", "2", "0", "-1", "99999",
        "100", "1000", "admin", "root",
    ]

    # Patterns indicating sensitive data exposure
    SENSITIVE_PATTERNS = [
        r"email.*@",
        r"password",
        r"ssn|social.?security",
        r"credit.?card|card.?number",
        r"phone|mobile|tel",
        r"address|street|city",
        r"dob|date.?of.?birth|birthday",
        r"salary|income|payment",
        r"bank|account.?number|routing",
        r"api.?key|secret|token",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 10,
        auth_headers: Optional[Dict[str, str]] = None,
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
        self.auth_headers = auth_headers or {}
        self.test_params = test_params
        self.methods = methods or ["GET"]
        self.verbose = verbose

        self.vulnerabilities: List[IDORVulnerability] = []
        self.baseline_response: Optional[HTTPResponse] = None
        self.id_params_found: List[str] = []

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run IDOR tests and return results."""
        result = ScanResult(
            tool="idor_tester",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "methods": self.methods,
            },
        )

        logger.info(f"Starting IDOR testing for: {self.target}")

        try:
            # Get baseline response
            await self._get_baseline()

            # Detect ID parameters
            await self._detect_id_params()

            # Test specified or detected params
            test_params = self.test_params or self.id_params_found

            if not test_params:
                # Try path-based IDOR
                await self._test_path_based_idor()
            else:
                logger.info(f"Testing parameters: {test_params}")

                for param in test_params:
                    await self._test_parameter_idor(param)

            # Statistics
            result.stats = {
                "parameters_tested": len(test_params) if test_params else 0,
                "path_segments_tested": self._count_path_segments(),
                "vulnerabilities_found": len(self.vulnerabilities),
                "by_confidence": self._count_by_confidence(),
            }

            # Add findings
            for vuln in self.vulnerabilities:
                severity = Severity.HIGH
                if vuln.confidence == "high":
                    severity = Severity.CRITICAL
                elif vuln.confidence == "low":
                    severity = Severity.MEDIUM

                result.add_finding(Finding(
                    title=f"IDOR: {vuln.parameter}",
                    severity=severity,
                    description=f"Insecure Direct Object Reference allowing access to other users' data",
                    url=vuln.url,
                    parameter=vuln.parameter,
                    evidence=vuln.evidence,
                    metadata={
                        "original_value": vuln.original_value,
                        "test_value": vuln.test_value,
                        "confidence": vuln.confidence,
                        "data_exposed": vuln.data_exposed,
                    },
                    cwe_id="CWE-639",
                    remediation="Implement proper authorization checks. Validate that the authenticated user has access to the requested resource.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _get_baseline(self):
        """Get baseline response with original ID."""
        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            headers=self.auth_headers,
        ) as client:
            self.baseline_response = await client.get(self.target)
            logger.info(f"Baseline: status={self.baseline_response.status}, length={len(self.baseline_response.body)}")

    async def _detect_id_params(self):
        """Detect potential ID parameters in URL."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        for param in params.keys():
            param_lower = param.lower()
            if any(id_name in param_lower for id_name in self.ID_PARAMS):
                self.id_params_found.append(param)

            # Check if value looks like an ID
            value = params[param][0]
            if self._looks_like_id(value):
                if param not in self.id_params_found:
                    self.id_params_found.append(param)

        logger.info(f"Detected ID parameters: {self.id_params_found}")

    def _looks_like_id(self, value: str) -> bool:
        """Check if value looks like an ID."""
        # Numeric ID
        if value.isdigit():
            return True

        # UUID/GUID
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if re.match(uuid_pattern, value, re.IGNORECASE):
            return True

        # Base64-encoded ID
        if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) >= 8:
            return True

        # Alphanumeric ID
        if re.match(r'^[a-zA-Z0-9]{8,}$', value):
            return True

        return False

    async def _test_parameter_idor(self, param: str):
        """Test IDOR on a specific parameter."""
        logger.info(f"Testing IDOR on parameter: {param}")

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if param not in params:
            logger.warning(f"Parameter {param} not found in URL")
            return

        original_value = params[param][0]

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            headers=self.auth_headers,
            max_retries=1,
        ) as client:
            # Generate test values
            test_values = self._generate_test_values(original_value)

            for test_value in test_values:
                if test_value == original_value:
                    continue

                modified_params = params.copy()
                modified_params[param] = [test_value]
                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    response = await client.get(test_url)

                    # Analyze response for IDOR
                    is_vulnerable, evidence, data_exposed = self._analyze_idor_response(
                        response, original_value, test_value
                    )

                    if is_vulnerable:
                        vuln = IDORVulnerability(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            original_value=original_value,
                            test_value=test_value,
                            evidence=evidence,
                            confidence=self._determine_confidence(response, evidence),
                            data_exposed=data_exposed,
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found IDOR: {param} (original: {original_value}, test: {test_value})")

                except Exception as e:
                    logger.debug(f"Error testing value {test_value}: {e}")

    async def _test_path_based_idor(self):
        """Test IDOR in URL path segments."""
        logger.info("Testing path-based IDOR...")

        parsed = urlparse(self.target)
        path_parts = parsed.path.split('/')

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            headers=self.auth_headers,
            max_retries=1,
        ) as client:
            for i, part in enumerate(path_parts):
                if self._looks_like_id(part):
                    logger.info(f"Testing path segment: {part}")

                    test_values = self._generate_test_values(part)

                    for test_value in test_values:
                        if test_value == part:
                            continue

                        new_parts = path_parts.copy()
                        new_parts[i] = test_value
                        new_path = '/'.join(new_parts)

                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, new_path,
                            parsed.params, parsed.query, parsed.fragment
                        ))

                        try:
                            response = await client.get(test_url)

                            is_vulnerable, evidence, data_exposed = self._analyze_idor_response(
                                response, part, test_value
                            )

                            if is_vulnerable:
                                vuln = IDORVulnerability(
                                    url=self.target,
                                    parameter=f"path[{i}]",
                                    method="GET",
                                    original_value=part,
                                    test_value=test_value,
                                    evidence=evidence,
                                    confidence=self._determine_confidence(response, evidence),
                                    data_exposed=data_exposed,
                                )
                                self.vulnerabilities.append(vuln)
                                logger.info(f"Found path-based IDOR: segment {i}")

                        except Exception as e:
                            logger.debug(f"Error testing path value {test_value}: {e}")

    def _generate_test_values(self, original: str) -> List[str]:
        """Generate test values based on original value type."""
        test_values = []

        # Numeric ID
        if original.isdigit():
            num = int(original)
            test_values.extend([
                str(num - 1),
                str(num + 1),
                str(num - 10),
                str(num + 10),
                "1", "0", "-1",
            ])

        # UUID
        elif re.match(r'^[0-9a-f-]{36}$', original, re.IGNORECASE):
            # Modify last character
            test_values.append(original[:-1] + ('0' if original[-1] != '0' else '1'))
            # Common test UUIDs
            test_values.extend([
                "00000000-0000-0000-0000-000000000000",
                "00000000-0000-0000-0000-000000000001",
            ])

        # Alphanumeric
        else:
            test_values.extend(self.NUMERIC_TEST_VALUES)

        return list(set(test_values))

    def _analyze_idor_response(
        self, response: HTTPResponse, original: str, test_value: str
    ) -> Tuple[bool, str, str]:
        """Analyze response for IDOR indicators."""
        if not self.baseline_response:
            return False, "", ""

        # Check for successful response with different data
        if response.status == 200:
            # Different content length suggests different data
            baseline_len = len(self.baseline_response.body)
            response_len = len(response.body)

            if response_len > 0 and baseline_len > 0:
                # Significant content difference
                if abs(response_len - baseline_len) > 50:
                    # Check if response contains different user data
                    if original in self.baseline_response.body and original not in response.body:
                        # Check for sensitive data
                        data_exposed = self._check_sensitive_data(response.body)
                        return True, f"Different user data returned (length diff: {response_len - baseline_len})", data_exposed

                # Check if test value appears in response (different object accessed)
                if test_value in response.body and test_value not in self.baseline_response.body:
                    data_exposed = self._check_sensitive_data(response.body)
                    return True, f"Test ID {test_value} appears in response", data_exposed

            # Same structure but different values
            if self._has_different_values(response.body):
                data_exposed = self._check_sensitive_data(response.body)
                return True, "Response contains different object data", data_exposed

        # Check for error-based detection (should have been 403/404)
        elif response.status in [200, 201]:
            if self.baseline_response.status in [403, 404]:
                return True, f"Status changed from {self.baseline_response.status} to {response.status}", ""

        return False, "", ""

    def _has_different_values(self, body: str) -> bool:
        """Check if response has different values than baseline."""
        if not self.baseline_response:
            return False

        # Simple heuristic: check for different JSON values
        try:
            baseline_data = json.loads(self.baseline_response.body)
            response_data = json.loads(body)

            if isinstance(baseline_data, dict) and isinstance(response_data, dict):
                # Check if keys match but values differ
                common_keys = set(baseline_data.keys()) & set(response_data.keys())
                for key in common_keys:
                    if baseline_data[key] != response_data[key]:
                        return True

        except json.JSONDecodeError:
            pass

        return False

    def _check_sensitive_data(self, body: str) -> str:
        """Check for sensitive data patterns in response."""
        found = []
        for pattern in self.SENSITIVE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                found.append(pattern.replace(r"\.?", " ").replace("|", "/"))

        return ", ".join(found[:3]) if found else ""

    def _determine_confidence(self, response: HTTPResponse, evidence: str) -> str:
        """Determine confidence level of IDOR finding."""
        if "different user data" in evidence.lower():
            return "high"
        if "test id" in evidence.lower() and "appears in response" in evidence.lower():
            return "high"
        if response.status == 200:
            return "medium"
        return "low"

    def _count_path_segments(self) -> int:
        """Count testable path segments."""
        parsed = urlparse(self.target)
        return sum(1 for part in parsed.path.split('/') if self._looks_like_id(part))

    def _count_by_confidence(self) -> Dict[str, int]:
        """Count vulnerabilities by confidence."""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.confidence] = counts.get(vuln.confidence, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"idor_{self.target_domain}")

        vuln_path = self.output_dir / f"idor_vulns_{self.target_domain}.json"
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
        description="Insecure Direct Object Reference (IDOR) vulnerability tester"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL with ID parameter")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--params", help="Parameters to test (comma-separated)")
    parser.add_argument("--auth-header", help="Authorization header value")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    test_params = args.params.split(",") if args.params else None
    auth_headers = {"Authorization": args.auth_header} if args.auth_header else {}

    tester = IDORTester(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        auth_headers=auth_headers,
        test_params=test_params,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"IDOR Testing Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Vulnerabilities Found: {len(tester.vulnerabilities)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if tester.vulnerabilities:
        print(f"\n*** IDOR VULNERABILITIES FOUND ***")
        for vuln in tester.vulnerabilities:
            print(f"  [{vuln.confidence.upper()}] {vuln.parameter}: {vuln.original_value} -> {vuln.test_value}")
            if vuln.data_exposed:
                print(f"      Exposed: {vuln.data_exposed}")


if __name__ == "__main__":
    asyncio.run(main())

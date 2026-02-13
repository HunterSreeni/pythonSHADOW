#!/usr/bin/env python3
"""
Access Control testing module.

Usage:
    python access_control.py --target https://example.com/api --output results/
"""

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("access_control")


@dataclass
class AccessControlVuln:
    """Represents an access control vulnerability."""

    url: str
    vuln_type: str
    method: str
    description: str
    evidence: str
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "method": self.method,
            "description": self.description,
            "evidence": self.evidence[:500],
            "confidence": self.confidence,
        }


class AccessControlTester:
    """
    Access Control vulnerability tester.

    Features:
    - HTTP method override testing
    - Forced browsing detection
    - Authentication bypass testing
    - Path traversal in endpoints
    """

    SENSITIVE_ENDPOINTS = [
        "/api/users", "/api/admin", "/api/config",
        "/users", "/admin", "/settings", "/config",
        "/private", "/internal", "/debug", "/backup",
    ]

    METHOD_OVERRIDES = [
        ("X-HTTP-Method-Override", "GET"),
        ("X-HTTP-Method", "GET"),
        ("X-Method-Override", "GET"),
        ("_method", "GET"),
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        proxy: Optional[str] = None,
        timeout: int = 30,
        auth_header: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.proxy = proxy
        self.timeout = timeout
        self.auth_header = auth_header
        self.verbose = verbose

        self.vulnerabilities: List[AccessControlVuln] = []
        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run access control tests."""
        result = ScanResult(
            tool="access_control",
            target=self.target,
            config={"timeout": self.timeout},
        )

        logger.info(f"Starting access control testing for: {self.target}")

        try:
            # Test forced browsing
            await self._test_forced_browsing()

            # Test method override
            await self._test_method_override()

            # Test unauthenticated access
            await self._test_unauth_access()

            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
            }

            for vuln in self.vulnerabilities:
                result.add_finding(Finding(
                    title=f"Access Control: {vuln.vuln_type}",
                    severity=Severity.HIGH,
                    description=vuln.description,
                    url=vuln.url,
                    evidence=vuln.evidence,
                    cwe_id="CWE-284",
                    remediation="Implement proper access control checks on all endpoints.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _test_forced_browsing(self):
        """Test for forced browsing vulnerabilities."""
        logger.info("Testing forced browsing...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for endpoint in self.SENSITIVE_ENDPOINTS:
                url = f"{self.target.rstrip('/')}{endpoint}"
                try:
                    response = await client.get(url)
                    if response.status == 200:
                        vuln = AccessControlVuln(
                            url=url,
                            vuln_type="forced_browsing",
                            method="GET",
                            description=f"Sensitive endpoint accessible: {endpoint}",
                            evidence=response.body[:200],
                            confidence="medium",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found forced browsing: {endpoint}")
                except Exception as e:
                    logger.debug(f"Error: {e}")

    async def _test_method_override(self):
        """Test HTTP method override bypasses."""
        logger.info("Testing method override...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            # Test POST with method override to GET
            for header_name, override_method in self.METHOD_OVERRIDES:
                try:
                    response = await client.post(
                        self.target,
                        headers={header_name: override_method},
                        data={}
                    )
                    if response.status == 200:
                        vuln = AccessControlVuln(
                            url=self.target,
                            vuln_type="method_override",
                            method="POST",
                            description=f"Method override via {header_name}",
                            evidence=f"Header: {header_name}: {override_method}",
                            confidence="medium",
                        )
                        self.vulnerabilities.append(vuln)
                except Exception as e:
                    logger.debug(f"Error: {e}")

    async def _test_unauth_access(self):
        """Test unauthenticated access to protected resources."""
        logger.info("Testing unauthenticated access...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            response = await client.get(self.target)

            if response.status == 200 and self.auth_header:
                # Compare with authenticated request
                auth_response = await client.get(
                    self.target,
                    headers={"Authorization": self.auth_header}
                )
                if auth_response.body == response.body:
                    vuln = AccessControlVuln(
                        url=self.target,
                        vuln_type="missing_auth",
                        method="GET",
                        description="Protected resource accessible without authentication",
                        evidence="Same response with and without auth",
                        confidence="high",
                    )
                    self.vulnerabilities.append(vuln)

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results."""
        paths = self.result_manager.save(result, f"access_control_{self.target_domain}")

        vuln_path = self.output_dir / f"access_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp_now(),
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            }, f, indent=2)
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Access Control tester")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--auth-header", help="Authorization header")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    tester = AccessControlTester(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        auth_header=args.auth_header,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\nAccess Control Testing Complete")
    print(f"Vulnerabilities: {len(tester.vulnerabilities)}")


if __name__ == "__main__":
    asyncio.run(main())

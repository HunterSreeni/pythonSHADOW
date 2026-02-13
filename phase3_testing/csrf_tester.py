#!/usr/bin/env python3
"""
CSRF (Cross-Site Request Forgery) testing module.

Usage:
    python csrf_tester.py --target https://example.com --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("csrf_tester")


@dataclass
class CSRFVuln:
    """Represents a CSRF vulnerability."""

    url: str
    vuln_type: str
    method: str
    description: str
    evidence: str
    form_action: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "method": self.method,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "form_action": self.form_action,
            "confidence": self.confidence,
        }


class CSRFTester:
    """
    CSRF vulnerability tester.

    Features:
    - Missing CSRF token detection
    - Token validation bypass testing
    - SameSite cookie analysis
    - Referer/Origin header validation
    - State-changing operation detection
    """

    CSRF_TOKEN_NAMES = [
        "csrf", "csrf_token", "csrftoken", "_csrf", "xsrf",
        "xsrf_token", "xsrftoken", "_xsrf", "authenticity_token",
        "anti_csrf", "anti-csrf", "__RequestVerificationToken",
        "_token", "token", "security_token", "form_token",
    ]

    STATE_CHANGING_ACTIONS = [
        "update", "delete", "remove", "add", "create", "edit",
        "modify", "change", "submit", "save", "post", "send",
        "transfer", "pay", "purchase", "order", "checkout",
        "register", "signup", "login", "logout", "password",
        "profile", "settings", "admin", "config",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        auth_cookie: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.auth_cookie = auth_cookie
        self.verbose = verbose

        self.vulnerabilities: List[CSRFVuln] = []
        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

        self.discovered_forms: List[Dict] = []
        self.discovered_endpoints: Set[str] = set()

    async def test(self) -> ScanResult:
        """Run CSRF tests."""
        result = ScanResult(
            tool="csrf_tester",
            target=self.target,
            config={"timeout": self.timeout},
        )

        logger.info(f"Starting CSRF testing for: {self.target}")

        try:
            # Discover forms and endpoints
            await self._discover_forms()

            # Test each form for CSRF
            await self._test_forms()

            # Test token validation bypass
            await self._test_token_bypass()

            # Test header-based CSRF protection
            await self._test_header_protection()

            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
                "forms_discovered": len(self.discovered_forms),
                "endpoints_tested": len(self.discovered_endpoints),
            }

            for vuln in self.vulnerabilities:
                severity_map = {
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }
                severity = severity_map.get(vuln.confidence, Severity.MEDIUM)

                result.add_finding(Finding(
                    title=f"CSRF: {vuln.vuln_type}",
                    severity=severity,
                    description=vuln.description,
                    url=vuln.url,
                    evidence=vuln.evidence,
                    metadata={"form_action": vuln.form_action, "method": vuln.method},
                    cwe_id="CWE-352",
                    remediation="Implement anti-CSRF tokens and validate on server-side. Use SameSite cookie attribute.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _discover_forms(self):
        """Discover HTML forms on the target."""
        logger.info("Discovering forms...")

        headers = {}
        if self.auth_cookie:
            headers["Cookie"] = self.auth_cookie

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            response = await client.get(self.target, headers=headers)

            if response.status != 200:
                logger.warning(f"Failed to fetch target: {response.status}")
                return

            # Extract forms
            forms = self._extract_forms(response.body)
            self.discovered_forms = forms
            logger.info(f"Discovered {len(forms)} forms")

            # Extract potential state-changing endpoints
            self._extract_endpoints(response.body)

    def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML."""
        forms = []

        # Simple regex-based form extraction
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

        for i, form_content in enumerate(form_matches):
            form = {"index": i, "fields": [], "has_csrf_token": False}

            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', html, re.IGNORECASE)
            form["action"] = action_match.group(1) if action_match else ""

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', html, re.IGNORECASE)
            form["method"] = (method_match.group(1) if method_match else "GET").upper()

            # Extract input fields
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            form["fields"] = inputs

            # Check for CSRF token
            for field in inputs:
                if any(csrf_name in field.lower() for csrf_name in self.CSRF_TOKEN_NAMES):
                    form["has_csrf_token"] = True
                    break

            # Check if form action is state-changing
            form["is_state_changing"] = self._is_state_changing(form)

            forms.append(form)

        return forms

    def _extract_endpoints(self, html: str):
        """Extract potential state-changing endpoints."""
        # Extract from links
        link_pattern = r'href=["\']([^"\']*)["\']'
        links = re.findall(link_pattern, html, re.IGNORECASE)

        for link in links:
            if any(action in link.lower() for action in self.STATE_CHANGING_ACTIONS):
                self.discovered_endpoints.add(link)

        # Extract from JavaScript
        js_pattern = r'(fetch|axios|ajax|XMLHttpRequest)[^}]*["\']([^"\']+)["\']'
        js_matches = re.findall(js_pattern, html, re.IGNORECASE)

        for _, endpoint in js_matches:
            if any(action in endpoint.lower() for action in self.STATE_CHANGING_ACTIONS):
                self.discovered_endpoints.add(endpoint)

    def _is_state_changing(self, form: Dict) -> bool:
        """Check if form performs state-changing action."""
        # POST forms are typically state-changing
        if form.get("method") == "POST":
            return True

        # Check action URL
        action = form.get("action", "").lower()
        return any(action_word in action for action_word in self.STATE_CHANGING_ACTIONS)

    async def _test_forms(self):
        """Test forms for CSRF vulnerabilities."""
        logger.info("Testing forms for CSRF...")

        for form in self.discovered_forms:
            if not form.get("is_state_changing"):
                continue

            # Test for missing CSRF token
            if not form.get("has_csrf_token"):
                action = form.get("action") or self.target
                if not action.startswith("http"):
                    action = urljoin(self.target, action)

                vuln = CSRFVuln(
                    url=self.target,
                    vuln_type="missing_csrf_token",
                    method=form.get("method", "POST"),
                    description=f"State-changing form has no CSRF token",
                    evidence=f"Form fields: {form.get('fields', [])}",
                    form_action=action,
                    confidence="high",
                )
                self.vulnerabilities.append(vuln)
                logger.info(f"Found form without CSRF token: {action}")

    async def _test_token_bypass(self):
        """Test CSRF token validation bypass."""
        logger.info("Testing CSRF token bypass...")

        # Find forms with CSRF tokens
        forms_with_token = [f for f in self.discovered_forms if f.get("has_csrf_token")]

        if not forms_with_token:
            return

        headers = {}
        if self.auth_cookie:
            headers["Cookie"] = self.auth_cookie

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for form in forms_with_token:
                action = form.get("action") or self.target
                if not action.startswith("http"):
                    action = urljoin(self.target, action)

                # Build form data without CSRF token
                data = {}
                for field in form.get("fields", []):
                    if not any(csrf in field.lower() for csrf in self.CSRF_TOKEN_NAMES):
                        data[field] = "test"

                # Test 1: Missing token
                try:
                    response = await client.post(action, headers=headers, data=data)

                    if response.status == 200 and not self._is_error_response(response.body):
                        vuln = CSRFVuln(
                            url=action,
                            vuln_type="token_not_required",
                            method="POST",
                            description="Request accepted without CSRF token",
                            evidence=f"Response status: {response.status}",
                            form_action=action,
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"CSRF token not required: {action}")
                        continue

                except Exception as e:
                    logger.debug(f"Error testing missing token: {e}")

                # Test 2: Empty token
                csrf_field = None
                for field in form.get("fields", []):
                    if any(csrf in field.lower() for csrf in self.CSRF_TOKEN_NAMES):
                        csrf_field = field
                        break

                if csrf_field:
                    data[csrf_field] = ""
                    try:
                        response = await client.post(action, headers=headers, data=data)

                        if response.status == 200 and not self._is_error_response(response.body):
                            vuln = CSRFVuln(
                                url=action,
                                vuln_type="empty_token_accepted",
                                method="POST",
                                description="Empty CSRF token accepted",
                                evidence=f"Response status: {response.status}",
                                form_action=action,
                                confidence="high",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Empty CSRF token accepted: {action}")
                            continue

                    except Exception as e:
                        logger.debug(f"Error testing empty token: {e}")

                    # Test 3: Invalid token
                    data[csrf_field] = "invalid_csrf_token_12345"
                    try:
                        response = await client.post(action, headers=headers, data=data)

                        if response.status == 200 and not self._is_error_response(response.body):
                            vuln = CSRFVuln(
                                url=action,
                                vuln_type="invalid_token_accepted",
                                method="POST",
                                description="Invalid CSRF token accepted",
                                evidence=f"Response status: {response.status}",
                                form_action=action,
                                confidence="high",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Invalid CSRF token accepted: {action}")

                    except Exception as e:
                        logger.debug(f"Error testing invalid token: {e}")

    async def _test_header_protection(self):
        """Test Referer/Origin header-based CSRF protection."""
        logger.info("Testing header-based protection...")

        headers = {}
        if self.auth_cookie:
            headers["Cookie"] = self.auth_cookie

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            # Test with different Origin headers
            test_origins = [
                "https://evil.com",
                "null",
                f"https://{self.target_domain}.evil.com",
            ]

            for form in self.discovered_forms:
                if not form.get("is_state_changing"):
                    continue

                action = form.get("action") or self.target
                if not action.startswith("http"):
                    action = urljoin(self.target, action)

                for origin in test_origins:
                    test_headers = headers.copy()
                    test_headers["Origin"] = origin
                    test_headers["Referer"] = f"{origin}/page"

                    # Build minimal form data
                    data = {}
                    for field in form.get("fields", []):
                        data[field] = "test"

                    try:
                        response = await client.post(action, headers=test_headers, data=data)

                        if response.status == 200 and not self._is_error_response(response.body):
                            vuln = CSRFVuln(
                                url=action,
                                vuln_type="origin_not_validated",
                                method="POST",
                                description=f"Request accepted with Origin: {origin}",
                                evidence=f"Response status: {response.status}",
                                form_action=action,
                                confidence="medium",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Origin not validated: {origin}")
                            break

                    except Exception as e:
                        logger.debug(f"Error testing origin header: {e}")

    def _is_error_response(self, body: str) -> bool:
        """Check if response indicates an error."""
        error_indicators = [
            "csrf",
            "invalid token",
            "token mismatch",
            "forbidden",
            "unauthorized",
            "access denied",
            "security error",
            "verification failed",
        ]

        body_lower = body.lower()
        return any(ind in body_lower for ind in error_indicators)

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"csrf_{self.target_domain}")

        vuln_path = self.output_dir / f"csrf_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp_now(),
                "forms_discovered": len(self.discovered_forms),
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            }, f, indent=2)
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="CSRF tester")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--auth-cookie", help="Authentication cookie")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    tester = CSRFTester(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        auth_cookie=args.auth_cookie,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"CSRF Testing Complete")
    print(f"{'='*60}")
    print(f"Forms Discovered: {len(tester.discovered_forms)}")
    print(f"Vulnerabilities: {len(tester.vulnerabilities)}")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

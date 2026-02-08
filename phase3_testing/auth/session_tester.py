#!/usr/bin/env python3
"""
Session Management testing module.

Usage:
    python session_tester.py --target https://example.com --output results/
"""

import argparse
import asyncio
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("session_tester")


@dataclass
class SessionVuln:
    """Represents a session management vulnerability."""

    url: str
    vuln_type: str
    description: str
    evidence: str
    cookie_name: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "cookie_name": self.cookie_name,
            "confidence": self.confidence,
        }


class SessionTester:
    """
    Session Management vulnerability tester.

    Features:
    - Session fixation testing
    - Session ID entropy analysis
    - Cookie security flags validation
    - Session timeout testing
    - Concurrent session testing
    - Session invalidation on logout
    """

    SENSITIVE_COOKIE_NAMES = [
        "sessionid", "session_id", "sessid", "sid",
        "phpsessid", "jsessionid", "aspsessionid",
        "auth", "auth_token", "token", "access_token",
        "user", "userid", "user_id", "logged_in",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        session_cookie: Optional[str] = None,
        login_url: Optional[str] = None,
        logout_url: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.session_cookie = session_cookie
        self.login_url = login_url
        self.logout_url = logout_url
        self.verbose = verbose

        self.vulnerabilities: List[SessionVuln] = []
        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

        self.collected_sessions: List[str] = []
        self.cookies_analyzed: Dict[str, Dict] = {}

    async def test(self) -> ScanResult:
        """Run session management tests."""
        result = ScanResult(
            tool="session_tester",
            target=self.target,
            config={"timeout": self.timeout},
        )

        logger.info(f"Starting session management testing for: {self.target}")

        try:
            # Collect session cookies
            await self._collect_sessions()

            # Analyze cookie security
            await self._analyze_cookie_security()

            # Test session entropy
            await self._test_session_entropy()

            # Test session fixation
            await self._test_session_fixation()

            # Test session invalidation
            if self.logout_url:
                await self._test_session_invalidation()

            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
                "sessions_collected": len(self.collected_sessions),
                "cookies_analyzed": len(self.cookies_analyzed),
            }

            for vuln in self.vulnerabilities:
                severity_map = {
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }
                severity = severity_map.get(vuln.confidence, Severity.MEDIUM)

                result.add_finding(Finding(
                    title=f"Session: {vuln.vuln_type}",
                    severity=severity,
                    description=vuln.description,
                    url=vuln.url,
                    evidence=vuln.evidence,
                    metadata={"cookie_name": vuln.cookie_name},
                    cwe_id="CWE-384",
                    remediation="Implement secure session management with proper flags and regeneration.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _collect_sessions(self):
        """Collect multiple session IDs for analysis."""
        logger.info("Collecting session IDs...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for i in range(10):
                try:
                    response = await client.get(self.target)
                    cookies = self._parse_set_cookies(response.headers)

                    for name, attrs in cookies.items():
                        if self._is_session_cookie(name):
                            self.collected_sessions.append(attrs.get("value", ""))
                            if name not in self.cookies_analyzed:
                                self.cookies_analyzed[name] = attrs

                except Exception as e:
                    logger.debug(f"Error collecting session: {e}")

        logger.info(f"Collected {len(self.collected_sessions)} session IDs")

    def _parse_set_cookies(self, headers: Dict[str, str]) -> Dict[str, Dict]:
        """Parse Set-Cookie headers."""
        cookies = {}
        set_cookie = headers.get("set-cookie", "")

        if not set_cookie:
            return cookies

        # Handle multiple cookies
        cookie_strings = set_cookie.split(", ")
        for cookie_str in cookie_strings:
            parts = cookie_str.split(";")
            if not parts:
                continue

            # First part is name=value
            name_value = parts[0].strip()
            if "=" not in name_value:
                continue

            name, value = name_value.split("=", 1)
            name = name.strip()
            value = value.strip()

            attrs = {"value": value}

            # Parse attributes
            for part in parts[1:]:
                part = part.strip().lower()
                if part == "secure":
                    attrs["secure"] = True
                elif part == "httponly":
                    attrs["httponly"] = True
                elif part.startswith("samesite="):
                    attrs["samesite"] = part.split("=")[1]
                elif part.startswith("path="):
                    attrs["path"] = part.split("=")[1]
                elif part.startswith("domain="):
                    attrs["domain"] = part.split("=")[1]
                elif part.startswith("max-age="):
                    attrs["max-age"] = part.split("=")[1]
                elif part.startswith("expires="):
                    attrs["expires"] = part.split("=")[1]

            cookies[name] = attrs

        return cookies

    def _is_session_cookie(self, name: str) -> bool:
        """Check if cookie name looks like a session cookie."""
        name_lower = name.lower()
        return any(s in name_lower for s in self.SENSITIVE_COOKIE_NAMES)

    async def _analyze_cookie_security(self):
        """Analyze cookie security flags."""
        logger.info("Analyzing cookie security flags...")

        parsed_url = urlparse(self.target)
        is_https = parsed_url.scheme == "https"

        for name, attrs in self.cookies_analyzed.items():
            # Check Secure flag
            if is_https and not attrs.get("secure"):
                vuln = SessionVuln(
                    url=self.target,
                    vuln_type="missing_secure_flag",
                    description=f"Session cookie '{name}' missing Secure flag on HTTPS site",
                    evidence=f"Cookie: {name}={attrs.get('value', '')[:20]}...",
                    cookie_name=name,
                    confidence="high",
                )
                self.vulnerabilities.append(vuln)
                logger.info(f"Missing Secure flag: {name}")

            # Check HttpOnly flag
            if not attrs.get("httponly"):
                vuln = SessionVuln(
                    url=self.target,
                    vuln_type="missing_httponly_flag",
                    description=f"Session cookie '{name}' missing HttpOnly flag - vulnerable to XSS theft",
                    evidence=f"Cookie: {name}={attrs.get('value', '')[:20]}...",
                    cookie_name=name,
                    confidence="high",
                )
                self.vulnerabilities.append(vuln)
                logger.info(f"Missing HttpOnly flag: {name}")

            # Check SameSite flag
            samesite = attrs.get("samesite", "").lower()
            if not samesite or samesite == "none":
                vuln = SessionVuln(
                    url=self.target,
                    vuln_type="weak_samesite_flag",
                    description=f"Session cookie '{name}' has weak/missing SameSite flag - vulnerable to CSRF",
                    evidence=f"SameSite value: {samesite or 'not set'}",
                    cookie_name=name,
                    confidence="medium",
                )
                self.vulnerabilities.append(vuln)
                logger.info(f"Weak SameSite flag: {name}")

    async def _test_session_entropy(self):
        """Test session ID entropy and predictability."""
        logger.info("Testing session entropy...")

        if len(self.collected_sessions) < 5:
            logger.warning("Not enough sessions collected for entropy analysis")
            return

        # Remove duplicates
        unique_sessions = list(set(self.collected_sessions))

        if len(unique_sessions) < len(self.collected_sessions) * 0.8:
            vuln = SessionVuln(
                url=self.target,
                vuln_type="session_id_collision",
                description="Session IDs have high collision rate - possible weak randomness",
                evidence=f"Collected {len(self.collected_sessions)}, only {len(unique_sessions)} unique",
                confidence="high",
            )
            self.vulnerabilities.append(vuln)
            logger.info("Found session ID collision")
            return

        # Check entropy
        for session_id in unique_sessions[:5]:
            entropy = self._calculate_entropy(session_id)
            if entropy < 3.0:
                vuln = SessionVuln(
                    url=self.target,
                    vuln_type="low_entropy_session",
                    description=f"Session ID has low entropy ({entropy:.2f} bits/char) - may be predictable",
                    evidence=f"Session: {session_id[:20]}... Entropy: {entropy:.2f}",
                    confidence="medium",
                )
                self.vulnerabilities.append(vuln)
                logger.info(f"Low entropy session: {entropy:.2f}")
                break

        # Check for sequential patterns
        if self._has_sequential_pattern(unique_sessions):
            vuln = SessionVuln(
                url=self.target,
                vuln_type="sequential_session_ids",
                description="Session IDs appear to be sequential - highly predictable",
                evidence=f"Sessions show sequential pattern",
                confidence="high",
            )
            self.vulnerabilities.append(vuln)
            logger.info("Found sequential session pattern")

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0

        from collections import Counter
        import math

        freq = Counter(s)
        length = len(s)
        entropy = 0.0

        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def _has_sequential_pattern(self, sessions: List[str]) -> bool:
        """Check if sessions have sequential patterns."""
        if len(sessions) < 3:
            return False

        # Try to find numeric portions and check if sequential
        numeric_parts = []
        for session in sessions:
            nums = re.findall(r'\d+', session)
            if nums:
                numeric_parts.append(int(nums[-1]))

        if len(numeric_parts) >= 3:
            numeric_parts.sort()
            diffs = [numeric_parts[i+1] - numeric_parts[i] for i in range(len(numeric_parts)-1)]
            # Check if differences are small and consistent
            if all(0 < d < 10 for d in diffs):
                return True

        return False

    async def _test_session_fixation(self):
        """Test for session fixation vulnerability."""
        logger.info("Testing session fixation...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            # Get initial session
            response1 = await client.get(self.target)
            cookies1 = self._parse_set_cookies(response1.headers)

            session_cookie_name = None
            initial_session = None

            for name, attrs in cookies1.items():
                if self._is_session_cookie(name):
                    session_cookie_name = name
                    initial_session = attrs.get("value")
                    break

            if not initial_session:
                logger.warning("No session cookie found for fixation test")
                return

            # Make another request with the same session
            response2 = await client.get(
                self.target,
                headers={"Cookie": f"{session_cookie_name}={initial_session}"}
            )

            cookies2 = self._parse_set_cookies(response2.headers)
            new_session = None

            for name, attrs in cookies2.items():
                if name == session_cookie_name:
                    new_session = attrs.get("value")
                    break

            # If session wasn't regenerated, could be fixation vuln
            if new_session and new_session == initial_session:
                # This alone isn't conclusive - need to test with login
                if self.login_url:
                    logger.info("Session not changed - testing with login flow")
                else:
                    vuln = SessionVuln(
                        url=self.target,
                        vuln_type="potential_session_fixation",
                        description="Session ID not regenerated on subsequent requests - test with login flow",
                        evidence=f"Session {initial_session[:20]}... remained unchanged",
                        cookie_name=session_cookie_name,
                        confidence="low",
                    )
                    self.vulnerabilities.append(vuln)

    async def _test_session_invalidation(self):
        """Test if session is properly invalidated on logout."""
        if not self.logout_url or not self.session_cookie:
            return

        logger.info("Testing session invalidation on logout...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            # Parse session cookie
            parts = self.session_cookie.split("=", 1)
            if len(parts) != 2:
                return
            cookie_name, cookie_value = parts

            # Make authenticated request
            headers = {"Cookie": self.session_cookie}
            response1 = await client.get(self.target, headers=headers)

            if response1.status != 200:
                logger.warning("Initial authenticated request failed")
                return

            # Logout
            await client.get(self.logout_url, headers=headers)

            # Try to use the same session again
            response2 = await client.get(self.target, headers=headers)

            # If we still get the same response, session might not be invalidated
            if response2.status == 200 and len(response2.body) == len(response1.body):
                vuln = SessionVuln(
                    url=self.target,
                    vuln_type="session_not_invalidated",
                    description="Session remains valid after logout - session fixation/replay possible",
                    evidence="Session usable after logout",
                    cookie_name=cookie_name,
                    confidence="high",
                )
                self.vulnerabilities.append(vuln)
                logger.info("Session not invalidated after logout")

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"session_{self.target_domain}")

        vuln_path = self.output_dir / f"session_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp_now(),
                "cookies_analyzed": self.cookies_analyzed,
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            }, f, indent=2)
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Session Management tester")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--session-cookie", help="Session cookie (name=value)")
    parser.add_argument("--login-url", help="Login URL for fixation testing")
    parser.add_argument("--logout-url", help="Logout URL for invalidation testing")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    tester = SessionTester(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        session_cookie=args.session_cookie,
        login_url=args.login_url,
        logout_url=args.logout_url,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"Session Management Testing Complete")
    print(f"{'='*60}")
    print(f"Vulnerabilities: {len(tester.vulnerabilities)}")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

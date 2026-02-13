#!/usr/bin/env python3
"""
Business Logic vulnerability testing module.

Usage:
    python business_logic.py --target https://example.com/api --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("business_logic")


@dataclass
class BusinessLogicVuln:
    """Represents a business logic vulnerability."""

    url: str
    vuln_type: str
    description: str
    evidence: str
    payload: str = ""
    impact: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "payload": self.payload,
            "impact": self.impact,
            "confidence": self.confidence,
        }


class BusinessLogicTester:
    """
    Business Logic vulnerability tester.

    Features:
    - Price manipulation testing
    - Quantity tampering
    - Coupon/discount abuse
    - Workflow bypass
    - Negative value testing
    - Integer overflow testing
    - Currency manipulation
    """

    PRICE_PARAMS = [
        "price", "amount", "total", "cost", "value", "fee",
        "subtotal", "grand_total", "order_total", "item_price",
        "unit_price", "discount", "tax", "shipping",
    ]

    QUANTITY_PARAMS = [
        "quantity", "qty", "count", "num", "number", "amount",
        "items", "units", "stock", "inventory",
    ]

    DISCOUNT_PARAMS = [
        "discount", "coupon", "promo", "voucher", "code",
        "discount_code", "promo_code", "coupon_code", "gift_card",
        "percent_off", "amount_off", "rebate",
    ]

    STATUS_PARAMS = [
        "status", "state", "step", "stage", "phase",
        "order_status", "payment_status", "verified", "approved",
        "confirmed", "completed", "processed",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        auth_cookie: Optional[str] = None,
        auth_header: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.auth_cookie = auth_cookie
        self.auth_header = auth_header
        self.verbose = verbose

        self.vulnerabilities: List[BusinessLogicVuln] = []
        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

        self.baseline_response: Optional[HTTPResponse] = None

    async def test(self) -> ScanResult:
        """Run business logic tests."""
        result = ScanResult(
            tool="business_logic",
            target=self.target,
            config={"timeout": self.timeout},
        )

        logger.info(f"Starting business logic testing for: {self.target}")

        try:
            # Get baseline response
            await self._get_baseline()

            # Test price manipulation
            await self._test_price_manipulation()

            # Test quantity manipulation
            await self._test_quantity_manipulation()

            # Test negative values
            await self._test_negative_values()

            # Test integer overflow
            await self._test_integer_overflow()

            # Test discount abuse
            await self._test_discount_abuse()

            # Test workflow bypass
            await self._test_workflow_bypass()

            # Test status manipulation
            await self._test_status_manipulation()

            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
            }

            for vuln in self.vulnerabilities:
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }
                severity = severity_map.get(vuln.confidence, Severity.MEDIUM)

                result.add_finding(Finding(
                    title=f"Business Logic: {vuln.vuln_type}",
                    severity=severity,
                    description=vuln.description,
                    url=vuln.url,
                    evidence=vuln.evidence,
                    metadata={
                        "payload": vuln.payload,
                        "impact": vuln.impact,
                    },
                    cwe_id="CWE-840",
                    remediation="Implement server-side validation for all business rules. Never trust client-side values for critical operations.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        headers = {}
        if self.auth_cookie:
            headers["Cookie"] = self.auth_cookie
        if self.auth_header:
            headers["Authorization"] = self.auth_header
        return headers

    async def _get_baseline(self):
        """Get baseline response."""
        logger.info("Getting baseline response...")

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            response = await client.get(self.target, headers=self._get_headers())
            self.baseline_response = response

    async def _test_price_manipulation(self):
        """Test price parameter manipulation."""
        logger.info("Testing price manipulation...")

        manipulation_values = [
            ("0", "zero_price"),
            ("0.01", "minimal_price"),
            ("-1", "negative_price"),
            ("-100", "large_negative"),
            ("0.001", "fractional_price"),
            ("1", "low_price"),
        ]

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for param in self.PRICE_PARAMS:
                for value, test_type in manipulation_values:
                    # Test in URL parameters
                    url = f"{self.target}?{param}={value}"
                    try:
                        response = await client.get(url, headers=self._get_headers())

                        if self._indicates_success(response, "price"):
                            vuln = BusinessLogicVuln(
                                url=url,
                                vuln_type=f"price_manipulation_{test_type}",
                                description=f"Price manipulation accepted: {param}={value}",
                                evidence=response.body[:300],
                                payload=f"{param}={value}",
                                impact="Financial loss through price manipulation",
                                confidence="high" if value in ["0", "-1", "-100"] else "medium",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Price manipulation: {param}={value}")
                            return

                    except Exception as e:
                        logger.debug(f"Error testing price: {e}")

                    # Test in POST body
                    try:
                        response = await client.post(
                            self.target,
                            headers=self._get_headers(),
                            data={param: value}
                        )

                        if self._indicates_success(response, "price"):
                            vuln = BusinessLogicVuln(
                                url=self.target,
                                vuln_type=f"price_manipulation_{test_type}",
                                description=f"Price manipulation via POST: {param}={value}",
                                evidence=response.body[:300],
                                payload=f"POST {param}={value}",
                                impact="Financial loss through price manipulation",
                                confidence="high" if value in ["0", "-1", "-100"] else "medium",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Price manipulation POST: {param}={value}")
                            return

                    except Exception as e:
                        logger.debug(f"Error testing price POST: {e}")

    async def _test_quantity_manipulation(self):
        """Test quantity parameter manipulation."""
        logger.info("Testing quantity manipulation...")

        manipulation_values = [
            ("0", "zero_quantity"),
            ("-1", "negative_quantity"),
            ("-999", "large_negative"),
            ("999999", "large_quantity"),
            ("0.5", "fractional_quantity"),
        ]

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for param in self.QUANTITY_PARAMS:
                for value, test_type in manipulation_values:
                    url = f"{self.target}?{param}={value}"
                    try:
                        response = await client.get(url, headers=self._get_headers())

                        if self._indicates_success(response, "quantity"):
                            vuln = BusinessLogicVuln(
                                url=url,
                                vuln_type=f"quantity_manipulation_{test_type}",
                                description=f"Quantity manipulation accepted: {param}={value}",
                                evidence=response.body[:300],
                                payload=f"{param}={value}",
                                impact="Inventory manipulation or financial loss",
                                confidence="high" if value.startswith("-") else "medium",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Quantity manipulation: {param}={value}")
                            return

                    except Exception as e:
                        logger.debug(f"Error testing quantity: {e}")

    async def _test_negative_values(self):
        """Test negative value handling across parameters."""
        logger.info("Testing negative value handling...")

        all_params = self.PRICE_PARAMS + self.QUANTITY_PARAMS
        negative_values = ["-1", "-100", "-999999"]

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for param in all_params[:10]:  # Limit for speed
                for value in negative_values:
                    try:
                        # Test JSON body
                        response = await client.post(
                            self.target,
                            headers={**self._get_headers(), "Content-Type": "application/json"},
                            data=json.dumps({param: int(value)})
                        )

                        if response.status == 200:
                            # Check if negative was processed
                            if value in response.body or "success" in response.body.lower():
                                vuln = BusinessLogicVuln(
                                    url=self.target,
                                    vuln_type="negative_value_accepted",
                                    description=f"Negative value accepted in JSON: {param}={value}",
                                    evidence=response.body[:300],
                                    payload=f"JSON {param}={value}",
                                    impact="Potential credit/balance manipulation",
                                    confidence="medium",
                                )
                                self.vulnerabilities.append(vuln)
                                logger.info(f"Negative value accepted: {param}={value}")
                                return

                    except Exception as e:
                        logger.debug(f"Error testing negative: {e}")

    async def _test_integer_overflow(self):
        """Test integer overflow vulnerabilities."""
        logger.info("Testing integer overflow...")

        overflow_values = [
            ("2147483647", "max_int32"),
            ("2147483648", "overflow_int32"),
            ("9223372036854775807", "max_int64"),
            ("9223372036854775808", "overflow_int64"),
            ("99999999999999999999", "very_large"),
        ]

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for param in self.QUANTITY_PARAMS[:3]:
                for value, test_type in overflow_values:
                    url = f"{self.target}?{param}={value}"
                    try:
                        response = await client.get(url, headers=self._get_headers())

                        # Check for overflow indicators
                        if response.status == 200:
                            # Check if value wrapped to negative or zero
                            if any(x in response.body.lower() for x in ["-", "negative", "0", "error"]):
                                vuln = BusinessLogicVuln(
                                    url=url,
                                    vuln_type=f"integer_overflow_{test_type}",
                                    description=f"Potential integer overflow: {param}={value}",
                                    evidence=response.body[:300],
                                    payload=f"{param}={value}",
                                    impact="Integer overflow may cause unexpected behavior",
                                    confidence="medium",
                                )
                                self.vulnerabilities.append(vuln)
                                logger.info(f"Integer overflow: {param}={value}")
                                return

                    except Exception as e:
                        logger.debug(f"Error testing overflow: {e}")

    async def _test_discount_abuse(self):
        """Test discount/coupon abuse."""
        logger.info("Testing discount abuse...")

        abuse_tests = [
            # Multiple applications
            ("DISCOUNT10", "DISCOUNT10,DISCOUNT10", "multiple_same"),
            ("DISCOUNT10", "DISCOUNT10&coupon=DISCOUNT20", "stacking"),
            # Negative discounts
            ("discount", "-50", "negative_discount"),
            ("percent_off", "150", "over_100_percent"),
            ("percent_off", "-20", "negative_percent"),
        ]

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for param, value, test_type in abuse_tests:
                url = f"{self.target}?{param}={value}"
                try:
                    response = await client.get(url, headers=self._get_headers())

                    if self._indicates_success(response, "discount"):
                        vuln = BusinessLogicVuln(
                            url=url,
                            vuln_type=f"discount_abuse_{test_type}",
                            description=f"Discount abuse possible: {param}={value}",
                            evidence=response.body[:300],
                            payload=f"{param}={value}",
                            impact="Financial loss through discount manipulation",
                            confidence="medium",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Discount abuse: {test_type}")

                except Exception as e:
                    logger.debug(f"Error testing discount: {e}")

    async def _test_workflow_bypass(self):
        """Test workflow/step bypass."""
        logger.info("Testing workflow bypass...")

        # Try to skip steps by directly accessing later stages
        workflow_endpoints = [
            "/checkout/confirm",
            "/order/complete",
            "/payment/success",
            "/api/order/finalize",
            "/api/checkout/complete",
            "/purchase/confirm",
            "/transaction/complete",
        ]

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            base_url = self.target.rstrip("/")

            for endpoint in workflow_endpoints:
                url = f"{base_url}{endpoint}"
                try:
                    response = await client.get(url, headers=self._get_headers())

                    if response.status == 200 and not self._is_error_page(response.body):
                        vuln = BusinessLogicVuln(
                            url=url,
                            vuln_type="workflow_bypass",
                            description=f"Workflow step accessible directly: {endpoint}",
                            evidence=response.body[:300],
                            payload=endpoint,
                            impact="May allow skipping payment or verification steps",
                            confidence="medium",
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Workflow bypass: {endpoint}")

                except Exception as e:
                    logger.debug(f"Error testing workflow: {e}")

    async def _test_status_manipulation(self):
        """Test order/payment status manipulation."""
        logger.info("Testing status manipulation...")

        status_values = [
            ("completed", "complete_status"),
            ("approved", "approved_status"),
            ("paid", "paid_status"),
            ("verified", "verified_status"),
            ("success", "success_status"),
            ("1", "boolean_true"),
            ("true", "boolean_true_str"),
        ]

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            for param in self.STATUS_PARAMS:
                for value, test_type in status_values:
                    # Test GET
                    url = f"{self.target}?{param}={value}"
                    try:
                        response = await client.get(url, headers=self._get_headers())

                        if self._indicates_status_change(response):
                            vuln = BusinessLogicVuln(
                                url=url,
                                vuln_type=f"status_manipulation_{test_type}",
                                description=f"Status manipulation accepted: {param}={value}",
                                evidence=response.body[:300],
                                payload=f"{param}={value}",
                                impact="May bypass payment or approval workflows",
                                confidence="high",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Status manipulation: {param}={value}")
                            return

                    except Exception as e:
                        logger.debug(f"Error testing status: {e}")

                    # Test POST
                    try:
                        response = await client.post(
                            self.target,
                            headers=self._get_headers(),
                            data={param: value}
                        )

                        if self._indicates_status_change(response):
                            vuln = BusinessLogicVuln(
                                url=self.target,
                                vuln_type=f"status_manipulation_{test_type}",
                                description=f"Status manipulation via POST: {param}={value}",
                                evidence=response.body[:300],
                                payload=f"POST {param}={value}",
                                impact="May bypass payment or approval workflows",
                                confidence="high",
                            )
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Status manipulation POST: {param}={value}")
                            return

                    except Exception as e:
                        logger.debug(f"Error testing status POST: {e}")

    def _indicates_success(self, response: HTTPResponse, context: str) -> bool:
        """Check if response indicates successful manipulation."""
        if response.status not in [200, 201]:
            return False

        body_lower = response.body.lower()

        success_indicators = [
            "success", "accepted", "processed", "confirmed",
            "order", "cart", "added", "updated",
        ]

        error_indicators = [
            "error", "invalid", "failed", "denied",
            "not allowed", "rejected", "must be positive",
            "cannot be negative", "minimum",
        ]

        has_success = any(ind in body_lower for ind in success_indicators)
        has_error = any(ind in body_lower for ind in error_indicators)

        return has_success and not has_error

    def _indicates_status_change(self, response: HTTPResponse) -> bool:
        """Check if response indicates status was changed."""
        if response.status not in [200, 201]:
            return False

        body_lower = response.body.lower()

        change_indicators = [
            "status updated", "status changed", "completed",
            "approved", "verified", "confirmed", "success",
        ]

        return any(ind in body_lower for ind in change_indicators)

    def _is_error_page(self, body: str) -> bool:
        """Check if response is an error page."""
        error_indicators = [
            "404", "not found", "error", "forbidden",
            "unauthorized", "access denied", "login required",
        ]

        body_lower = body.lower()
        return any(ind in body_lower for ind in error_indicators)

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"business_logic_{self.target_domain}")

        vuln_path = self.output_dir / f"business_logic_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp_now(),
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            }, f, indent=2)
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Business Logic tester")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--auth-cookie", help="Authentication cookie")
    parser.add_argument("--auth-header", help="Authorization header")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    tester = BusinessLogicTester(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        auth_cookie=args.auth_cookie,
        auth_header=args.auth_header,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"Business Logic Testing Complete")
    print(f"{'='*60}")
    print(f"Vulnerabilities: {len(tester.vulnerabilities)}")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

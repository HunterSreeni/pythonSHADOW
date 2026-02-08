#!/usr/bin/env python3
"""
Technology fingerprinting module for detecting web technologies.

Usage:
    python tech_fingerprint.py --target https://example.com --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, timestamp_now, ensure_dir, normalize_url

logger = setup_logging("tech_fingerprint")


# Technology detection patterns
TECH_SIGNATURES = {
    # Web Servers
    "nginx": {
        "headers": {"Server": r"nginx"},
        "category": "web-server",
    },
    "apache": {
        "headers": {"Server": r"Apache"},
        "category": "web-server",
    },
    "iis": {
        "headers": {"Server": r"Microsoft-IIS"},
        "category": "web-server",
    },
    "cloudflare": {
        "headers": {"Server": r"cloudflare", "CF-RAY": r".+"},
        "category": "cdn",
    },

    # Frameworks
    "wordpress": {
        "body": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "headers": {"X-Powered-By": r"WordPress"},
        "meta": {"generator": r"WordPress"},
        "category": "cms",
    },
    "drupal": {
        "body": [r"/sites/default/files", r"Drupal.settings"],
        "headers": {"X-Drupal-Cache": r".+", "X-Generator": r"Drupal"},
        "category": "cms",
    },
    "joomla": {
        "body": [r"/media/jui/", r"/components/com_"],
        "meta": {"generator": r"Joomla"},
        "category": "cms",
    },
    "django": {
        "headers": {"X-Frame-Options": r"SAMEORIGIN"},
        "cookies": ["csrftoken", "sessionid"],
        "body": [r"csrfmiddlewaretoken"],
        "category": "framework",
    },
    "flask": {
        "cookies": ["session"],
        "body": [r"Werkzeug"],
        "category": "framework",
    },
    "rails": {
        "headers": {"X-Powered-By": r"Phusion Passenger"},
        "cookies": ["_session_id"],
        "meta": {"csrf-token": r".+"},
        "category": "framework",
    },
    "laravel": {
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "body": [r"laravel"],
        "category": "framework",
    },
    "express": {
        "headers": {"X-Powered-By": r"Express"},
        "category": "framework",
    },
    "spring": {
        "headers": {"X-Application-Context": r".+"},
        "cookies": ["JSESSIONID"],
        "category": "framework",
    },
    "aspnet": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".+"},
        "cookies": ["ASP.NET_SessionId", ".AspNetCore."],
        "body": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
        "category": "framework",
    },

    # JavaScript Frameworks
    "react": {
        "body": [r"react\.production\.min\.js", r"_reactRootContainer", r"data-reactroot"],
        "category": "js-framework",
    },
    "angular": {
        "body": [r"ng-version", r"ng-app", r"angular\.min\.js", r"\[\[ngModel\]\]"],
        "category": "js-framework",
    },
    "vue": {
        "body": [r"vue\.min\.js", r"v-cloak", r"v-bind", r"Vue\."],
        "category": "js-framework",
    },
    "jquery": {
        "body": [r"jquery[\.-][\d\.]+\.min\.js", r"jQuery v"],
        "category": "js-library",
    },
    "bootstrap": {
        "body": [r"bootstrap[\.-][\d\.]+\.min\.(js|css)", r"class=\"[^\"]*btn btn-"],
        "category": "css-framework",
    },

    # Caching/CDN
    "varnish": {
        "headers": {"Via": r"varnish", "X-Varnish": r".+"},
        "category": "cache",
    },
    "akamai": {
        "headers": {"X-Akamai-Transformed": r".+"},
        "category": "cdn",
    },
    "fastly": {
        "headers": {"X-Served-By": r"cache-", "X-Cache": r".+"},
        "category": "cdn",
    },
    "aws-cloudfront": {
        "headers": {"X-Amz-Cf-Id": r".+", "Via": r"CloudFront"},
        "category": "cdn",
    },

    # Security
    "waf-cloudflare": {
        "headers": {"CF-RAY": r".+"},
        "body": [r"Attention Required! \| Cloudflare"],
        "category": "waf",
    },
    "waf-aws": {
        "headers": {"X-Amzn-RequestId": r".+"},
        "category": "waf",
    },
    "waf-akamai": {
        "body": [r"Access Denied.*akamai"],
        "category": "waf",
    },

    # Analytics
    "google-analytics": {
        "body": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"_ga="],
        "category": "analytics",
    },
    "google-tag-manager": {
        "body": [r"googletagmanager\.com/gtm\.js"],
        "category": "analytics",
    },

    # E-commerce
    "shopify": {
        "body": [r"cdn\.shopify\.com", r"Shopify\."],
        "headers": {"X-ShopId": r".+"},
        "category": "ecommerce",
    },
    "magento": {
        "body": [r"/skin/frontend/", r"Mage\."],
        "cookies": ["frontend"],
        "category": "ecommerce",
    },
    "woocommerce": {
        "body": [r"woocommerce", r"wc-ajax"],
        "category": "ecommerce",
    },

    # Databases
    "php": {
        "headers": {"X-Powered-By": r"PHP/[\d\.]+"},
        "category": "language",
    },
    "phpmyadmin": {
        "body": [r"phpMyAdmin", r"pma_"],
        "category": "database-admin",
    },

    # Authentication
    "okta": {
        "body": [r"okta\.com", r"OktaAuth"],
        "category": "auth",
    },
    "auth0": {
        "body": [r"auth0\.com", r"auth0-js"],
        "category": "auth",
    },
}


@dataclass
class Technology:
    """Detected technology."""

    name: str
    category: str
    confidence: float
    version: Optional[str] = None
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence,
            "version": self.version,
            "evidence": self.evidence,
        }


@dataclass
class FingerprintResult:
    """Fingerprinting result for a URL."""

    url: str
    status_code: int
    title: str = ""
    technologies: List[Technology] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "technologies": [t.to_dict() for t in self.technologies],
            "headers": self.headers,
            "cookies": self.cookies,
        }


class TechFingerprinter:
    """
    Web technology fingerprinting.

    Detection methods:
    - HTTP headers
    - HTML content patterns
    - Cookie names
    - Meta tags
    - JavaScript files
    """

    def __init__(
        self,
        targets: List[str],
        output_dir: str = "results",
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 20,
        verbose: bool = False,
    ):
        self.targets = [normalize_url(t) for t in targets]
        self.output_dir = Path(output_dir)
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose

        self.results: Dict[str, FingerprintResult] = {}
        self.result_manager = ResultManager(output_dir)

        ensure_dir(self.output_dir)

    async def fingerprint(self) -> ScanResult:
        """Run fingerprinting on all targets."""
        result = ScanResult(
            tool="tech_fingerprint",
            target=",".join(self.targets[:5]) + ("..." if len(self.targets) > 5 else ""),
            config={
                "timeout": self.timeout,
                "threads": self.threads,
            },
        )

        logger.info(f"Fingerprinting {len(self.targets)} targets...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            follow_redirects=True,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def fingerprint_one(url: str) -> Optional[FingerprintResult]:
                async with semaphore:
                    try:
                        response = await client.get(url)
                        if response.ok:
                            return self._analyze_response(url, response)
                    except Exception as e:
                        logger.error(f"Error fingerprinting {url}: {e}")
                    return None

            tasks = [fingerprint_one(url) for url in self.targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, FingerprintResult):
                    self.results[res.url] = res

        # Generate findings
        all_techs: Dict[str, Set[str]] = {}  # tech -> set of urls

        for url, fp_result in self.results.items():
            for tech in fp_result.technologies:
                if tech.name not in all_techs:
                    all_techs[tech.name] = set()
                all_techs[tech.name].add(url)

        for tech_name, urls in all_techs.items():
            # Get category from first detection
            category = "unknown"
            for url in urls:
                for tech in self.results[url].technologies:
                    if tech.name == tech_name:
                        category = tech.category
                        break
                break

            severity = self._get_tech_severity(tech_name, category)

            result.add_finding(Finding(
                title=f"Technology Detected: {tech_name}",
                severity=severity,
                description=f"{tech_name} ({category}) detected on {len(urls)} URL(s)",
                url=list(urls)[0],
                metadata={
                    "category": category,
                    "count": len(urls),
                    "urls": list(urls)[:10],
                },
            ))

        # Statistics
        result.stats = {
            "urls_scanned": len(self.targets),
            "urls_alive": len(self.results),
            "unique_technologies": len(all_techs),
            "technologies": list(all_techs.keys()),
        }

        result.finalize()
        return result

    def _analyze_response(self, url: str, response: HTTPResponse) -> FingerprintResult:
        """Analyze HTTP response for technology signatures."""
        fp_result = FingerprintResult(
            url=url,
            status_code=response.status,
            headers={k.lower(): v for k, v in response.headers.items()},
        )

        # Extract title
        title_match = re.search(r"<title[^>]*>([^<]+)</title>", response.body, re.IGNORECASE)
        if title_match:
            fp_result.title = title_match.group(1).strip()[:100]

        # Extract cookies
        for header, value in response.headers.items():
            if header.lower() == "set-cookie":
                cookie_name = value.split("=")[0] if "=" in value else value
                fp_result.cookies.append(cookie_name)

        # Check each technology signature
        for tech_name, signature in TECH_SIGNATURES.items():
            confidence = 0.0
            evidence = []

            # Check headers
            if "headers" in signature:
                for header, pattern in signature["headers"].items():
                    header_value = fp_result.headers.get(header.lower(), "")
                    if header_value and re.search(pattern, header_value, re.IGNORECASE):
                        confidence += 0.4
                        evidence.append(f"Header: {header}={header_value[:50]}")

            # Check body patterns
            if "body" in signature:
                for pattern in signature["body"]:
                    if re.search(pattern, response.body, re.IGNORECASE):
                        confidence += 0.3
                        evidence.append(f"Body pattern: {pattern}")

            # Check cookies
            if "cookies" in signature:
                for cookie_pattern in signature["cookies"]:
                    for cookie in fp_result.cookies:
                        if cookie_pattern.lower() in cookie.lower():
                            confidence += 0.3
                            evidence.append(f"Cookie: {cookie}")

            # Check meta tags
            if "meta" in signature:
                for meta_name, meta_pattern in signature["meta"].items():
                    meta_match = re.search(
                        rf'<meta[^>]+name=["\']?{meta_name}["\']?[^>]+content=["\']?([^"\']+)',
                        response.body,
                        re.IGNORECASE,
                    )
                    if meta_match and re.search(meta_pattern, meta_match.group(1), re.IGNORECASE):
                        confidence += 0.3
                        evidence.append(f"Meta: {meta_name}={meta_match.group(1)[:50]}")

            # If we have evidence, add the technology
            if confidence >= 0.3:
                # Try to extract version
                version = self._extract_version(tech_name, response)

                fp_result.technologies.append(Technology(
                    name=tech_name,
                    category=signature.get("category", "unknown"),
                    confidence=min(confidence, 1.0),
                    version=version,
                    evidence=evidence[:3],
                ))

        return fp_result

    def _extract_version(self, tech_name: str, response: HTTPResponse) -> Optional[str]:
        """Try to extract version number."""
        version_patterns = {
            "nginx": r"nginx/([\d\.]+)",
            "apache": r"Apache/([\d\.]+)",
            "php": r"PHP/([\d\.]+)",
            "wordpress": r"WordPress ([\d\.]+)",
            "jquery": r"jQuery v?([\d\.]+)",
            "bootstrap": r"bootstrap[/\-]([\d\.]+)",
            "react": r"react[@/\-]([\d\.]+)",
            "angular": r"angular[@/\-]([\d\.]+)",
            "vue": r"vue[@/\-]([\d\.]+)",
        }

        if tech_name in version_patterns:
            # Check headers
            for value in response.headers.values():
                match = re.search(version_patterns[tech_name], value, re.IGNORECASE)
                if match:
                    return match.group(1)

            # Check body
            match = re.search(version_patterns[tech_name], response.body, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _get_tech_severity(self, tech_name: str, category: str) -> Severity:
        """Determine severity based on technology type."""
        # Potentially vulnerable or interesting technologies
        high_interest = ["phpmyadmin", "wp-admin", "drupal", "joomla"]
        if tech_name.lower() in high_interest:
            return Severity.LOW

        if category in ["waf", "cdn"]:
            return Severity.INFO

        return Severity.INFO

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, "technologies")

        # Save detailed JSON
        detailed_path = self.output_dir / "technologies_detailed.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "timestamp": timestamp_now(),
                    "results": {url: r.to_dict() for url, r in self.results.items()},
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Technology fingerprinting")
    parser.add_argument("-t", "--target", required=True, help="Target URL(s), comma-separated or file")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Parse targets
    targets = []
    if Path(args.target).exists():
        with open(args.target) as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [t.strip() for t in args.target.split(",")]

    fingerprinter = TechFingerprinter(
        targets=targets,
        output_dir=args.output,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
    )

    result = await fingerprinter.fingerprint()
    paths = fingerprinter.save_results(result)

    print(f"\n{'='*60}")
    print(f"Technology Fingerprinting Complete")
    print(f"{'='*60}")
    print(f"URLs Scanned: {result.stats.get('urls_scanned', 0)}")
    print(f"URLs Alive: {result.stats.get('urls_alive', 0)}")
    print(f"Technologies Found: {result.stats.get('unique_technologies', 0)}")

    if result.stats.get('technologies'):
        print(f"\nDetected: {', '.join(result.stats['technologies'][:10])}")

    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

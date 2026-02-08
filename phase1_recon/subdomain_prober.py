#!/usr/bin/env python3
"""
Subdomain prober for automated subdomain discovery and fingerprinting.

Usage:
    python subdomain_prober.py -d example.com -o results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, timestamp_now, ensure_dir

logger = setup_logging("subdomain_prober")


@dataclass
class SubdomainResult:
    """Represents a discovered subdomain."""

    subdomain: str
    url: str
    status: int
    content_length: int
    title: str = ""
    server: str = ""
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    ssrf_vulnerable_headers: List[str] = field(default_factory=list)
    redirect_location: str = ""
    certificate_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subdomain": self.subdomain,
            "url": self.url,
            "status": self.status,
            "content_length": self.content_length,
            "title": self.title,
            "server": self.server,
            "technologies": self.technologies,
            "headers": self.headers,
            "ssrf_vulnerable_headers": self.ssrf_vulnerable_headers,
            "redirect_location": self.redirect_location,
        }


class SubdomainProber:
    """
    Subdomain prober for automated discovery and fingerprinting.

    Features:
    - Common subdomain prefixes probing
    - Async parallel probing for speed
    - Response fingerprinting (status, title, technology)
    - SSRF header testing on discovered subdomains
    - Technology detection
    """

    # Common subdomain prefixes to probe
    COMMON_PREFIXES = [
        # API & Development
        "api", "api2", "api-v1", "api-v2", "apiv1", "apiv2",
        "dev", "dev2", "development", "staging", "stage",
        "test", "testing", "qa", "uat", "sandbox",
        "demo", "preview", "beta", "alpha",

        # Admin & Management
        "admin", "administrator", "manage", "management",
        "panel", "portal", "console", "dashboard",
        "ops", "operations", "internal", "intranet",

        # Business units
        "merchant", "partner", "vendor", "supplier",
        "customer", "client", "user", "member",
        "support", "help", "helpdesk", "service",

        # Application types
        "app", "apps", "application", "mobile", "m",
        "web", "www2", "www3", "old", "legacy", "new",
        "static", "assets", "cdn", "media", "images", "img",

        # Infrastructure
        "mail", "email", "smtp", "pop", "imap",
        "ftp", "sftp", "files", "upload", "download",
        "vpn", "remote", "gateway", "proxy",
        "db", "database", "mysql", "postgres", "mongo", "redis",
        "cache", "memcached", "elasticsearch", "elastic",

        # CI/CD & DevOps
        "jenkins", "gitlab", "github", "bitbucket",
        "ci", "cd", "build", "deploy", "release",
        "docker", "k8s", "kubernetes", "rancher",
        "grafana", "prometheus", "kibana", "monitoring",

        # Security & Auth
        "auth", "oauth", "sso", "login", "signin", "signup",
        "secure", "security", "vault", "secrets",
        "bugbounty", "security-reports",

        # Regional/Geo
        "us", "eu", "ap", "asia", "emea",
        "us-east", "us-west", "eu-west",

        # Misc
        "blog", "news", "status", "health",
        "docs", "documentation", "wiki",
        "shop", "store", "pay", "payment", "billing",
        "analytics", "metrics", "stats", "tracking",
    ]

    # SSRF-prone headers to test
    SSRF_HEADERS = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Real-IP",
        "X-Client-IP",
        "True-Client-IP",
        "X-Originating-IP",
        "Client-IP",
        "Forwarded",
        "X-Host",
    ]

    # Technology detection patterns
    TECH_PATTERNS = [
        # Server headers
        (r"nginx", "headers", "Nginx"),
        (r"apache", "headers", "Apache"),
        (r"iis", "headers", "IIS"),
        (r"cloudflare", "headers", "Cloudflare"),
        (r"akamai", "headers", "Akamai"),
        (r"fastly", "headers", "Fastly"),
        (r"varnish", "headers", "Varnish"),

        # Response body patterns
        (r"wp-content|wordpress", "body", "WordPress"),
        (r"drupal", "body", "Drupal"),
        (r"joomla", "body", "Joomla"),
        (r"rails|ruby on rails", "body", "Ruby on Rails"),
        (r"laravel", "body", "Laravel"),
        (r"django", "body", "Django"),
        (r"express", "headers", "Express.js"),
        (r"next\.js|__NEXT", "body", "Next.js"),
        (r"react|reactdom", "body", "React"),
        (r"vue\.js|vuejs", "body", "Vue.js"),
        (r"angular", "body", "Angular"),
        (r"bootstrap", "body", "Bootstrap"),
        (r"jquery", "body", "jQuery"),

        # Header-specific
        (r"x-powered-by:\s*php", "headers", "PHP"),
        (r"x-powered-by:\s*asp\.net", "headers", "ASP.NET"),
        (r"x-aspnet-version", "headers", "ASP.NET"),
        (r"x-runtime", "headers", "Ruby"),
    ]

    def __init__(
        self,
        domain: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 10,
        threads: int = 50,
        custom_prefixes: Optional[List[str]] = None,
        test_ssrf: bool = True,
        verbose: bool = False,
    ):
        self.domain = domain.lower().strip()
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.custom_prefixes = custom_prefixes or []
        self.test_ssrf = test_ssrf
        self.verbose = verbose

        self.discovered: Dict[str, SubdomainResult] = {}
        self.failed: Set[str] = set()

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def probe(self) -> ScanResult:
        """Run subdomain probing and return results."""
        result = ScanResult(
            tool="subdomain_prober",
            target=self.domain,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "test_ssrf": self.test_ssrf,
            },
        )

        logger.info(f"Starting subdomain probing for: {self.domain}")

        try:
            # Combine default and custom prefixes
            all_prefixes = list(set(self.COMMON_PREFIXES + self.custom_prefixes))
            logger.info(f"Testing {len(all_prefixes)} subdomain prefixes")

            # Generate subdomain list
            subdomains = [f"{prefix}.{self.domain}" for prefix in all_prefixes]

            # Also test the base domain
            subdomains.insert(0, self.domain)
            subdomains.insert(1, f"www.{self.domain}")

            # Probe all subdomains
            await self._probe_subdomains(subdomains)

            # Test SSRF on discovered subdomains
            if self.test_ssrf and self.discovered:
                await self._test_ssrf_headers()

            # Compile statistics
            result.stats = {
                "prefixes_tested": len(all_prefixes),
                "subdomains_discovered": len(self.discovered),
                "subdomains_failed": len(self.failed),
                "ssrf_vulnerable": sum(
                    1 for s in self.discovered.values() if s.ssrf_vulnerable_headers
                ),
                "by_status": self._count_by_status(),
                "technologies_found": self._get_all_technologies(),
            }

            # Add findings for discovered subdomains
            for subdomain, sub_result in self.discovered.items():
                severity = Severity.INFO

                # Elevate severity for interesting findings
                if sub_result.ssrf_vulnerable_headers:
                    severity = Severity.HIGH
                elif any(t in ["Admin Panel", "Jenkins", "GitLab"] for t in sub_result.technologies):
                    severity = Severity.MEDIUM
                elif sub_result.status in [401, 403]:
                    severity = Severity.LOW

                result.add_finding(Finding(
                    title=f"Subdomain: {subdomain}",
                    severity=severity,
                    description=f"Discovered subdomain with status {sub_result.status}",
                    url=sub_result.url,
                    metadata={
                        "status": sub_result.status,
                        "title": sub_result.title,
                        "server": sub_result.server,
                        "technologies": sub_result.technologies,
                        "content_length": sub_result.content_length,
                        "ssrf_vulnerable_headers": sub_result.ssrf_vulnerable_headers,
                    },
                ))

        except Exception as e:
            result.add_error(f"Probing error: {e}")
            logger.error(f"Probing error: {e}")

        result.finalize()
        return result

    async def _probe_subdomains(self, subdomains: List[str]):
        """Probe all subdomains in parallel."""
        logger.info(f"Probing {len(subdomains)} subdomains...")

        semaphore = asyncio.Semaphore(self.threads)

        async def probe_single(subdomain: str):
            async with semaphore:
                await self._probe_subdomain(subdomain)

        tasks = [probe_single(sub) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Discovered {len(self.discovered)} live subdomains")

    async def _probe_subdomain(self, subdomain: str):
        """Probe a single subdomain."""
        # Try HTTPS first, then HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"

            try:
                async with AsyncHTTPClient(
                    timeout=self.timeout,
                    proxy=self.proxy,
                    max_retries=1,
                    follow_redirects=False,
                ) as client:
                    response = await client.get(url)

                    if response.status > 0:
                        # Extract information
                        title = self._extract_title(response.body)
                        server = response.headers.get("server", "")
                        technologies = self._detect_technologies(response)

                        redirect_location = ""
                        if response.status in [301, 302, 303, 307, 308]:
                            redirect_location = response.headers.get("location", "")

                        self.discovered[subdomain] = SubdomainResult(
                            subdomain=subdomain,
                            url=url,
                            status=response.status,
                            content_length=len(response.body),
                            title=title,
                            server=server,
                            technologies=technologies,
                            headers=dict(response.headers),
                            redirect_location=redirect_location,
                        )

                        logger.debug(f"Found: {subdomain} [{response.status}] - {title[:50] if title else 'No title'}")
                        return

            except Exception as e:
                logger.debug(f"Error probing {url}: {e}")
                continue

        self.failed.add(subdomain)

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML."""
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:200]
        return ""

    def _detect_technologies(self, response: HTTPResponse) -> List[str]:
        """Detect technologies from response."""
        technologies = []
        headers_str = str(response.headers).lower()
        body_lower = response.body.lower()

        for pattern, source, tech in self.TECH_PATTERNS:
            if source == "headers":
                if re.search(pattern, headers_str, re.IGNORECASE):
                    if tech not in technologies:
                        technologies.append(tech)
            elif source == "body":
                if re.search(pattern, body_lower, re.IGNORECASE):
                    if tech not in technologies:
                        technologies.append(tech)

        # Additional header-based detection
        if "x-powered-by" in response.headers:
            powered_by = response.headers.get("x-powered-by", "")
            if powered_by and powered_by not in technologies:
                technologies.append(f"X-Powered-By: {powered_by}")

        return technologies

    async def _test_ssrf_headers(self):
        """Test SSRF-prone headers on discovered subdomains."""
        logger.info("Testing SSRF-prone headers on discovered subdomains...")

        for subdomain, sub_result in self.discovered.items():
            if sub_result.status not in [200, 301, 302, 401, 403]:
                continue

            vulnerable_headers = []

            async with AsyncHTTPClient(
                timeout=self.timeout,
                proxy=self.proxy,
                max_retries=1,
            ) as client:
                # Get baseline
                try:
                    baseline = await client.get(sub_result.url)
                    baseline_status = baseline.status
                    baseline_length = len(baseline.body)
                except Exception:
                    continue

                for header in self.SSRF_HEADERS:
                    try:
                        # Test with localhost payload
                        test_headers = {header: "127.0.0.1"}
                        response = await client.get(sub_result.url, headers=test_headers)

                        # Check for behavioral changes
                        if self._is_ssrf_indicator(
                            baseline_status, baseline_length,
                            response.status, len(response.body)
                        ):
                            vulnerable_headers.append(header)
                            logger.info(f"SSRF indicator: {subdomain} via {header}")

                    except Exception as e:
                        logger.debug(f"Error testing {header} on {subdomain}: {e}")

            sub_result.ssrf_vulnerable_headers = vulnerable_headers

    def _is_ssrf_indicator(
        self,
        baseline_status: int,
        baseline_length: int,
        response_status: int,
        response_length: int,
    ) -> bool:
        """Check if response indicates potential SSRF."""
        # Status code changes
        suspicious_changes = [
            (200, 502),
            (200, 504),
            (200, 500),
            (200, 403),
            (200, 404),
        ]

        if (baseline_status, response_status) in suspicious_changes:
            return True

        # Significant length change
        if baseline_length > 0:
            change = abs(response_length - baseline_length) / baseline_length
            if change > 0.3:
                return True

        return False

    def _count_by_status(self) -> Dict[str, int]:
        """Count subdomains by status code."""
        counts: Dict[str, int] = {}
        for sub_result in self.discovered.values():
            status_group = f"{sub_result.status // 100}xx"
            counts[status_group] = counts.get(status_group, 0) + 1
        return counts

    def _get_all_technologies(self) -> List[str]:
        """Get all unique technologies found."""
        all_techs = set()
        for sub_result in self.discovered.values():
            all_techs.update(sub_result.technologies)
        return sorted(list(all_techs))

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"subdomain_probe_{self.domain}")

        # Save detailed JSON
        detailed_path = self.output_dir / f"subdomains_{self.domain}.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "domain": self.domain,
                    "timestamp": timestamp_now(),
                    "discovered": [s.to_dict() for s in self.discovered.values()],
                    "failed_count": len(self.failed),
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        # Save subdomain list (simple text)
        list_path = self.output_dir / f"subdomains_{self.domain}.txt"
        with open(list_path, "w") as f:
            for subdomain in sorted(self.discovered.keys()):
                f.write(f"{subdomain}\n")
        paths["list"] = str(list_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="Subdomain prober for automated discovery and fingerprinting"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--prefixes", help="Additional prefixes (comma-separated)")
    parser.add_argument("--no-ssrf", action="store_true", help="Skip SSRF header testing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    custom_prefixes = args.prefixes.split(",") if args.prefixes else []

    prober = SubdomainProber(
        domain=args.domain,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        custom_prefixes=custom_prefixes,
        test_ssrf=not args.no_ssrf,
        verbose=args.verbose,
    )

    result = await prober.probe()
    paths = prober.save_results(result)

    print(f"\n{'='*60}")
    print(f"Subdomain Probing Complete: {args.domain}")
    print(f"{'='*60}")
    print(f"Subdomains Discovered: {len(prober.discovered)}")
    print(f"Subdomains Failed: {len(prober.failed)}")
    print(f"SSRF Vulnerable: {sum(1 for s in prober.discovered.values() if s.ssrf_vulnerable_headers)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    # Show top discoveries
    if prober.discovered:
        print(f"\n*** DISCOVERED SUBDOMAINS ***")
        for subdomain, sub in sorted(prober.discovered.items())[:20]:
            status_icon = "+" if sub.status == 200 else "~"
            ssrf_icon = "[SSRF!]" if sub.ssrf_vulnerable_headers else ""
            title_short = sub.title[:40] + "..." if len(sub.title) > 40 else sub.title
            print(f"  {status_icon} [{sub.status}] {subdomain} - {title_short} {ssrf_icon}")

        if len(prober.discovered) > 20:
            print(f"  ... and {len(prober.discovered) - 20} more")


if __name__ == "__main__":
    asyncio.run(main())

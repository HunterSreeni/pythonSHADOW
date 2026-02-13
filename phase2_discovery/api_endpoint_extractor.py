#!/usr/bin/env python3
"""
API endpoint extraction module for discovering REST and GraphQL endpoints.

Usage:
    python api_endpoint_extractor.py --target https://example.com --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir, parse_cookies

logger = setup_logging("api_endpoint_extractor")


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint."""

    path: str
    method: str = "GET"
    full_url: str = ""
    source: str = ""  # Where it was found (js, html, robots, sitemap, etc.)
    parameters: List[str] = field(default_factory=list)
    authenticated: bool = False
    response_type: str = ""
    status_code: int = 0
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "full_url": self.full_url,
            "source": self.source,
            "parameters": self.parameters,
            "authenticated": self.authenticated,
            "response_type": self.response_type,
            "status_code": self.status_code,
            "description": self.description,
        }


class APIEndpointExtractor:
    """
    API endpoint extractor from multiple sources.

    Features:
    - JavaScript file analysis
    - HTML parsing for API calls
    - robots.txt and sitemap.xml parsing
    - Common API path probing
    - OpenAPI/Swagger discovery
    - GraphQL endpoint detection
    """

    # Common API path patterns
    API_PATH_PATTERNS = [
        # Versioned APIs
        r'/api/v\d+/[\w\-/{}:]+',
        r'/v\d+/[\w\-/{}:]+',
        r'/api/[\w\-/{}:]+',

        # REST patterns
        r'/rest/[\w\-/{}:]+',
        r'/services/[\w\-/{}:]+',
        r'/endpoints?/[\w\-/{}:]+',

        # Common frameworks
        r'/wp-json/[\w\-/{}:]+',  # WordPress
        r'/_api/[\w\-/{}:]+',  # SharePoint
        r'/odata/[\w\-/{}:]+',  # OData

        # Action patterns
        r'/[\w\-]+/(?:get|post|create|update|delete|list|search|find|fetch)[\w\-/{}:]*',
    ]

    # Common API endpoints to probe
    COMMON_API_PATHS = [
        # Versioned
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",

        # REST
        "/rest", "/rest/api", "/services",

        # GraphQL
        "/graphql", "/graphiql", "/playground",
        "/api/graphql", "/v1/graphql",

        # Documentation
        "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
        "/openapi", "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api/docs", "/docs/api",
        "/redoc", "/api/schema",

        # Health/Status
        "/health", "/healthz", "/healthcheck",
        "/status", "/api/status", "/ping",
        "/ready", "/readiness", "/liveness",

        # Authentication
        "/auth", "/login", "/logout", "/register",
        "/oauth", "/oauth/token", "/token",
        "/api/auth", "/api/login",

        # Users/Accounts
        "/users", "/user", "/account", "/profile",
        "/api/users", "/api/user", "/api/me",

        # Common resources
        "/products", "/orders", "/items",
        "/posts", "/articles", "/comments",
        "/files", "/uploads", "/media",
        "/search", "/query", "/filter",

        # Admin
        "/admin", "/admin/api", "/management",
        "/internal", "/debug", "/metrics",

        # Config
        "/config", "/configuration", "/settings",
        "/env", "/environment",
    ]

    # HTTP methods to test
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 15,
        threads: int = 30,
        probe_methods: bool = True,
        verbose: bool = False,
        auth_cookie: Optional[str] = None,
        auth_header: Optional[str] = None,
    ):
        self.target = normalize_url(target).rstrip('/')
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.probe_methods = probe_methods
        self.verbose = verbose
        self.auth_cookie = auth_cookie
        self.auth_header = auth_header

        self.endpoints: Dict[str, APIEndpoint] = {}
        self.visited_urls: Set[str] = set()

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def extract(self) -> ScanResult:
        """Run API endpoint extraction and return results."""
        result = ScanResult(
            tool="api_endpoint_extractor",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "probe_methods": self.probe_methods,
            },
        )

        logger.info(f"Starting API endpoint extraction for: {self.target}")

        try:
            # Run all extraction methods concurrently
            await asyncio.gather(
                self._extract_from_main_page(),
                self._extract_from_robots(),
                self._extract_from_sitemap(),
                self._probe_common_paths(),
                self._extract_from_js_files(),
                return_exceptions=True,
            )

            # Probe endpoints for additional info
            if self.probe_methods:
                await self._probe_endpoints()

            # Calculate statistics
            result.stats = {
                "total_endpoints": len(self.endpoints),
                "unique_paths": len(set(e.path for e in self.endpoints.values())),
                "by_source": self._count_by_source(),
                "by_method": self._count_by_method(),
                "authenticated_endpoints": sum(1 for e in self.endpoints.values() if e.authenticated),
            }

            # Add findings
            for endpoint in self.endpoints.values():
                severity = Severity.INFO

                # Higher severity for interesting endpoints
                if any(x in endpoint.path.lower() for x in ["admin", "debug", "internal", "config"]):
                    severity = Severity.MEDIUM
                if any(x in endpoint.path.lower() for x in ["graphql", "swagger", "openapi"]):
                    severity = Severity.LOW

                result.add_finding(Finding(
                    title=f"API Endpoint: {endpoint.method} {endpoint.path}",
                    severity=severity,
                    description=f"API endpoint discovered from {endpoint.source}",
                    url=endpoint.full_url or f"{self.target}{endpoint.path}",
                    metadata={
                        "method": endpoint.method,
                        "source": endpoint.source,
                        "parameters": endpoint.parameters,
                        "authenticated": endpoint.authenticated,
                        "response_type": endpoint.response_type,
                        "status_code": endpoint.status_code,
                    },
                ))

        except Exception as e:
            result.add_error(f"Extraction error: {e}")
            logger.error(f"Extraction error: {e}")

        result.finalize()
        return result

    async def _extract_from_main_page(self):
        """Extract API endpoints from main page HTML."""
        logger.info("Extracting from main page...")

        cookies = parse_cookies(self.auth_cookie) if self.auth_cookie else None
        headers = {"Authorization": self.auth_header} if self.auth_header else {}

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            cookies=cookies,
            headers=headers,
        ) as client:
            response = await client.get(self.target)
            if response.ok:
                self._extract_from_html(response.body, "html")

    async def _extract_from_robots(self):
        """Extract paths from robots.txt."""
        logger.info("Checking robots.txt...")

        cookies = parse_cookies(self.auth_cookie) if self.auth_cookie else None
        headers = {"Authorization": self.auth_header} if self.auth_header else {}

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            cookies=cookies,
            headers=headers,
        ) as client:
            url = f"{self.target}/robots.txt"
            response = await client.get(url)

            if response.ok and response.body:
                # Extract paths from Disallow and Allow directives
                for line in response.body.split('\n'):
                    line = line.strip()
                    if line.startswith(('Disallow:', 'Allow:')):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/' and '/api' in path.lower():
                            self._add_endpoint(path, "robots.txt")

    async def _extract_from_sitemap(self):
        """Extract paths from sitemap.xml."""
        logger.info("Checking sitemap.xml...")

        cookies = parse_cookies(self.auth_cookie) if self.auth_cookie else None
        headers = {"Authorization": self.auth_header} if self.auth_header else {}

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            cookies=cookies,
            headers=headers,
        ) as client:
            sitemap_urls = [
                f"{self.target}/sitemap.xml",
                f"{self.target}/sitemap_index.xml",
                f"{self.target}/sitemap/sitemap.xml",
            ]

            for sitemap_url in sitemap_urls:
                response = await client.get(sitemap_url)
                if response.ok and response.body:
                    # Extract URLs from sitemap
                    url_pattern = r'<loc>([^<]+)</loc>'
                    for match in re.finditer(url_pattern, response.body):
                        url = match.group(1)
                        parsed = urlparse(url)
                        if '/api' in parsed.path.lower() or '/v1' in parsed.path or '/v2' in parsed.path:
                            self._add_endpoint(parsed.path, "sitemap.xml")

    async def _probe_common_paths(self):
        """Probe common API paths."""
        logger.info("Probing common API paths...")

        cookies = parse_cookies(self.auth_cookie) if self.auth_cookie else None
        headers = {"Authorization": self.auth_header} if self.auth_header else {}

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
            cookies=cookies,
            headers=headers,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def probe_path(path: str):
                async with semaphore:
                    url = f"{self.target}{path}"
                    try:
                        response = await client.get(url)

                        # Consider valid if not 404 and has some content
                        if response.status not in [404, 400] and len(response.body) > 0:
                            content_type = response.headers.get("content-type", "").lower()

                            endpoint = APIEndpoint(
                                path=path,
                                method="GET",
                                full_url=url,
                                source="probe",
                                status_code=response.status,
                                response_type=content_type,
                                authenticated=response.status in [401, 403],
                            )

                            # Check if it's a JSON API
                            if "json" in content_type:
                                endpoint.description = "JSON API endpoint"

                            # Check for GraphQL
                            if "graphql" in path.lower():
                                endpoint.description = "GraphQL endpoint"

                            # Check for Swagger/OpenAPI
                            if any(x in path.lower() for x in ["swagger", "openapi", "api-docs"]):
                                endpoint.description = "API documentation endpoint"

                            key = f"{path}:GET"
                            self.endpoints[key] = endpoint

                            if self.verbose:
                                logger.info(f"Found: {path} [{response.status}]")

                    except Exception as e:
                        logger.debug(f"Error probing {path}: {e}")

            tasks = [probe_path(path) for path in self.COMMON_API_PATHS]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _extract_from_js_files(self):
        """Extract API endpoints from JavaScript files."""
        logger.info("Extracting from JavaScript files...")

        cookies = parse_cookies(self.auth_cookie) if self.auth_cookie else None
        headers = {"Authorization": self.auth_header} if self.auth_header else {}

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            cookies=cookies,
            headers=headers,
        ) as client:
            # First get the main page to find JS files
            response = await client.get(self.target)
            if not response.ok:
                return

            # Find JS file URLs
            js_pattern = r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']'
            js_urls = set()
            for match in re.finditer(js_pattern, response.body, re.IGNORECASE):
                js_url = urljoin(self.target, match.group(1))
                js_urls.add(js_url)

            # Fetch and analyze JS files
            semaphore = asyncio.Semaphore(self.threads)

            async def analyze_js(url: str):
                async with semaphore:
                    try:
                        resp = await client.get(url)
                        if resp.ok:
                            self._extract_endpoints_from_js(resp.body, url)
                    except Exception as e:
                        logger.debug(f"Error fetching JS {url}: {e}")

            tasks = [analyze_js(url) for url in list(js_urls)[:50]]  # Limit to 50 JS files
            await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_from_html(self, html: str, source: str):
        """Extract API endpoints from HTML content."""
        # Look for API URLs in various attributes
        patterns = [
            r'(?:href|src|action|data-url|data-api)=["\']([^"\']*(?:/api/|/v\d+/)[^"\']*)["\']',
            r'fetch\s*\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(["\']([^"\']+)["\']',
            r'\.(?:get|post|put|delete|patch)\s*\(["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                path = match.group(1)
                if self._is_valid_api_path(path):
                    self._add_endpoint(path, source)

    def _extract_endpoints_from_js(self, js_content: str, source_url: str):
        """Extract API endpoints from JavaScript content."""
        # API URL patterns
        for pattern in self.API_PATH_PATTERNS:
            for match in re.finditer(pattern, js_content):
                path = match.group(0)
                if self._is_valid_api_path(path):
                    self._add_endpoint(path, f"js:{source_url.split('/')[-1]}")

        # Fetch/axios patterns
        fetch_patterns = [
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*`([^`]+)`',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
            r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in fetch_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                path = match.group(1)
                if self._is_valid_api_path(path):
                    self._add_endpoint(path, f"js:{source_url.split('/')[-1]}")

        # URL construction patterns
        url_patterns = [
            r'(?:baseUrl|apiUrl|endpoint|API_URL|BASE_URL)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\'](?:url|endpoint|path)["\']?\s*:\s*["\']([^"\']+)["\']',
        ]

        for pattern in url_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                path = match.group(1)
                if self._is_valid_api_path(path):
                    self._add_endpoint(path, f"js:{source_url.split('/')[-1]}")

    async def _probe_endpoints(self):
        """Probe discovered endpoints for additional information."""
        logger.info("Probing endpoints for method support...")

        cookies = parse_cookies(self.auth_cookie) if self.auth_cookie else None
        headers = {"Authorization": self.auth_header} if self.auth_header else {}

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
            cookies=cookies,
            headers=headers,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def probe_methods(endpoint: APIEndpoint):
                async with semaphore:
                    url = endpoint.full_url or f"{self.target}{endpoint.path}"

                    # Try OPTIONS to discover allowed methods
                    try:
                        response = await client.options(url)
                        allow_header = response.headers.get("allow", "")
                        if allow_header:
                            methods = [m.strip() for m in allow_header.split(",")]
                            for method in methods:
                                if method != "GET" and method in self.HTTP_METHODS:
                                    new_endpoint = APIEndpoint(
                                        path=endpoint.path,
                                        method=method,
                                        full_url=url,
                                        source=endpoint.source,
                                        parameters=endpoint.parameters,
                                        status_code=response.status,
                                    )
                                    key = f"{endpoint.path}:{method}"
                                    if key not in self.endpoints:
                                        self.endpoints[key] = new_endpoint
                    except Exception:
                        pass

            # Probe a subset of endpoints
            endpoints_to_probe = list(self.endpoints.values())[:100]
            tasks = [probe_methods(ep) for ep in endpoints_to_probe]
            await asyncio.gather(*tasks, return_exceptions=True)

    def _add_endpoint(self, path: str, source: str):
        """Add an endpoint to the collection."""
        # Normalize path
        if path.startswith(('http://', 'https://')):
            parsed = urlparse(path)
            # Only include if same domain or relative
            if parsed.netloc and parsed.netloc != self.target_domain:
                return
            path = parsed.path

        # Clean up path
        path = path.split('?')[0].split('#')[0]
        if not path.startswith('/'):
            path = '/' + path

        # Skip invalid paths
        if not self._is_valid_api_path(path):
            return

        key = f"{path}:GET"
        if key not in self.endpoints:
            self.endpoints[key] = APIEndpoint(
                path=path,
                method="GET",
                full_url=f"{self.target}{path}",
                source=source,
            )

    def _is_valid_api_path(self, path: str) -> bool:
        """Check if path looks like a valid API endpoint."""
        if not path or len(path) < 2:
            return False

        # Skip static assets
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.ttf', '.eot']
        if any(path.lower().endswith(ext) for ext in static_extensions):
            return False

        # Skip obvious non-API paths
        skip_patterns = [
            r'^/static/',
            r'^/assets/',
            r'^/images?/',
            r'^/css/',
            r'^/fonts?/',
            r'^/media/',
            r'^javascript:',
            r'^mailto:',
            r'^data:',
            r'^#',
        ]
        for pattern in skip_patterns:
            if re.match(pattern, path, re.IGNORECASE):
                return False

        return True

    def _count_by_source(self) -> Dict[str, int]:
        """Count endpoints by source."""
        counts: Dict[str, int] = {}
        for endpoint in self.endpoints.values():
            source = endpoint.source.split(':')[0]  # Get base source
            counts[source] = counts.get(source, 0) + 1
        return counts

    def _count_by_method(self) -> Dict[str, int]:
        """Count endpoints by HTTP method."""
        counts: Dict[str, int] = {}
        for endpoint in self.endpoints.values():
            counts[endpoint.method] = counts.get(endpoint.method, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"api_endpoints_{self.target_domain}")

        # Save endpoints list
        txt_path = self.output_dir / f"api_endpoints_{self.target_domain}.txt"
        with open(txt_path, "w") as f:
            for endpoint in sorted(self.endpoints.values(), key=lambda e: e.path):
                f.write(f"{endpoint.method} {endpoint.full_url or endpoint.path}\n")
        paths["txt"] = str(txt_path)

        # Save detailed JSON
        detailed_path = self.output_dir / f"api_endpoints_{self.target_domain}_detailed.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "total": len(self.endpoints),
                    "endpoints": [e.to_dict() for e in self.endpoints.values()],
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="API endpoint extraction from multiple sources"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=30, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout")
    parser.add_argument("--no-probe", action="store_true", help="Skip method probing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    extractor = APIEndpointExtractor(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        probe_methods=not args.no_probe,
        verbose=args.verbose,
    )

    result = await extractor.extract()
    paths = extractor.save_results(result)

    print(f"\n{'='*60}")
    print(f"API Endpoint Extraction Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Total Endpoints: {len(extractor.endpoints)}")
    print(f"By Source: {result.stats.get('by_source', {})}")
    print(f"By Method: {result.stats.get('by_method', {})}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    # Show sample endpoints
    print(f"\nSample Endpoints:")
    for endpoint in list(extractor.endpoints.values())[:10]:
        print(f"  {endpoint.method} {endpoint.path} [{endpoint.source}]")


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""
JavaScript bundle analyzer for discovering endpoints, secrets, and sensitive data.

Usage:
    python js_analyzer.py --target https://example.com --output results/
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
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir, calculate_entropy

logger = setup_logging("js_analyzer")


@dataclass
class JSFile:
    """Represents a discovered JavaScript file."""

    url: str
    size: int = 0
    content: str = ""
    endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    auth_patterns: List[str] = field(default_factory=list)
    admin_routes: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    hardcoded_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "size": self.size,
            "endpoints_count": len(self.endpoints),
            "secrets_count": len(self.secrets),
            "domains_count": len(self.domains),
            "endpoints": self.endpoints[:50],  # Limit output
            "secrets": self.secrets,
            "domains": self.domains,
            "source_maps": self.source_maps,
            "auth_patterns": self.auth_patterns,
            "admin_routes": self.admin_routes,
            "api_endpoints": self.api_endpoints[:30],
            "hardcoded_urls": self.hardcoded_urls[:20],
        }


@dataclass
class SecretMatch:
    """Represents a discovered secret/credential."""

    type: str
    value: str
    context: str
    file_url: str
    line_number: int = 0
    confidence: str = "medium"  # low, medium, high

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value[:50] + "..." if len(self.value) > 50 else self.value,
            "context": self.context[:100] if self.context else "",
            "file_url": self.file_url,
            "line_number": self.line_number,
            "confidence": self.confidence,
        }


class JSAnalyzer:
    """
    JavaScript bundle analyzer for security reconnaissance.

    Features:
    - Extract endpoints/API paths from JS files
    - Detect secrets, API keys, and credentials
    - Find hidden domains and subdomains
    - Extract comments and debug info
    - Discover source maps
    """

    # Secret detection patterns with type and confidence
    SECRET_PATTERNS = [
        # API Keys
        (r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "api_key", "high"),
        (r'(?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "secret_key", "high"),

        # AWS
        (r'AKIA[0-9A-Z]{16}', "aws_access_key", "high"),
        (r'(?:aws[_-]?secret|AWS_SECRET)["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', "aws_secret_key", "high"),

        # Google
        (r'AIza[0-9A-Za-z_-]{35}', "google_api_key", "high"),
        (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "google_oauth", "high"),

        # GitHub
        (r'gh[pousr]_[A-Za-z0-9_]{36,}', "github_token", "high"),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', "github_pat", "high"),

        # Stripe
        (r'sk_live_[0-9a-zA-Z]{24,}', "stripe_secret_key", "high"),
        (r'pk_live_[0-9a-zA-Z]{24,}', "stripe_publishable_key", "medium"),
        (r'rk_live_[0-9a-zA-Z]{24,}', "stripe_restricted_key", "high"),

        # Slack
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', "slack_token", "high"),
        (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+', "slack_webhook", "high"),

        # Firebase
        (r'(?:firebase|firestore)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "firebase_key", "medium"),

        # JWT
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "jwt_token", "high"),

        # Private keys
        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "private_key", "high"),

        # Generic patterns
        (r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "password", "medium"),
        (r'(?:token|auth[_-]?token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "auth_token", "medium"),
        (r'(?:bearer|authorization)["\']?\s*[:=]\s*["\'](?:Bearer\s+)?([a-zA-Z0-9_\-\.]+)["\']', "bearer_token", "medium"),

        # Database connections
        (r'(?:mongodb(?:\+srv)?|mysql|postgres|postgresql|redis)://[^\s"\'<>]+', "database_url", "high"),

        # Internal IPs
        (r'(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?', "internal_ip", "medium"),
    ]

    # Endpoint extraction patterns (ENHANCED)
    ENDPOINT_PATTERNS = [
        # API paths - comprehensive patterns
        r'["\'](/api/v?\d*/[a-zA-Z0-9_/\-{}:]+)["\']',
        r'["\'](/v\d+/[a-zA-Z0-9_/\-{}:]+)["\']',
        r'["\'](\.[a-zA-Z0-9_/\-]+(?:\.json|\.xml|\.php|\.asp|\.aspx|\.jsp))["\']',

        # Quoted paths - catch more API routes
        r'["\'](/[a-zA-Z0-9_/-]{2,})["\']',

        # Fetch/axios patterns - enhanced
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*`([^`]+)`',
        r'axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*["\']([^"\']+)["\']',
        r'axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*`([^`]+)`',
        r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',

        # Method calls
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.patch\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',

        # Configuration patterns
        r'baseURL["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiBase["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiEndpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'serverUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'backendUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',

        # Route definitions
        r'(?:url|endpoint|path|route|uri)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'router\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',

        # Template literals with variables
        r'`([^`]*\$\{[^}]+\}[^`]*)`',

        # HTTP URLs in code
        r'https?://[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',

        # GraphQL endpoints
        r'graphql["\']?\s*[:=]\s*["\']([^"\']+)["\']',

        # WebSocket endpoints
        r'wss?://[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
    ]

    # Authentication patterns
    AUTH_PATTERNS = [
        (r'Bearer\s+[a-zA-Z0-9\-_\.]+', "bearer_token_usage"),
        (r'Authorization["\']?\s*[:=]', "authorization_header"),
        (r'["\']Token\s+[a-zA-Z0-9]+["\']', "token_auth"),
        (r'["\']X-API-Key["\']', "api_key_header"),
        (r'["\']X-Auth-Token["\']', "auth_token_header"),
        (r'localStorage\.getItem\(["\']token["\']', "localstorage_token"),
        (r'sessionStorage\.getItem\(["\']token["\']', "sessionstorage_token"),
    ]

    # Admin/internal route patterns
    ADMIN_ROUTE_PATTERNS = [
        r'/admin[/\w]*',
        r'/internal[/\w]*',
        r'/private[/\w]*',
        r'/dashboard[/\w]*',
        r'/manage[/\w]*',
        r'/backend[/\w]*',
        r'/ops[/\w]*',
        r'/staff[/\w]*',
        r'/_[a-zA-Z]+',  # Underscore-prefixed routes
    ]

    # Domain extraction pattern
    DOMAIN_PATTERN = r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)'

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 20,
        depth: int = 2,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.depth = depth
        self.verbose = verbose

        self.js_files: Dict[str, JSFile] = {}
        self.all_endpoints: Set[str] = set()
        self.all_secrets: List[SecretMatch] = []
        self.all_domains: Set[str] = set()
        self.visited_urls: Set[str] = set()
        self.all_admin_routes: Set[str] = set()
        self.all_auth_patterns: Set[str] = set()
        self.all_api_endpoints: Set[str] = set()
        self.all_hardcoded_urls: Set[str] = set()

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def analyze(self) -> ScanResult:
        """Run JS analysis and return results."""
        result = ScanResult(
            tool="js_analyzer",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "depth": self.depth,
            },
        )

        logger.info(f"Starting JS analysis for: {self.target}")

        try:
            # Discover JS files
            await self._discover_js_files()

            # Analyze each JS file
            await self._analyze_all_js()

            # Compile statistics
            result.stats = {
                "js_files_found": len(self.js_files),
                "total_endpoints": len(self.all_endpoints),
                "total_secrets": len(self.all_secrets),
                "total_domains": len(self.all_domains),
                "high_confidence_secrets": sum(1 for s in self.all_secrets if s.confidence == "high"),
                "admin_routes_found": len(self.all_admin_routes),
                "api_endpoints_found": len(self.all_api_endpoints),
                "auth_patterns_detected": len(self.all_auth_patterns),
                "hardcoded_urls_found": len(self.all_hardcoded_urls),
            }

            # Add findings for secrets (high severity)
            for secret in self.all_secrets:
                severity = Severity.HIGH if secret.confidence == "high" else Severity.MEDIUM
                if secret.type in ["private_key", "aws_secret_key", "database_url"]:
                    severity = Severity.CRITICAL

                result.add_finding(Finding(
                    title=f"Exposed {secret.type.replace('_', ' ').title()}",
                    severity=severity,
                    description=f"Sensitive {secret.type} found in JavaScript file",
                    url=secret.file_url,
                    evidence=f"Value: {secret.value[:30]}{'...' if len(secret.value) > 30 else ''}\nContext: {secret.context[:100]}",
                    metadata={
                        "secret_type": secret.type,
                        "confidence": secret.confidence,
                        "line_number": secret.line_number,
                    },
                    cwe_id="CWE-798",
                    remediation="Remove hardcoded credentials and use environment variables or secure secret management",
                ))

            # Add info findings for interesting endpoints
            api_endpoints = [e for e in self.all_endpoints if '/api/' in e or '/v1/' in e or '/v2/' in e]
            if api_endpoints:
                result.add_finding(Finding(
                    title=f"API Endpoints Discovered ({len(api_endpoints)} found)",
                    severity=Severity.INFO,
                    description="API endpoints extracted from JavaScript files",
                    url=self.target,
                    metadata={"endpoints": list(api_endpoints)[:50]},
                ))

            # Add findings for external domains
            external_domains = [d for d in self.all_domains if self.target_domain not in d]
            if external_domains:
                result.add_finding(Finding(
                    title=f"External Domains Referenced ({len(external_domains)} found)",
                    severity=Severity.INFO,
                    description="External domains found in JavaScript files",
                    url=self.target,
                    metadata={"domains": list(external_domains)[:50]},
                ))

            # Add findings for admin routes
            if self.all_admin_routes:
                result.add_finding(Finding(
                    title=f"Admin/Internal Routes Discovered ({len(self.all_admin_routes)} found)",
                    severity=Severity.MEDIUM,
                    description="Admin or internal routes found in JavaScript files - these may expose sensitive functionality",
                    url=self.target,
                    metadata={"routes": list(self.all_admin_routes)[:30]},
                ))

            # Add findings for auth patterns
            if self.all_auth_patterns:
                result.add_finding(Finding(
                    title=f"Authentication Patterns Detected ({len(self.all_auth_patterns)} types)",
                    severity=Severity.INFO,
                    description="Authentication mechanisms detected in JavaScript code",
                    url=self.target,
                    metadata={"patterns": list(self.all_auth_patterns)},
                ))

            # Add findings for hardcoded URLs
            if self.all_hardcoded_urls:
                result.add_finding(Finding(
                    title=f"Hardcoded URLs Found ({len(self.all_hardcoded_urls)} found)",
                    severity=Severity.LOW,
                    description="Hardcoded URLs found in JavaScript - may reveal internal services or development endpoints",
                    url=self.target,
                    metadata={"urls": list(self.all_hardcoded_urls)[:20]},
                ))

        except Exception as e:
            result.add_error(f"Analysis error: {e}")
            logger.error(f"Analysis error: {e}")

        result.finalize()
        return result

    async def _discover_js_files(self):
        """Discover JavaScript files from the target."""
        logger.info("Discovering JavaScript files...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=2,
        ) as client:
            # Fetch main page
            response = await client.get(self.target)
            if not response.ok:
                logger.warning(f"Failed to fetch target: {response.status}")
                return

            self.visited_urls.add(self.target)

            # Extract JS URLs from HTML
            js_urls = self._extract_js_urls(response.body, self.target)
            logger.info(f"Found {len(js_urls)} JS files in main page")

            # Also check common JS paths
            common_paths = [
                "/static/js/main.js",
                "/static/js/app.js",
                "/static/js/bundle.js",
                "/js/main.js",
                "/js/app.js",
                "/dist/main.js",
                "/dist/bundle.js",
                "/assets/js/app.js",
                "/build/static/js/main.js",
                "/_next/static/chunks/main.js",
                "/_next/static/chunks/webpack.js",
            ]

            for path in common_paths:
                js_urls.add(urljoin(self.target, path))

            # Fetch and register JS files
            semaphore = asyncio.Semaphore(self.threads)

            async def fetch_js(url: str):
                async with semaphore:
                    if url in self.js_files:
                        return
                    try:
                        resp = await client.get(url)
                        if resp.ok and resp.body and self._is_javascript(resp):
                            self.js_files[url] = JSFile(
                                url=url,
                                size=len(resp.body),
                                content=resp.body,
                            )
                            logger.debug(f"Found JS: {url} ({len(resp.body)} bytes)")

                            # Check for source maps
                            source_map = self._find_source_map(resp.body, url)
                            if source_map:
                                self.js_files[url].source_maps.append(source_map)
                    except Exception as e:
                        logger.debug(f"Error fetching {url}: {e}")

            tasks = [fetch_js(url) for url in js_urls]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Discovered {len(self.js_files)} JavaScript files")

    def _extract_js_urls(self, html: str, base_url: str) -> Set[str]:
        """Extract JavaScript URLs from HTML."""
        urls = set()

        # Script src attributes
        script_pattern = r'<script[^>]*\ssrc=["\']([^"\']+)["\']'
        for match in re.finditer(script_pattern, html, re.IGNORECASE):
            src = match.group(1)
            if src.endswith('.js') or '.js?' in src or '/js/' in src:
                urls.add(urljoin(base_url, src))

        # Module imports
        import_pattern = r'(?:import|from)\s+["\']([^"\']+\.js)["\']'
        for match in re.finditer(import_pattern, html):
            urls.add(urljoin(base_url, match.group(1)))

        # Webpack chunks
        webpack_pattern = r'["\']([^"\']*(?:chunk|bundle|vendor)[^"\']*\.js)["\']'
        for match in re.finditer(webpack_pattern, html):
            urls.add(urljoin(base_url, match.group(1)))

        return urls

    def _is_javascript(self, response) -> bool:
        """Check if response is JavaScript content."""
        content_type = response.headers.get("content-type", "").lower()
        if "javascript" in content_type or "application/x-javascript" in content_type:
            return True
        # Check content starts with JS-like patterns
        body_start = response.body[:500].strip()
        js_indicators = ["function", "var ", "let ", "const ", "import ", "export ", "(function", "!function", "//", "/*"]
        return any(body_start.startswith(ind) or f"\n{ind}" in body_start for ind in js_indicators)

    def _find_source_map(self, content: str, js_url: str) -> Optional[str]:
        """Find source map URL in JS content."""
        patterns = [
            r'//[#@]\s*sourceMappingURL=([^\s]+)',
            r'/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*/',
        ]
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                map_url = match.group(1)
                if map_url.startswith('data:'):
                    return None  # Inline source map
                return urljoin(js_url, map_url)
        return None

    async def _analyze_all_js(self):
        """Analyze all discovered JS files."""
        logger.info("Analyzing JavaScript files...")

        for url, js_file in self.js_files.items():
            if not js_file.content:
                continue

            # Extract endpoints
            endpoints = self._extract_endpoints(js_file.content)
            js_file.endpoints = list(endpoints)
            self.all_endpoints.update(endpoints)

            # Extract secrets
            secrets = self._extract_secrets(js_file.content, url)
            js_file.secrets = [s.to_dict() for s in secrets]
            self.all_secrets.extend(secrets)

            # Extract domains
            domains = self._extract_domains(js_file.content)
            js_file.domains = list(domains)
            self.all_domains.update(domains)

            # Extract comments (might contain debug info)
            comments = self._extract_comments(js_file.content)
            js_file.comments = comments[:20]  # Limit stored comments

            # NEW: Extract authentication patterns
            auth_patterns = self._extract_auth_patterns(js_file.content)
            js_file.auth_patterns = auth_patterns
            self.all_auth_patterns.update(auth_patterns)

            # NEW: Extract admin/internal routes
            admin_routes = self._extract_admin_routes(js_file.content)
            js_file.admin_routes = admin_routes
            self.all_admin_routes.update(admin_routes)

            # NEW: Categorize API endpoints
            api_endpoints = self._categorize_api_endpoints(endpoints)
            js_file.api_endpoints = api_endpoints
            self.all_api_endpoints.update(api_endpoints)

            # NEW: Extract hardcoded URLs
            hardcoded_urls = self._extract_hardcoded_urls(js_file.content)
            js_file.hardcoded_urls = hardcoded_urls
            self.all_hardcoded_urls.update(hardcoded_urls)

        logger.info(f"Analysis complete: {len(self.all_endpoints)} endpoints, {len(self.all_secrets)} secrets, "
                   f"{len(self.all_admin_routes)} admin routes, {len(self.all_auth_patterns)} auth patterns")

    def _extract_endpoints(self, content: str) -> Set[str]:
        """Extract API endpoints from JS content."""
        endpoints = set()

        for pattern in self.ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip()

                # Filter out obvious non-endpoints
                if self._is_valid_endpoint(endpoint):
                    endpoints.add(endpoint)

        return endpoints

    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Check if string looks like a valid endpoint."""
        if not endpoint or len(endpoint) < 2:
            return False

        # Skip common false positives
        skip_patterns = [
            r'^https?://$',
            r'^[a-zA-Z]+$',  # Single words
            r'^\d+$',  # Just numbers
            r'^[./]+$',  # Just dots/slashes
            r'\.(?:png|jpg|jpeg|gif|svg|ico|css|woff|ttf|eot)$',  # Static assets
            r'^data:',  # Data URIs
            r'^javascript:',  # JS URIs
            r'^mailto:',  # Email links
            r'^#',  # Anchors
        ]

        for pattern in skip_patterns:
            if re.match(pattern, endpoint, re.IGNORECASE):
                return False

        return True

    def _extract_secrets(self, content: str, file_url: str) -> List[SecretMatch]:
        """Extract secrets and credentials from JS content."""
        secrets = []
        lines = content.split('\n')

        for secret_type, pattern, confidence in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1) if match.lastindex else match.group(0)

                # Skip if value looks like a placeholder
                if self._is_placeholder(value):
                    continue

                # Find line number
                line_num = content[:match.start()].count('\n') + 1

                # Get context (surrounding text)
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ')

                secrets.append(SecretMatch(
                    type=secret_type,
                    value=value,
                    context=context,
                    file_url=file_url,
                    line_number=line_num,
                    confidence=confidence,
                ))

        # Additional entropy-based detection for unknown secrets
        secrets.extend(self._detect_high_entropy_strings(content, file_url))

        return secrets

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder."""
        placeholders = [
            "your_api_key", "your-api-key", "api_key_here", "xxx", "yyy",
            "placeholder", "example", "test", "demo", "sample", "fake",
            "changeme", "password123", "secret123", "undefined", "null",
            "process.env", "ENV_VAR", "INSERT_", "REPLACE_", "TODO",
        ]
        value_lower = value.lower()
        return any(p in value_lower for p in placeholders)

    def _detect_high_entropy_strings(self, content: str, file_url: str) -> List[SecretMatch]:
        """Detect high-entropy strings that might be secrets."""
        secrets = []

        # Pattern for quoted strings
        pattern = r'["\']([a-zA-Z0-9+/=_\-]{32,})["\']'

        for match in re.finditer(pattern, content):
            value = match.group(1)

            # Skip if looks like a hash or encoded data we already detect
            if self._is_placeholder(value):
                continue

            entropy = calculate_entropy(value)

            # High entropy strings (> 4.5) are likely secrets
            if entropy > 4.5 and len(value) >= 32:
                line_num = content[:match.start()].count('\n') + 1
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
                context = content[start:end].replace('\n', ' ')

                secrets.append(SecretMatch(
                    type="high_entropy_string",
                    value=value,
                    context=context,
                    file_url=file_url,
                    line_number=line_num,
                    confidence="low",
                ))

        return secrets[:10]  # Limit high entropy findings

    def _extract_domains(self, content: str) -> Set[str]:
        """Extract domains from JS content."""
        domains = set()

        for match in re.finditer(self.DOMAIN_PATTERN, content):
            domain = match.group(1).lower()

            # Skip common non-interesting domains
            skip_domains = [
                "w3.org", "schema.org", "example.com", "localhost",
                "google.com", "googleapis.com", "gstatic.com",
                "facebook.com", "twitter.com", "jquery.com",
                "cloudflare.com", "unpkg.com", "jsdelivr.net",
                "npmjs.com", "github.com", "githubusercontent.com",
            ]

            if not any(skip in domain for skip in skip_domains):
                if '.' in domain and len(domain) > 4:
                    domains.add(domain)

        return domains

    def _extract_comments(self, content: str) -> List[str]:
        """Extract potentially interesting comments."""
        comments = []

        # Single-line comments
        single_pattern = r'//\s*(.+?)(?:\n|$)'
        for match in re.finditer(single_pattern, content):
            comment = match.group(1).strip()
            if self._is_interesting_comment(comment):
                comments.append(comment[:200])

        # Multi-line comments
        multi_pattern = r'/\*\s*([\s\S]*?)\s*\*/'
        for match in re.finditer(multi_pattern, content):
            comment = match.group(1).strip()
            if self._is_interesting_comment(comment):
                comments.append(comment[:200])

        return comments

    def _is_interesting_comment(self, comment: str) -> bool:
        """Check if comment contains interesting information."""
        keywords = [
            "todo", "fixme", "hack", "bug", "xxx", "debug",
            "password", "secret", "key", "token", "auth",
            "admin", "internal", "private", "api", "endpoint",
            "vulnerability", "security", "danger", "warning",
            "temporary", "hardcoded", "deprecated",
        ]
        comment_lower = comment.lower()
        return any(kw in comment_lower for kw in keywords) and len(comment) > 10

    def _extract_auth_patterns(self, content: str) -> List[str]:
        """Extract authentication patterns from JS content."""
        patterns_found = []

        for pattern, pattern_type in self.AUTH_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                if pattern_type not in patterns_found:
                    patterns_found.append(pattern_type)

        return patterns_found

    def _extract_admin_routes(self, content: str) -> List[str]:
        """Extract admin/internal routes from JS content."""
        admin_routes = set()

        for pattern in self.ADMIN_ROUTE_PATTERNS:
            for match in re.finditer(f'["\']({pattern})["\']', content, re.IGNORECASE):
                route = match.group(1)
                if len(route) > 2 and len(route) < 100:
                    admin_routes.add(route)

        return list(admin_routes)

    def _categorize_api_endpoints(self, endpoints: Set[str]) -> List[str]:
        """Categorize and prioritize API endpoints."""
        api_endpoints = []

        # Priority patterns for API endpoints
        api_indicators = [
            '/api/',
            '/v1/',
            '/v2/',
            '/v3/',
            '/rest/',
            '/graphql',
            '/query',
            '/mutation',
        ]

        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()
            if any(ind in endpoint_lower for ind in api_indicators):
                api_endpoints.append(endpoint)

        # Sort by likely importance (shorter paths often more interesting)
        return sorted(api_endpoints, key=len)[:50]

    def _extract_hardcoded_urls(self, content: str) -> List[str]:
        """Extract hardcoded URLs from JS content."""
        urls = set()

        # Full URL pattern
        url_pattern = r'https?://[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'

        for match in re.finditer(url_pattern, content):
            url = match.group(0)
            # Filter out common CDN/library URLs
            skip_domains = [
                'googleapis.com',
                'gstatic.com',
                'cloudflare.com',
                'jsdelivr.net',
                'unpkg.com',
                'cdnjs.com',
                'bootstrap',
                'jquery',
                'fontawesome',
                'w3.org',
                'schema.org',
            ]
            if not any(skip in url.lower() for skip in skip_domains):
                urls.add(url)

        return list(urls)[:30]

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        # Save via result manager
        paths = self.result_manager.save(result, f"js_analysis_{self.target_domain}")

        # Save endpoints list
        endpoints_path = self.output_dir / f"endpoints_{self.target_domain}.txt"
        with open(endpoints_path, "w") as f:
            for endpoint in sorted(self.all_endpoints):
                f.write(f"{endpoint}\n")
        paths["endpoints"] = str(endpoints_path)

        # Save detailed JSON
        detailed_path = self.output_dir / f"js_analysis_{self.target_domain}_detailed.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "js_files": [js.to_dict() for js in self.js_files.values()],
                    "all_endpoints": list(self.all_endpoints),
                    "all_secrets": [s.to_dict() for s in self.all_secrets],
                    "all_domains": list(self.all_domains),
                    "all_admin_routes": list(self.all_admin_routes),
                    "all_auth_patterns": list(self.all_auth_patterns),
                    "all_api_endpoints": list(self.all_api_endpoints),
                    "all_hardcoded_urls": list(self.all_hardcoded_urls),
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        # Save admin routes list (if any found)
        if self.all_admin_routes:
            admin_path = self.output_dir / f"admin_routes_{self.target_domain}.txt"
            with open(admin_path, "w") as f:
                for route in sorted(self.all_admin_routes):
                    f.write(f"{route}\n")
            paths["admin_routes"] = str(admin_path)

        # Save API endpoints list
        if self.all_api_endpoints:
            api_path = self.output_dir / f"api_endpoints_{self.target_domain}.txt"
            with open(api_path, "w") as f:
                for endpoint in sorted(self.all_api_endpoints):
                    f.write(f"{endpoint}\n")
            paths["api_endpoints"] = str(api_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="JavaScript bundle analyzer for endpoint and secret discovery"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth for JS discovery")
    parser.add_argument("--deep-extract", action="store_true", help="Enable deep extraction (admin routes, auth patterns)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    analyzer = JSAnalyzer(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        depth=args.depth,
        verbose=args.verbose,
    )

    result = await analyzer.analyze()
    paths = analyzer.save_results(result)

    print(f"\n{'='*60}")
    print(f"JavaScript Analysis Complete: {args.target}")
    print(f"{'='*60}")
    print(f"JS Files Found: {len(analyzer.js_files)}")
    print(f"Endpoints Discovered: {len(analyzer.all_endpoints)}")
    print(f"API Endpoints: {len(analyzer.all_api_endpoints)}")
    print(f"Admin Routes: {len(analyzer.all_admin_routes)}")
    print(f"Secrets Found: {len(analyzer.all_secrets)}")
    print(f"Domains Found: {len(analyzer.all_domains)}")
    print(f"Auth Patterns: {len(analyzer.all_auth_patterns)}")
    print(f"Hardcoded URLs: {len(analyzer.all_hardcoded_urls)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    # Show high-confidence secrets
    high_confidence = [s for s in analyzer.all_secrets if s.confidence == "high"]
    if high_confidence:
        print(f"\n*** HIGH CONFIDENCE SECRETS FOUND: {len(high_confidence)} ***")
        for secret in high_confidence[:5]:
            print(f"  - {secret.type}: {secret.value[:30]}...")

    # Show admin routes
    if analyzer.all_admin_routes:
        print(f"\n*** ADMIN/INTERNAL ROUTES ***")
        for route in sorted(analyzer.all_admin_routes)[:10]:
            print(f"  - {route}")
        if len(analyzer.all_admin_routes) > 10:
            print(f"  ... and {len(analyzer.all_admin_routes) - 10} more")

    # Show auth patterns
    if analyzer.all_auth_patterns:
        print(f"\n*** AUTH PATTERNS DETECTED ***")
        for pattern in analyzer.all_auth_patterns:
            print(f"  - {pattern}")


if __name__ == "__main__":
    asyncio.run(main())

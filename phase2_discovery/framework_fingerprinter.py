#!/usr/bin/env python3
"""
Web framework fingerprinter and framework-specific endpoint tester.

Usage:
    python framework_fingerprinter.py -t https://example.com -o results/
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
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("framework_fingerprinter")


@dataclass
class FrameworkFingerprint:
    """Represents a detected framework."""

    name: str
    version: str = ""
    confidence: str = "medium"  # low, medium, high
    indicators: List[str] = field(default_factory=list)
    recommended_paths: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "recommended_paths": self.recommended_paths,
        }


@dataclass
class DiscoveredPath:
    """Represents a discovered framework-specific path."""

    path: str
    status: int
    content_length: int
    title: str = ""
    framework: str = ""
    path_type: str = ""  # admin, debug, api, etc.
    sensitive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "content_length": self.content_length,
            "title": self.title,
            "framework": self.framework,
            "path_type": self.path_type,
            "sensitive": self.sensitive,
        }


class FrameworkFingerprinter:
    """
    Web framework fingerprinter with framework-specific endpoint testing.

    Features:
    - Rails Detection: X-Runtime header, Rails 404, _session cookies, Sidekiq
    - Django Detection: csrfmiddlewaretoken, Django debug page, admin
    - Node.js/Express Detection: X-Powered-By, API patterns
    - Active Admin Detection: active_admin in JS/CSS
    - Laravel, Spring Boot, ASP.NET detection
    - Framework-specific sensitive endpoint discovery
    """

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        "rails": {
            "headers": [
                (r"x-runtime", "X-Runtime header present"),
                (r"x-request-id", "X-Request-Id header (Rails)"),
            ],
            "body": [
                (r"_[a-z]+_session", "Rails session cookie pattern"),
                (r"authenticity_token", "Rails CSRF token"),
                (r"rails/info", "Rails info route"),
                (r"action_controller", "ActionController reference"),
                (r"active_record", "ActiveRecord reference"),
                (r"turbo-frame|turbo-stream", "Hotwire/Turbo (Rails)"),
            ],
            "cookies": [
                (r"_.*_session", "Rails session cookie"),
            ],
            "paths": [
                "/admin",
                "/admin/login",
                "/rails/info",
                "/rails/info/routes",
                "/rails/info/properties",
                "/rails/mailers",
                "/sidekiq",
                "/sidekiq/queues",
                "/letter_opener",
                "/assets/application.js",
                "/assets/application.css",
            ],
        },
        "django": {
            "headers": [
                (r"x-frame-options:\s*SAMEORIGIN", "Django default X-Frame-Options"),
            ],
            "body": [
                (r"csrfmiddlewaretoken", "Django CSRF token"),
                (r"django", "Django reference"),
                (r"__admin_media_prefix__", "Django admin media"),
                (r"You're seeing this error because you have.*DEBUG = True", "Django debug mode"),
            ],
            "cookies": [
                (r"csrftoken", "Django CSRF cookie"),
                (r"sessionid", "Django session cookie"),
            ],
            "paths": [
                "/admin/",
                "/admin/login/",
                "/__debug__/",
                "/static/admin/",
                "/api/",
                "/api/v1/",
                "/graphql/",
            ],
        },
        "express": {
            "headers": [
                (r"x-powered-by:\s*express", "Express.js header"),
            ],
            "body": [
                (r"express", "Express reference"),
                (r"Cannot GET|Cannot POST", "Express default error"),
            ],
            "cookies": [
                (r"connect\.sid", "Express session cookie"),
            ],
            "paths": [
                "/api",
                "/api/v1",
                "/api/v2",
                "/graphql",
                "/health",
                "/healthz",
                "/status",
                "/metrics",
                "/docs",
                "/api-docs",
                "/swagger",
            ],
        },
        "laravel": {
            "headers": [
                (r"x-powered-by:\s*php", "PHP header (Laravel candidate)"),
            ],
            "body": [
                (r"laravel", "Laravel reference"),
                (r"_token", "Laravel CSRF token"),
                (r"laravel_session", "Laravel session"),
                (r"Whoops!", "Laravel Whoops error handler"),
                (r"Illuminate\\", "Laravel Illuminate namespace"),
            ],
            "cookies": [
                (r"laravel_session", "Laravel session cookie"),
                (r"XSRF-TOKEN", "Laravel XSRF token"),
            ],
            "paths": [
                "/login",
                "/register",
                "/password/reset",
                "/admin",
                "/dashboard",
                "/api",
                "/api/v1",
                "/telescope",
                "/horizon",
                "/nova",
                "/storage",
            ],
        },
        "spring_boot": {
            "headers": [
                (r"x-application-context", "Spring Boot context header"),
            ],
            "body": [
                (r"Whitelabel Error Page", "Spring Boot error page"),
                (r"springframework", "Spring Framework reference"),
                (r"There was an unexpected error.*type=", "Spring error message"),
            ],
            "cookies": [
                (r"JSESSIONID", "Java session cookie"),
            ],
            "paths": [
                "/actuator",
                "/actuator/health",
                "/actuator/info",
                "/actuator/env",
                "/actuator/mappings",
                "/actuator/beans",
                "/actuator/configprops",
                "/actuator/heapdump",
                "/api",
                "/api/v1",
                "/swagger-ui.html",
                "/v2/api-docs",
                "/v3/api-docs",
                "/h2-console",
            ],
        },
        "aspnet": {
            "headers": [
                (r"x-powered-by:\s*asp\.net", "ASP.NET header"),
                (r"x-aspnet-version", "ASP.NET version header"),
                (r"x-aspnetmvc-version", "ASP.NET MVC version"),
            ],
            "body": [
                (r"__VIEWSTATE", "ASP.NET ViewState"),
                (r"__EVENTVALIDATION", "ASP.NET EventValidation"),
                (r"asp\.net", "ASP.NET reference"),
            ],
            "cookies": [
                (r"ASP\.NET_SessionId", "ASP.NET session cookie"),
                (r"\.ASPXAUTH", "ASP.NET auth cookie"),
            ],
            "paths": [
                "/admin",
                "/login.aspx",
                "/default.aspx",
                "/web.config",
                "/elmah.axd",
                "/trace.axd",
                "/api",
                "/swagger",
            ],
        },
        "active_admin": {
            "headers": [],
            "body": [
                (r"active_admin", "Active Admin reference"),
                (r"activeadmin", "ActiveAdmin reference"),
                (r"aa-.*css|aa-.*js", "Active Admin assets"),
                (r"batch_actions_index", "Active Admin batch actions"),
            ],
            "cookies": [],
            "paths": [
                "/admin",
                "/admin/login",
                "/admin/dashboard",
                "/admin/users",
                "/admin/comments",
            ],
        },
        "wordpress": {
            "headers": [],
            "body": [
                (r"wp-content", "WordPress content directory"),
                (r"wp-includes", "WordPress includes"),
                (r"wp-json", "WordPress REST API"),
            ],
            "cookies": [
                (r"wordpress_", "WordPress cookie"),
            ],
            "paths": [
                "/wp-admin",
                "/wp-admin/admin-ajax.php",
                "/wp-login.php",
                "/wp-json/wp/v2/users",
                "/wp-json/wp/v2/posts",
                "/xmlrpc.php",
                "/readme.html",
            ],
        },
        "nextjs": {
            "headers": [
                (r"x-powered-by:\s*next\.js", "Next.js header"),
            ],
            "body": [
                (r"__NEXT_DATA__", "Next.js data"),
                (r"_next/static", "Next.js static assets"),
                (r"next/dist", "Next.js distribution"),
            ],
            "cookies": [],
            "paths": [
                "/_next/static/chunks/main.js",
                "/_next/static/chunks/webpack.js",
                "/api",
                "/api/health",
            ],
        },
    }

    # Sensitive paths by framework
    SENSITIVE_PATHS = {
        "rails": ["/rails/info/routes", "/sidekiq", "/letter_opener"],
        "django": ["/__debug__/"],
        "spring_boot": ["/actuator/env", "/actuator/heapdump", "/actuator/configprops", "/h2-console"],
        "laravel": ["/telescope", "/.env"],
        "aspnet": ["/elmah.axd", "/trace.axd", "/web.config"],
        "wordpress": ["/wp-json/wp/v2/users", "/xmlrpc.php"],
    }

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 20,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose

        self.detected_frameworks: List[FrameworkFingerprint] = []
        self.discovered_paths: Dict[str, DiscoveredPath] = {}
        self.initial_response: Optional[HTTPResponse] = None

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def fingerprint(self) -> ScanResult:
        """Run framework fingerprinting and return results."""
        result = ScanResult(
            tool="framework_fingerprinter",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
            },
        )

        logger.info(f"Starting framework fingerprinting for: {self.target}")

        try:
            # 1. Fetch initial response
            await self._fetch_initial_response()

            if not self.initial_response:
                result.add_error("Failed to fetch initial response")
                result.finalize()
                return result

            # 2. Detect frameworks from initial response
            self._detect_frameworks_from_response(self.initial_response)

            # 3. Test framework-specific paths
            await self._test_framework_paths()

            # 4. Additional detection based on path responses
            self._refine_detection()

            # Compile statistics
            result.stats = {
                "frameworks_detected": len(self.detected_frameworks),
                "paths_discovered": len(self.discovered_paths),
                "sensitive_paths": sum(1 for p in self.discovered_paths.values() if p.sensitive),
            }

            # Add findings for detected frameworks
            for framework in self.detected_frameworks:
                severity = Severity.INFO
                if framework.name in ["active_admin", "spring_boot"]:
                    severity = Severity.LOW

                result.add_finding(Finding(
                    title=f"Framework Detected: {framework.name.replace('_', ' ').title()}",
                    severity=severity,
                    description=f"Web framework {framework.name} detected with {framework.confidence} confidence",
                    url=self.target,
                    metadata=framework.to_dict(),
                ))

            # Add findings for discovered paths
            for path, discovered in self.discovered_paths.items():
                severity = Severity.INFO
                if discovered.sensitive:
                    severity = Severity.HIGH
                elif discovered.path_type == "admin":
                    severity = Severity.MEDIUM
                elif discovered.status in [200, 401, 403]:
                    severity = Severity.LOW

                result.add_finding(Finding(
                    title=f"Path: {path}",
                    severity=severity,
                    description=f"Framework-specific path discovered ({discovered.framework})",
                    url=urljoin(self.target, path),
                    metadata=discovered.to_dict(),
                ))

        except Exception as e:
            result.add_error(f"Fingerprinting error: {e}")
            logger.error(f"Fingerprinting error: {e}")

        result.finalize()
        return result

    async def _fetch_initial_response(self):
        """Fetch initial response from target."""
        logger.info("Fetching initial response...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=2,
        ) as client:
            self.initial_response = await client.get(self.target)

    def _detect_frameworks_from_response(self, response: HTTPResponse):
        """Detect frameworks from response headers, body, and cookies."""
        logger.info("Detecting frameworks from initial response...")

        headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items()).lower()
        body_lower = response.body.lower()
        cookies_str = response.headers.get("set-cookie", "").lower()

        for framework_name, patterns in self.FRAMEWORK_PATTERNS.items():
            indicators = []
            confidence_score = 0

            # Check headers
            for pattern, indicator in patterns.get("headers", []):
                if re.search(pattern, headers_str, re.IGNORECASE):
                    indicators.append(indicator)
                    confidence_score += 2

            # Check body
            for pattern, indicator in patterns.get("body", []):
                if re.search(pattern, body_lower, re.IGNORECASE):
                    indicators.append(indicator)
                    confidence_score += 1

            # Check cookies
            for pattern, indicator in patterns.get("cookies", []):
                if re.search(pattern, cookies_str, re.IGNORECASE):
                    indicators.append(indicator)
                    confidence_score += 2

            # Determine confidence
            if indicators:
                if confidence_score >= 4:
                    confidence = "high"
                elif confidence_score >= 2:
                    confidence = "medium"
                else:
                    confidence = "low"

                # Extract version if possible
                version = self._extract_version(framework_name, headers_str, body_lower)

                fingerprint = FrameworkFingerprint(
                    name=framework_name,
                    version=version,
                    confidence=confidence,
                    indicators=indicators,
                    recommended_paths=patterns.get("paths", []),
                )

                self.detected_frameworks.append(fingerprint)
                logger.info(f"Detected {framework_name} with {confidence} confidence")

    def _extract_version(self, framework: str, headers: str, body: str) -> str:
        """Extract framework version if possible."""
        version_patterns = {
            "rails": r"rails[/ ](\d+\.\d+(?:\.\d+)?)",
            "django": r"django[/ ](\d+\.\d+(?:\.\d+)?)",
            "laravel": r"laravel[/ ](\d+\.\d+(?:\.\d+)?)",
            "spring_boot": r"spring[- ]boot[/ ](\d+\.\d+(?:\.\d+)?)",
            "aspnet": r"x-aspnet(?:mvc)?-version:\s*(\d+\.\d+(?:\.\d+)?)",
            "wordpress": r"wordpress[/ ](\d+\.\d+(?:\.\d+)?)",
        }

        pattern = version_patterns.get(framework)
        if pattern:
            combined = headers + body
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                return match.group(1)

        return ""

    async def _test_framework_paths(self):
        """Test framework-specific paths."""
        logger.info("Testing framework-specific paths...")

        # Collect all paths to test
        paths_to_test = set()

        for framework in self.detected_frameworks:
            paths_to_test.update(framework.recommended_paths)

        # If no frameworks detected, test all paths
        if not self.detected_frameworks:
            for patterns in self.FRAMEWORK_PATTERNS.values():
                paths_to_test.update(patterns.get("paths", []))

        logger.info(f"Testing {len(paths_to_test)} paths...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def test_path(path: str):
                async with semaphore:
                    url = urljoin(self.target, path)

                    try:
                        response = await client.get(url)

                        # Interesting status codes
                        if response.status in [200, 401, 403, 500]:
                            title = self._extract_title(response.body)
                            framework = self._determine_path_framework(path)
                            path_type = self._determine_path_type(path)
                            sensitive = self._is_sensitive_path(path, framework)

                            self.discovered_paths[path] = DiscoveredPath(
                                path=path,
                                status=response.status,
                                content_length=len(response.body),
                                title=title,
                                framework=framework,
                                path_type=path_type,
                                sensitive=sensitive,
                            )

                            # Check for additional framework indicators
                            self._check_additional_indicators(response, framework)

                            logger.debug(f"Found: {path} [{response.status}]")

                    except Exception as e:
                        logger.debug(f"Error testing {path}: {e}")

            tasks = [test_path(path) for path in paths_to_test]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Discovered {len(self.discovered_paths)} paths")

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML."""
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:100]
        return ""

    def _determine_path_framework(self, path: str) -> str:
        """Determine which framework a path belongs to."""
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            if path in patterns.get("paths", []):
                return framework
        return "unknown"

    def _determine_path_type(self, path: str) -> str:
        """Determine path type."""
        path_lower = path.lower()

        if "admin" in path_lower:
            return "admin"
        elif "api" in path_lower:
            return "api"
        elif "debug" in path_lower or "trace" in path_lower:
            return "debug"
        elif "login" in path_lower or "auth" in path_lower:
            return "auth"
        elif "actuator" in path_lower or "health" in path_lower:
            return "monitoring"
        elif "swagger" in path_lower or "api-docs" in path_lower:
            return "docs"
        else:
            return "other"

    def _is_sensitive_path(self, path: str, framework: str) -> bool:
        """Check if path is sensitive."""
        sensitive_paths = self.SENSITIVE_PATHS.get(framework, [])
        return path in sensitive_paths

    def _check_additional_indicators(self, response: HTTPResponse, framework: str):
        """Check for additional framework indicators in response."""
        # This could reveal more about the detected framework
        body_lower = response.body.lower()

        # Check for debug mode indicators
        debug_indicators = [
            "debug = true",
            "development mode",
            "stack trace",
            "exception",
            "error_log",
        ]

        for indicator in debug_indicators:
            if indicator in body_lower:
                logger.warning(f"Debug indicator found: {indicator}")

    def _refine_detection(self):
        """Refine framework detection based on discovered paths."""
        # If certain paths exist, increase confidence
        for path, discovered in self.discovered_paths.items():
            if discovered.status == 200:
                for framework in self.detected_frameworks:
                    if discovered.framework == framework.name:
                        if framework.confidence == "low":
                            framework.confidence = "medium"
                        elif framework.confidence == "medium":
                            framework.confidence = "high"

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"framework_{self.target_domain}")

        # Save detailed JSON
        detailed_path = self.output_dir / f"framework_{self.target_domain}.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "frameworks": [fw.to_dict() for fw in self.detected_frameworks],
                    "paths": [p.to_dict() for p in self.discovered_paths.values()],
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="Web framework fingerprinter and endpoint discovery"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    fingerprinter = FrameworkFingerprinter(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
    )

    result = await fingerprinter.fingerprint()
    paths = fingerprinter.save_results(result)

    print(f"\n{'='*60}")
    print(f"Framework Fingerprinting Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Frameworks Detected: {len(fingerprinter.detected_frameworks)}")
    print(f"Paths Discovered: {len(fingerprinter.discovered_paths)}")
    print(f"Sensitive Paths: {sum(1 for p in fingerprinter.discovered_paths.values() if p.sensitive)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if fingerprinter.detected_frameworks:
        print(f"\n*** DETECTED FRAMEWORKS ***")
        for fw in fingerprinter.detected_frameworks:
            version = f" v{fw.version}" if fw.version else ""
            print(f"  - {fw.name.replace('_', ' ').title()}{version} [{fw.confidence}]")
            for indicator in fw.indicators[:3]:
                print(f"      * {indicator}")

    if fingerprinter.discovered_paths:
        print(f"\n*** DISCOVERED PATHS ***")
        for path, p in sorted(fingerprinter.discovered_paths.items()):
            sensitive = " [SENSITIVE!]" if p.sensitive else ""
            print(f"  [{p.status}] {path} ({p.framework}){sensitive}")


if __name__ == "__main__":
    asyncio.run(main())

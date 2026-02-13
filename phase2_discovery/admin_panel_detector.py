#!/usr/bin/env python3
"""
Admin panel detection and analysis module.

Usage:
    python admin_panel_detector.py -t https://example.com -o results/
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

logger = setup_logging("admin_panel_detector")


@dataclass
class AdminPanel:
    """Represents a discovered admin panel."""

    url: str
    path: str
    status: int
    panel_type: str  # active_admin, django, wordpress, custom, etc.
    title: str = ""
    login_form: bool = False
    registration_available: bool = False
    csrf_token_name: str = ""
    form_fields: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    content_length: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "path": self.path,
            "status": self.status,
            "panel_type": self.panel_type,
            "title": self.title,
            "login_form": self.login_form,
            "registration_available": self.registration_available,
            "csrf_token_name": self.csrf_token_name,
            "form_fields": self.form_fields,
            "technologies": self.technologies,
            "content_length": self.content_length,
        }


class AdminPanelDetector:
    """
    Admin panel detection and analysis module.

    Features:
    - Common admin paths detection
    - Panel type identification (Active Admin, Django, WordPress, custom)
    - Login form field extraction
    - CSRF token detection
    - Registration endpoint discovery
    - Technology detection from login page
    - Default credential testing (with rate limiting)
    """

    # Common admin paths
    ADMIN_PATHS = [
        # Generic admin paths
        "/admin",
        "/admin/",
        "/administrator",
        "/administrator/",
        "/admin/login",
        "/admin/login/",
        "/adminpanel",
        "/admin-panel",

        # Management panels
        "/manage",
        "/management",
        "/manager",
        "/panel",
        "/cpanel",
        "/controlpanel",
        "/control-panel",

        # Dashboard paths
        "/dashboard",
        "/dashboard/login",
        "/console",
        "/backend",
        "/backoffice",
        "/back-office",

        # CMS-specific
        "/wp-admin",
        "/wp-admin/",
        "/wp-login.php",
        "/user/login",
        "/user/signin",
        "/users/sign_in",

        # API/Modern admin
        "/admin/api",
        "/api/admin",
        "/_admin",
        "/~admin",
        "/admin.php",
        "/admin.html",
        "/admin.asp",
        "/admin.aspx",

        # Localized paths
        "/administrateur",
        "/administrador",
        "/verwaltung",

        # Framework-specific
        "/admin/dashboard",
        "/admin/index",
        "/admin/home",
        "/admin/main",

        # Operator/Internal
        "/ops",
        "/ops/login",
        "/internal",
        "/internal/admin",
        "/staff",
        "/staff/login",
        "/merchant",
        "/merchant/login",
        "/partner",
        "/partner/login",
        "/vendor",
        "/vendor/login",
    ]

    # Admin panel type patterns
    PANEL_PATTERNS = {
        "active_admin": [
            (r"active_admin", "body"),
            (r"activeadmin", "body"),
            (r"aa_", "body"),
            (r"batch_actions", "body"),
            (r"Active Admin", "title"),
        ],
        "django_admin": [
            (r"django", "body"),
            (r"csrfmiddlewaretoken", "body"),
            (r"Django administration", "title"),
            (r"/admin/login/", "url"),
        ],
        "wordpress": [
            (r"wp-login", "url"),
            (r"WordPress", "body"),
            (r"wp-admin", "url"),
            (r"Log In.*WordPress", "title"),
        ],
        "joomla": [
            (r"joomla", "body"),
            (r"/administrator/", "url"),
            (r"Joomla", "title"),
        ],
        "drupal": [
            (r"drupal", "body"),
            (r"/user/login", "url"),
            (r"Drupal", "body"),
        ],
        "laravel_nova": [
            (r"laravel", "body"),
            (r"nova", "body"),
            (r"Laravel Nova", "title"),
        ],
        "rails_admin": [
            (r"rails_admin", "body"),
            (r"RailsAdmin", "title"),
        ],
        "phpmyadmin": [
            (r"phpmyadmin", "url"),
            (r"phpMyAdmin", "body"),
        ],
        "grafana": [
            (r"grafana", "body"),
            (r"Grafana", "title"),
        ],
        "kibana": [
            (r"kibana", "body"),
            (r"Kibana", "title"),
        ],
    }

    # CSRF token patterns
    CSRF_PATTERNS = [
        (r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']', "csrf_token"),
        (r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']', "_token"),
        (r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']', "csrfmiddlewaretoken"),
        (r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']', "authenticity_token"),
        (r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']', "_csrf"),
        (r'name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)["\']', "__RequestVerificationToken"),
        (r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']', "meta_csrf"),
    ]

    # Common default credentials
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("demo", "demo"),
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 20,
        test_credentials: bool = False,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.test_credentials = test_credentials
        self.verbose = verbose

        self.discovered_panels: Dict[str, AdminPanel] = {}
        self.registration_endpoints: List[str] = []

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def detect(self) -> ScanResult:
        """Run admin panel detection and return results."""
        result = ScanResult(
            tool="admin_panel_detector",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "test_credentials": self.test_credentials,
            },
        )

        logger.info(f"Starting admin panel detection for: {self.target}")

        try:
            # 1. Probe admin paths
            await self._probe_admin_paths()

            # 2. Analyze discovered panels
            await self._analyze_panels()

            # 3. Check for registration endpoints
            await self._check_registration()

            # 4. Test default credentials (if enabled)
            if self.test_credentials:
                await self._test_default_credentials()

            # Compile statistics
            result.stats = {
                "panels_discovered": len(self.discovered_panels),
                "login_forms_found": sum(1 for p in self.discovered_panels.values() if p.login_form),
                "registration_endpoints": len(self.registration_endpoints),
                "panel_types": self._get_panel_types(),
            }

            # Add findings
            for path, panel in self.discovered_panels.items():
                severity = Severity.MEDIUM  # Admin panels are always noteworthy

                if panel.registration_available:
                    severity = Severity.HIGH  # Open registration is concerning

                if panel.status == 200 and panel.login_form:
                    severity = Severity.MEDIUM

                result.add_finding(Finding(
                    title=f"Admin Panel: {panel.panel_type.replace('_', ' ').title()}",
                    severity=severity,
                    description=f"Admin panel discovered at {panel.path}",
                    url=panel.url,
                    metadata=panel.to_dict(),
                ))

            # Add registration endpoint findings
            for reg_path in self.registration_endpoints:
                result.add_finding(Finding(
                    title="Admin Registration Endpoint",
                    severity=Severity.HIGH,
                    description="Admin registration endpoint found - may allow unauthorized account creation",
                    url=urljoin(self.target, reg_path),
                ))

        except Exception as e:
            result.add_error(f"Detection error: {e}")
            logger.error(f"Detection error: {e}")

        result.finalize()
        return result

    async def _probe_admin_paths(self):
        """Probe all admin paths."""
        logger.info(f"Probing {len(self.ADMIN_PATHS)} admin paths...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
            follow_redirects=False,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def probe_path(path: str):
                async with semaphore:
                    url = urljoin(self.target, path)

                    try:
                        response = await client.get(url)

                        # Interesting status codes (200, 401, 403, 302)
                        if response.status in [200, 401, 403, 302, 301]:
                            # Detect panel type
                            panel_type = self._detect_panel_type(response, path)
                            title = self._extract_title(response.body)

                            panel = AdminPanel(
                                url=url,
                                path=path,
                                status=response.status,
                                panel_type=panel_type,
                                title=title,
                                headers=dict(response.headers),
                                content_length=len(response.body),
                            )

                            # Check for login form
                            if self._has_login_form(response.body):
                                panel.login_form = True
                                panel.form_fields = self._extract_form_fields(response.body)
                                panel.csrf_token_name = self._extract_csrf_token_name(response.body)

                            # Detect technologies
                            panel.technologies = self._detect_technologies(response)

                            self.discovered_panels[path] = panel
                            logger.info(f"Found admin panel: {path} [{response.status}] - {panel_type}")

                    except Exception as e:
                        logger.debug(f"Error probing {path}: {e}")

            tasks = [probe_path(path) for path in self.ADMIN_PATHS]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Discovered {len(self.discovered_panels)} admin panels")

    def _detect_panel_type(self, response: HTTPResponse, path: str) -> str:
        """Detect the type of admin panel."""
        body_lower = response.body.lower()
        title = self._extract_title(response.body).lower()

        for panel_type, patterns in self.PANEL_PATTERNS.items():
            for pattern, source in patterns:
                if source == "body" and re.search(pattern, body_lower, re.IGNORECASE):
                    return panel_type
                elif source == "title" and re.search(pattern, title, re.IGNORECASE):
                    return panel_type
                elif source == "url" and re.search(pattern, path, re.IGNORECASE):
                    return panel_type

        return "custom"

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML."""
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:200]
        return ""

    def _has_login_form(self, html: str) -> bool:
        """Check if page has a login form."""
        login_indicators = [
            r'<form[^>]*(?:login|signin|auth)',
            r'<input[^>]*type=["\']password["\']',
            r'name=["\'](?:password|passwd|pwd)["\']',
            r'id=["\'](?:password|passwd|pwd)["\']',
            r'(?:username|email|login)["\']',
        ]

        for pattern in login_indicators:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False

    def _extract_form_fields(self, html: str) -> List[str]:
        """Extract form field names from HTML."""
        fields = []

        # Input fields
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\']'
        for match in re.finditer(input_pattern, html, re.IGNORECASE):
            field_name = match.group(1)
            if field_name not in fields:
                fields.append(field_name)

        return fields[:20]  # Limit to 20 fields

    def _extract_csrf_token_name(self, html: str) -> str:
        """Extract CSRF token field name."""
        for pattern, token_name in self.CSRF_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE):
                return token_name
        return ""

    def _detect_technologies(self, response: HTTPResponse) -> List[str]:
        """Detect technologies from response."""
        technologies = []
        body_lower = response.body.lower()
        headers_str = str(response.headers).lower()

        tech_patterns = [
            (r"bootstrap", "Bootstrap"),
            (r"jquery", "jQuery"),
            (r"react", "React"),
            (r"vue", "Vue.js"),
            (r"angular", "Angular"),
            (r"tailwind", "Tailwind CSS"),
            (r"materialize", "Materialize"),
            (r"bulma", "Bulma"),
            (r"foundation", "Foundation"),
        ]

        for pattern, tech in tech_patterns:
            if re.search(pattern, body_lower) or re.search(pattern, headers_str):
                if tech not in technologies:
                    technologies.append(tech)

        return technologies

    async def _analyze_panels(self):
        """Perform deeper analysis on discovered panels."""
        logger.info("Analyzing discovered panels...")

        for path, panel in self.discovered_panels.items():
            # Follow redirects to final destination
            if panel.status in [301, 302]:
                redirect_url = panel.headers.get("location", "")
                if redirect_url:
                    logger.debug(f"Panel {path} redirects to {redirect_url}")

    async def _check_registration(self):
        """Check for registration endpoints."""
        logger.info("Checking for registration endpoints...")

        registration_paths = [
            "/admin/register",
            "/admin/signup",
            "/admin/sign_up",
            "/admin/users/new",
            "/users/sign_up",
            "/register",
            "/signup",
            "/sign_up",
        ]

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for path in registration_paths:
                url = urljoin(self.target, path)

                try:
                    response = await client.get(url)

                    if response.status == 200:
                        # Check if it's actually a registration page
                        if self._is_registration_page(response.body):
                            self.registration_endpoints.append(path)

                            # Update associated admin panel
                            admin_path = path.rsplit("/", 1)[0] or "/admin"
                            if admin_path in self.discovered_panels:
                                self.discovered_panels[admin_path].registration_available = True

                            logger.warning(f"Registration endpoint found: {path}")

                except Exception as e:
                    logger.debug(f"Error checking {path}: {e}")

    def _is_registration_page(self, html: str) -> bool:
        """Check if page is a registration page."""
        registration_indicators = [
            r'<form[^>]*(?:register|signup|sign.up)',
            r'(?:create|register|sign.up)[^<]*account',
            r'(?:confirm|repeat)[^<]*password',
            r'already have an account',
        ]

        for pattern in registration_indicators:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False

    async def _test_default_credentials(self):
        """Test default credentials on discovered panels."""
        logger.info("Testing default credentials...")

        panels_with_login = [
            p for p in self.discovered_panels.values()
            if p.login_form and p.status == 200
        ]

        if not panels_with_login:
            logger.info("No login forms found for credential testing")
            return

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for panel in panels_with_login[:3]:  # Limit to 3 panels
                logger.info(f"Testing credentials on {panel.path}")

                for username, password in self.DEFAULT_CREDENTIALS[:5]:  # Limit attempts
                    try:
                        # Build login data
                        login_data = {}

                        # Find username field
                        for field in panel.form_fields:
                            field_lower = field.lower()
                            if any(u in field_lower for u in ["user", "email", "login", "name"]):
                                login_data[field] = username
                            elif any(p in field_lower for p in ["pass", "pwd"]):
                                login_data[field] = password

                        # Add CSRF token if detected
                        if panel.csrf_token_name:
                            # Would need to fetch fresh token - simplified for now
                            pass

                        if len(login_data) >= 2:
                            response = await client.post(
                                panel.url,
                                data=login_data,
                                headers={"Content-Type": "application/x-www-form-urlencoded"},
                            )

                            # Check for successful login indicators
                            if self._is_login_success(response):
                                logger.critical(f"DEFAULT CREDENTIALS WORK: {username}:{password} on {panel.path}")

                        # Rate limit
                        await asyncio.sleep(1)

                    except Exception as e:
                        logger.debug(f"Error testing credentials: {e}")

    def _is_login_success(self, response: HTTPResponse) -> bool:
        """Check if login was successful."""
        # Redirect to dashboard often indicates success
        if response.status in [301, 302]:
            location = response.headers.get("location", "").lower()
            if any(s in location for s in ["dashboard", "home", "index", "welcome"]):
                return True

        # Check for failure indicators (if absent, might be success)
        failure_indicators = [
            "invalid",
            "incorrect",
            "wrong",
            "failed",
            "error",
            "denied",
        ]

        body_lower = response.body.lower()
        has_failure = any(ind in body_lower for ind in failure_indicators)

        return response.status == 200 and not has_failure

    def _get_panel_types(self) -> Dict[str, int]:
        """Get count of panel types."""
        types: Dict[str, int] = {}
        for panel in self.discovered_panels.values():
            types[panel.panel_type] = types.get(panel.panel_type, 0) + 1
        return types

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"admin_panels_{self.target_domain}")

        # Save detailed JSON
        detailed_path = self.output_dir / f"admin_panels_{self.target_domain}.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "panels": [p.to_dict() for p in self.discovered_panels.values()],
                    "registration_endpoints": self.registration_endpoints,
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="Admin panel detection and analysis"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--test-creds", action="store_true", help="Test default credentials")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    detector = AdminPanelDetector(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        test_credentials=args.test_creds,
        verbose=args.verbose,
    )

    result = await detector.detect()
    paths = detector.save_results(result)

    print(f"\n{'='*60}")
    print(f"Admin Panel Detection Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Panels Discovered: {len(detector.discovered_panels)}")
    print(f"Login Forms Found: {sum(1 for p in detector.discovered_panels.values() if p.login_form)}")
    print(f"Registration Endpoints: {len(detector.registration_endpoints)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if detector.discovered_panels:
        print(f"\n*** DISCOVERED ADMIN PANELS ***")
        for path, panel in detector.discovered_panels.items():
            login = "[LOGIN]" if panel.login_form else ""
            reg = "[REGISTRATION!]" if panel.registration_available else ""
            print(f"  [{panel.status}] {path} - {panel.panel_type} {login} {reg}")
            if panel.title:
                print(f"        Title: {panel.title[:50]}")

    if detector.registration_endpoints:
        print(f"\n*** WARNING: REGISTRATION ENDPOINTS ***")
        for reg in detector.registration_endpoints:
            print(f"  - {reg}")


if __name__ == "__main__":
    asyncio.run(main())

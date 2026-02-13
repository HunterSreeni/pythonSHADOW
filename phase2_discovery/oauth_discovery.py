#!/usr/bin/env python3
"""
OAuth endpoint discovery and testing module.

Usage:
    python oauth_discovery.py -t https://api.example.com -o results/
"""

import argparse
import asyncio
import base64
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("oauth_discovery")


@dataclass
class OAuthEndpoint:
    """Represents a discovered OAuth endpoint."""

    url: str
    endpoint_type: str  # token, authorize, revoke, etc.
    status: int
    response_body: str = ""
    error_message: str = ""
    supported_grant_types: List[str] = field(default_factory=list)
    info_disclosure: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "endpoint_type": self.endpoint_type,
            "status": self.status,
            "error_message": self.error_message,
            "supported_grant_types": self.supported_grant_types,
            "info_disclosure": self.info_disclosure,
        }


@dataclass
class OAuthConfig:
    """Represents discovered OAuth configuration."""

    issuer: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    scopes_supported: List[str] = field(default_factory=list)
    grant_types_supported: List[str] = field(default_factory=list)
    response_types_supported: List[str] = field(default_factory=list)
    raw_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "userinfo_endpoint": self.userinfo_endpoint,
            "jwks_uri": self.jwks_uri,
            "scopes_supported": self.scopes_supported,
            "grant_types_supported": self.grant_types_supported,
            "response_types_supported": self.response_types_supported,
        }


class OAuthDiscovery:
    """
    OAuth endpoint discovery and testing module.

    Features:
    - Probe OAuth endpoints: /oauth/token, /oauth/authorize, etc.
    - Test all grant types: client_credentials, password, authorization_code
    - Check .well-known/openid-configuration and oauth-authorization-server
    - Extract error messages for information disclosure
    - Test Basic Auth header variations
    - Detect misconfigurations and vulnerabilities
    """

    # OAuth endpoint paths to probe
    OAUTH_PATHS = [
        # Token endpoints
        "/oauth/token",
        "/oauth2/token",
        "/token",
        "/api/oauth/token",
        "/api/token",
        "/auth/token",
        "/connect/token",
        "/realms/master/protocol/openid-connect/token",

        # Authorization endpoints
        "/oauth/authorize",
        "/oauth2/authorize",
        "/authorize",
        "/auth/authorize",
        "/api/oauth/authorize",
        "/connect/authorize",
        "/realms/master/protocol/openid-connect/auth",

        # Revoke endpoints
        "/oauth/revoke",
        "/oauth2/revoke",
        "/revoke",
        "/api/oauth/revoke",
        "/connect/revocation",

        # Token info/introspect
        "/oauth/token/info",
        "/oauth2/tokeninfo",
        "/tokeninfo",
        "/oauth/introspect",
        "/oauth2/introspect",
        "/introspect",
        "/connect/introspect",

        # Applications/clients
        "/oauth/applications",
        "/oauth2/applications",
        "/api/oauth/applications",
        "/oauth/clients",

        # User info
        "/oauth/userinfo",
        "/userinfo",
        "/connect/userinfo",
        "/api/me",

        # JWKS
        "/oauth/jwks",
        "/.well-known/jwks.json",
        "/jwks",
        "/realms/master/protocol/openid-connect/certs",
    ]

    # Well-known configuration paths
    WELL_KNOWN_PATHS = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration/",
        "/oauth/.well-known/openid-configuration",
        "/api/.well-known/openid-configuration",
    ]

    # Grant types to test
    GRANT_TYPES = [
        "client_credentials",
        "password",
        "authorization_code",
        "refresh_token",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "urn:ietf:params:oauth:grant-type:device_code",
    ]

    # Common client IDs to test
    COMMON_CLIENT_IDS = [
        "admin",
        "client",
        "api",
        "web",
        "mobile",
        "app",
        "default",
        "public",
        "test",
        "demo",
        "internal",
    ]

    # Error patterns that reveal information
    INFO_DISCLOSURE_PATTERNS = [
        (r"invalid_client", "Client validation error reveals client existence"),
        (r"client_id.*not found", "Client ID enumeration possible"),
        (r"invalid_grant", "Grant type validation error"),
        (r"unsupported_grant_type", "Reveals supported grant types"),
        (r"unauthorized_client", "Client authorization info disclosed"),
        (r"invalid_scope", "Scope validation error"),
        (r"invalid_redirect_uri", "Redirect URI validation info"),
        (r"access_denied", "Access control information"),
        (r"version|build|internal|debug", "Internal version/debug info"),
        (r"stack\s*trace|exception|error.*line\s*\d+", "Stack trace leaked"),
        (r"sql|database|query", "Database error leaked"),
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 10,
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

        self.discovered_endpoints: Dict[str, OAuthEndpoint] = {}
        self.oauth_config: Optional[OAuthConfig] = None
        self.info_disclosures: List[Dict[str, str]] = []

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def discover(self) -> ScanResult:
        """Run OAuth discovery and return results."""
        result = ScanResult(
            tool="oauth_discovery",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
            },
        )

        logger.info(f"Starting OAuth discovery for: {self.target}")

        try:
            # 1. Check well-known configuration
            await self._check_well_known_config()

            # 2. Probe OAuth endpoints
            await self._probe_oauth_endpoints()

            # 3. Test grant types on discovered token endpoints
            await self._test_grant_types()

            # 4. Test with common client IDs
            await self._test_common_clients()

            # 5. Test Basic Auth variations
            await self._test_basic_auth()

            # Compile statistics
            result.stats = {
                "endpoints_discovered": len(self.discovered_endpoints),
                "well_known_found": self.oauth_config is not None,
                "info_disclosures": len(self.info_disclosures),
                "endpoints_by_type": self._count_by_type(),
            }

            # Add findings
            # Well-known config finding
            if self.oauth_config:
                result.add_finding(Finding(
                    title="OAuth Configuration Discovered",
                    severity=Severity.INFO,
                    description="OpenID Connect / OAuth configuration found",
                    url=self.target,
                    metadata=self.oauth_config.to_dict(),
                ))

            # Endpoint findings
            for path, endpoint in self.discovered_endpoints.items():
                severity = Severity.INFO
                if endpoint.info_disclosure:
                    severity = Severity.LOW
                if endpoint.supported_grant_types:
                    severity = Severity.MEDIUM

                result.add_finding(Finding(
                    title=f"OAuth Endpoint: {endpoint.endpoint_type}",
                    severity=severity,
                    description=f"OAuth {endpoint.endpoint_type} endpoint discovered",
                    url=endpoint.url,
                    metadata={
                        "status": endpoint.status,
                        "grant_types": endpoint.supported_grant_types,
                        "info_disclosure": endpoint.info_disclosure,
                    },
                ))

            # Info disclosure findings
            for disclosure in self.info_disclosures:
                result.add_finding(Finding(
                    title=f"OAuth Information Disclosure",
                    severity=Severity.LOW,
                    description=disclosure.get("description", ""),
                    url=disclosure.get("url", ""),
                    evidence=disclosure.get("evidence", ""),
                ))

        except Exception as e:
            result.add_error(f"Discovery error: {e}")
            logger.error(f"Discovery error: {e}")

        result.finalize()
        return result

    async def _check_well_known_config(self):
        """Check for .well-known OAuth configuration."""
        logger.info("Checking well-known OAuth configuration...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=2,
        ) as client:
            for path in self.WELL_KNOWN_PATHS:
                url = urljoin(self.target, path)

                try:
                    response = await client.get(url)

                    if response.status == 200:
                        try:
                            config_data = json.loads(response.body)

                            self.oauth_config = OAuthConfig(
                                issuer=config_data.get("issuer", ""),
                                authorization_endpoint=config_data.get("authorization_endpoint", ""),
                                token_endpoint=config_data.get("token_endpoint", ""),
                                userinfo_endpoint=config_data.get("userinfo_endpoint", ""),
                                jwks_uri=config_data.get("jwks_uri", ""),
                                scopes_supported=config_data.get("scopes_supported", []),
                                grant_types_supported=config_data.get("grant_types_supported", []),
                                response_types_supported=config_data.get("response_types_supported", []),
                                raw_config=config_data,
                            )

                            logger.info(f"Found OAuth config at: {path}")

                            # Add endpoints from config to probe list
                            if self.oauth_config.token_endpoint:
                                self._add_discovered_endpoint(
                                    self.oauth_config.token_endpoint,
                                    "token",
                                    200,
                                )
                            if self.oauth_config.authorization_endpoint:
                                self._add_discovered_endpoint(
                                    self.oauth_config.authorization_endpoint,
                                    "authorize",
                                    200,
                                )

                            return

                        except json.JSONDecodeError:
                            logger.debug(f"Invalid JSON at {path}")

                except Exception as e:
                    logger.debug(f"Error checking {path}: {e}")

    async def _probe_oauth_endpoints(self):
        """Probe common OAuth endpoints."""
        logger.info("Probing OAuth endpoints...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def probe_endpoint(path: str):
                async with semaphore:
                    url = urljoin(self.target, path)

                    try:
                        # Try GET first
                        response = await client.get(url)

                        # Interesting status codes
                        if response.status in [200, 400, 401, 403, 405, 500]:
                            endpoint_type = self._determine_endpoint_type(path)

                            endpoint = OAuthEndpoint(
                                url=url,
                                endpoint_type=endpoint_type,
                                status=response.status,
                                response_body=response.body[:2000],
                                headers=dict(response.headers),
                            )

                            # Check for info disclosure
                            self._check_info_disclosure(endpoint, response.body, url)

                            self.discovered_endpoints[path] = endpoint
                            logger.debug(f"Found endpoint: {path} [{response.status}]")

                    except Exception as e:
                        logger.debug(f"Error probing {path}: {e}")

            tasks = [probe_endpoint(path) for path in self.OAUTH_PATHS]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Discovered {len(self.discovered_endpoints)} OAuth endpoints")

    async def _test_grant_types(self):
        """Test grant types on discovered token endpoints."""
        logger.info("Testing grant types...")

        token_endpoints = [
            ep for ep in self.discovered_endpoints.values()
            if ep.endpoint_type == "token"
        ]

        if not token_endpoints:
            return

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for endpoint in token_endpoints:
                supported_grants = []

                for grant_type in self.GRANT_TYPES:
                    try:
                        # POST with grant_type
                        data = {
                            "grant_type": grant_type,
                            "client_id": "test",
                            "client_secret": "test",
                        }

                        # Add grant-specific params
                        if grant_type == "password":
                            data.update({"username": "test", "password": "test"})
                        elif grant_type == "authorization_code":
                            data.update({"code": "test", "redirect_uri": "http://localhost"})
                        elif grant_type == "refresh_token":
                            data.update({"refresh_token": "test"})

                        response = await client.post(
                            endpoint.url,
                            data=data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )

                        # Analyze response
                        body_lower = response.body.lower()

                        # If we get anything other than "unsupported_grant_type", it might be supported
                        if response.status in [200, 400, 401]:
                            if "unsupported_grant_type" not in body_lower:
                                supported_grants.append(grant_type)
                                logger.debug(f"Grant type {grant_type} may be supported at {endpoint.url}")

                        # Check for info disclosure
                        self._check_info_disclosure(endpoint, response.body, endpoint.url)

                    except Exception as e:
                        logger.debug(f"Error testing grant {grant_type}: {e}")

                endpoint.supported_grant_types = supported_grants

    async def _test_common_clients(self):
        """Test with common client IDs."""
        logger.info("Testing common client IDs...")

        token_endpoints = [
            ep for ep in self.discovered_endpoints.values()
            if ep.endpoint_type == "token"
        ]

        if not token_endpoints:
            return

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for endpoint in token_endpoints:
                for client_id in self.COMMON_CLIENT_IDS:
                    try:
                        data = {
                            "grant_type": "client_credentials",
                            "client_id": client_id,
                            "client_secret": "test",
                        }

                        response = await client.post(
                            endpoint.url,
                            data=data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )

                        # Check for client enumeration
                        body_lower = response.body.lower()

                        # Different responses for different clients = enumeration possible
                        if "invalid_client" not in body_lower and response.status != 401:
                            self.info_disclosures.append({
                                "url": endpoint.url,
                                "description": f"Client ID '{client_id}' may exist (different response)",
                                "evidence": response.body[:200],
                            })

                    except Exception as e:
                        logger.debug(f"Error testing client {client_id}: {e}")

    async def _test_basic_auth(self):
        """Test Basic Auth header variations."""
        logger.info("Testing Basic Auth variations...")

        token_endpoints = [
            ep for ep in self.discovered_endpoints.values()
            if ep.endpoint_type == "token"
        ]

        if not token_endpoints:
            return

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            for endpoint in token_endpoints:
                # Test Basic Auth
                credentials = base64.b64encode(b"admin:admin").decode()

                try:
                    response = await client.post(
                        endpoint.url,
                        data={"grant_type": "client_credentials"},
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Authorization": f"Basic {credentials}",
                        },
                    )

                    if response.status == 200:
                        self.info_disclosures.append({
                            "url": endpoint.url,
                            "description": "Basic auth with admin:admin returned 200",
                            "evidence": response.body[:200],
                        })
                        logger.warning(f"Weak credentials accepted at {endpoint.url}")

                except Exception as e:
                    logger.debug(f"Error testing Basic Auth: {e}")

    def _determine_endpoint_type(self, path: str) -> str:
        """Determine endpoint type from path."""
        path_lower = path.lower()

        if "token" in path_lower and "info" not in path_lower:
            return "token"
        elif "authorize" in path_lower or "auth" in path_lower:
            return "authorize"
        elif "revoke" in path_lower or "revocation" in path_lower:
            return "revoke"
        elif "introspect" in path_lower or "tokeninfo" in path_lower:
            return "introspect"
        elif "application" in path_lower or "client" in path_lower:
            return "applications"
        elif "userinfo" in path_lower or "/me" in path_lower:
            return "userinfo"
        elif "jwks" in path_lower or "certs" in path_lower:
            return "jwks"
        else:
            return "unknown"

    def _add_discovered_endpoint(self, url: str, endpoint_type: str, status: int):
        """Add endpoint to discovered list."""
        path = urlparse(url).path
        if path not in self.discovered_endpoints:
            self.discovered_endpoints[path] = OAuthEndpoint(
                url=url,
                endpoint_type=endpoint_type,
                status=status,
            )

    def _check_info_disclosure(self, endpoint: OAuthEndpoint, body: str, url: str):
        """Check for information disclosure in response."""
        body_lower = body.lower()

        for pattern, description in self.INFO_DISCLOSURE_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                if description not in endpoint.info_disclosure:
                    endpoint.info_disclosure.append(description)

                    self.info_disclosures.append({
                        "url": url,
                        "description": description,
                        "evidence": body[:200],
                    })

    def _count_by_type(self) -> Dict[str, int]:
        """Count endpoints by type."""
        counts: Dict[str, int] = {}
        for endpoint in self.discovered_endpoints.values():
            counts[endpoint.endpoint_type] = counts.get(endpoint.endpoint_type, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"oauth_discovery_{self.target_domain}")

        # Save detailed JSON
        detailed_path = self.output_dir / f"oauth_{self.target_domain}.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "oauth_config": self.oauth_config.to_dict() if self.oauth_config else None,
                    "endpoints": [ep.to_dict() for ep in self.discovered_endpoints.values()],
                    "info_disclosures": self.info_disclosures,
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="OAuth endpoint discovery and testing"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    discoverer = OAuthDiscovery(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
    )

    result = await discoverer.discover()
    paths = discoverer.save_results(result)

    print(f"\n{'='*60}")
    print(f"OAuth Discovery Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Endpoints Discovered: {len(discoverer.discovered_endpoints)}")
    print(f"Well-Known Config: {'Found' if discoverer.oauth_config else 'Not Found'}")
    print(f"Info Disclosures: {len(discoverer.info_disclosures)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if discoverer.oauth_config:
        print(f"\n*** OAUTH CONFIGURATION ***")
        print(f"  Issuer: {discoverer.oauth_config.issuer}")
        print(f"  Token Endpoint: {discoverer.oauth_config.token_endpoint}")
        print(f"  Grant Types: {', '.join(discoverer.oauth_config.grant_types_supported)}")

    if discoverer.discovered_endpoints:
        print(f"\n*** DISCOVERED ENDPOINTS ***")
        for path, ep in discoverer.discovered_endpoints.items():
            grants = f" [Grants: {', '.join(ep.supported_grant_types)}]" if ep.supported_grant_types else ""
            info = f" [INFO LEAK]" if ep.info_disclosure else ""
            print(f"  [{ep.status}] {ep.endpoint_type}: {path}{grants}{info}")


if __name__ == "__main__":
    asyncio.run(main())

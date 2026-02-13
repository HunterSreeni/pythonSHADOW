#!/usr/bin/env python3
"""
OpenAPI/Swagger specification discovery and analysis module.

Usage:
    python openapi_discovery.py --target https://example.com --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import yaml

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("openapi_discovery")


@dataclass
class APIOperation:
    """Represents an API operation from OpenAPI spec."""

    path: str
    method: str
    operation_id: str = ""
    summary: str = ""
    description: str = ""
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Dict[str, Any] = field(default_factory=dict)
    responses: Dict[str, Any] = field(default_factory=dict)
    security: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    deprecated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "operation_id": self.operation_id,
            "summary": self.summary,
            "description": self.description[:200] if self.description else "",
            "parameters": self.parameters,
            "security": self.security,
            "tags": self.tags,
            "deprecated": self.deprecated,
        }


@dataclass
class OpenAPISpec:
    """Represents an OpenAPI specification."""

    url: str
    version: str = ""
    title: str = ""
    description: str = ""
    base_url: str = ""
    servers: List[str] = field(default_factory=list)
    operations: List[APIOperation] = field(default_factory=list)
    security_schemes: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "version": self.version,
            "title": self.title,
            "description": self.description[:500] if self.description else "",
            "base_url": self.base_url,
            "servers": self.servers,
            "operations_count": len(self.operations),
            "operations": [op.to_dict() for op in self.operations],
            "security_schemes": list(self.security_schemes.keys()),
            "tags": self.tags,
        }


class OpenAPIDiscovery:
    """
    OpenAPI/Swagger specification discovery and analysis.

    Features:
    - Multiple endpoint discovery
    - Swagger 2.0 and OpenAPI 3.x support
    - Endpoint enumeration
    - Security scheme analysis
    - Parameter extraction
    - Authentication detection
    """

    # Common paths for OpenAPI/Swagger specs
    OPENAPI_PATHS = [
        # Swagger UI
        "/swagger", "/swagger-ui", "/swagger-ui.html",
        "/swagger/index.html", "/api/swagger",

        # OpenAPI specs
        "/openapi", "/openapi.json", "/openapi.yaml",
        "/api/openapi", "/api/openapi.json", "/api/openapi.yaml",

        # Swagger specs
        "/swagger.json", "/swagger.yaml",
        "/api/swagger.json", "/api/swagger.yaml",
        "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",

        # API documentation
        "/api-docs", "/api-docs.json", "/api/docs",
        "/docs", "/docs/api", "/documentation",

        # Version-specific
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/api/v1/swagger.json", "/api/v2/swagger.json",

        # Framework-specific
        "/redoc", "/api/redoc",
        "/rapidoc", "/api/rapidoc",

        # Other common patterns
        "/.well-known/openapi.json",
        "/api/schema", "/api/spec",
        "/spec", "/spec.json", "/spec.yaml",
    ]

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
        self.target = normalize_url(target).rstrip('/')
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose

        self.specs: List[OpenAPISpec] = []
        self.all_operations: List[APIOperation] = []
        self.security_issues: List[Dict[str, str]] = []

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def discover(self) -> ScanResult:
        """Run OpenAPI discovery and return results."""
        result = ScanResult(
            tool="openapi_discovery",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
            },
        )

        logger.info(f"Starting OpenAPI discovery for: {self.target}")

        try:
            # Discover OpenAPI specs
            await self._discover_specs()

            if not self.specs:
                # Try to find specs from main page
                await self._discover_from_html()

            if not self.specs:
                result.add_finding(Finding(
                    title="No OpenAPI/Swagger Specification Found",
                    severity=Severity.INFO,
                    description="No publicly accessible API documentation was found",
                    url=self.target,
                ))
            else:
                # Add findings for discovered specs
                for spec in self.specs:
                    result.add_finding(Finding(
                        title=f"OpenAPI Specification Found: {spec.title or 'Untitled'}",
                        severity=Severity.LOW,
                        description=f"OpenAPI {spec.version} specification discovered with {len(spec.operations)} endpoints",
                        url=spec.url,
                        metadata={
                            "version": spec.version,
                            "endpoints": len(spec.operations),
                            "security_schemes": list(spec.security_schemes.keys()),
                        },
                    ))

                # Analyze security
                self._analyze_security()

                # Add security issue findings
                for issue in self.security_issues:
                    result.add_finding(Finding(
                        title=issue["title"],
                        severity=Severity(issue["severity"]),
                        description=issue["description"],
                        url=issue.get("url", self.target),
                        remediation=issue.get("remediation", ""),
                    ))

                # Add findings for sensitive endpoints
                for op in self.all_operations:
                    if self._is_sensitive_endpoint(op):
                        result.add_finding(Finding(
                            title=f"Sensitive Endpoint: {op.method.upper()} {op.path}",
                            severity=Severity.MEDIUM,
                            description=f"Potentially sensitive API endpoint: {op.summary or op.description[:100] if op.description else 'No description'}",
                            url=f"{self.target}{op.path}",
                            metadata={
                                "method": op.method,
                                "operation_id": op.operation_id,
                                "security": op.security,
                            },
                        ))

            # Calculate statistics
            result.stats = {
                "specs_found": len(self.specs),
                "total_operations": len(self.all_operations),
                "operations_by_method": self._count_by_method(),
                "operations_by_tag": self._count_by_tag(),
                "security_issues": len(self.security_issues),
            }

        except Exception as e:
            result.add_error(f"Discovery error: {e}")
            logger.error(f"Discovery error: {e}")

        result.finalize()
        return result

    async def _discover_specs(self):
        """Discover OpenAPI specifications."""
        logger.info("Searching for OpenAPI specifications...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def check_path(path: str):
                async with semaphore:
                    url = f"{self.target}{path}"
                    try:
                        response = await client.get(url)

                        if response.ok and response.body:
                            spec = self._parse_spec(response.body, url)
                            if spec:
                                self.specs.append(spec)
                                logger.info(f"Found spec: {url}")

                    except Exception as e:
                        logger.debug(f"Error checking {url}: {e}")

            tasks = [check_path(path) for path in self.OPENAPI_PATHS]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Found {len(self.specs)} OpenAPI specifications")

    async def _discover_from_html(self):
        """Try to discover specs from main page HTML."""
        logger.info("Searching HTML for OpenAPI references...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            response = await client.get(self.target)
            if not response.ok:
                return

            # Look for swagger/openapi URLs in HTML
            patterns = [
                r'(?:url|spec|swagger|openapi)["\']?\s*[:=]\s*["\']([^"\']+(?:swagger|openapi|api-docs)[^"\']*\.(?:json|yaml))["\']',
                r'href=["\']([^"\']*(?:swagger|openapi|api-docs)[^"\']*)["\']',
                r'src=["\']([^"\']*swagger[^"\']*)["\']',
            ]

            urls = set()
            for pattern in patterns:
                for match in re.finditer(pattern, response.body, re.IGNORECASE):
                    url = urljoin(self.target, match.group(1))
                    urls.add(url)

            # Check discovered URLs
            for url in urls:
                try:
                    resp = await client.get(url)
                    if resp.ok:
                        spec = self._parse_spec(resp.body, url)
                        if spec:
                            self.specs.append(spec)
                            logger.info(f"Found spec from HTML: {url}")
                except Exception:
                    pass

    def _parse_spec(self, content: str, url: str) -> Optional[OpenAPISpec]:
        """Parse OpenAPI/Swagger specification."""
        try:
            # Try JSON first
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                # Try YAML
                try:
                    data = yaml.safe_load(content)
                except yaml.YAMLError:
                    return None

            if not isinstance(data, dict):
                return None

            # Check if it's a valid OpenAPI/Swagger spec
            if "swagger" not in data and "openapi" not in data:
                return None

            spec = OpenAPISpec(url=url)

            # Detect version
            if "swagger" in data:
                spec.version = f"Swagger {data['swagger']}"
            elif "openapi" in data:
                spec.version = f"OpenAPI {data['openapi']}"

            # Basic info
            info = data.get("info", {})
            spec.title = info.get("title", "")
            spec.description = info.get("description", "")

            # Servers/Base URL
            if "servers" in data:
                spec.servers = [s.get("url", "") for s in data["servers"]]
                spec.base_url = spec.servers[0] if spec.servers else ""
            elif "host" in data:
                scheme = data.get("schemes", ["https"])[0]
                base_path = data.get("basePath", "")
                spec.base_url = f"{scheme}://{data['host']}{base_path}"
                spec.servers = [spec.base_url]

            # Security schemes
            if "securityDefinitions" in data:  # Swagger 2.0
                spec.security_schemes = data["securityDefinitions"]
            elif "components" in data and "securitySchemes" in data["components"]:  # OpenAPI 3.x
                spec.security_schemes = data["components"]["securitySchemes"]

            # Tags
            spec.tags = [t.get("name", "") for t in data.get("tags", [])]

            # Parse paths
            paths = data.get("paths", {})
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue

                for method, details in methods.items():
                    if method.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                        continue

                    if not isinstance(details, dict):
                        continue

                    operation = APIOperation(
                        path=path,
                        method=method.upper(),
                        operation_id=details.get("operationId", ""),
                        summary=details.get("summary", ""),
                        description=details.get("description", ""),
                        tags=details.get("tags", []),
                        deprecated=details.get("deprecated", False),
                    )

                    # Parameters
                    operation.parameters = details.get("parameters", [])

                    # Request body (OpenAPI 3.x)
                    if "requestBody" in details:
                        operation.request_body = details["requestBody"]

                    # Responses
                    operation.responses = details.get("responses", {})

                    # Security
                    operation.security = details.get("security", data.get("security", []))

                    spec.operations.append(operation)
                    self.all_operations.append(operation)

            return spec

        except Exception as e:
            logger.debug(f"Error parsing spec from {url}: {e}")
            return None

    def _analyze_security(self):
        """Analyze security configurations in discovered specs."""
        for spec in self.specs:
            # Check for missing security schemes
            if not spec.security_schemes:
                self.security_issues.append({
                    "title": "No Security Schemes Defined",
                    "severity": "medium",
                    "description": f"No security schemes defined in spec: {spec.title or spec.url}",
                    "url": spec.url,
                    "remediation": "Define appropriate security schemes (OAuth2, API Key, etc.)",
                })

            # Check for insecure schemes
            for name, scheme in spec.security_schemes.items():
                scheme_type = scheme.get("type", "")

                if scheme_type == "http" and scheme.get("scheme") == "basic":
                    self.security_issues.append({
                        "title": "Basic Authentication Used",
                        "severity": "medium",
                        "description": f"Basic authentication scheme '{name}' is used, which transmits credentials with each request",
                        "url": spec.url,
                        "remediation": "Consider using more secure authentication methods like OAuth2 or API keys",
                    })

                if scheme_type == "apiKey" and scheme.get("in") == "query":
                    self.security_issues.append({
                        "title": "API Key in Query Parameter",
                        "severity": "low",
                        "description": f"API key '{name}' is passed in query parameter, which may be logged",
                        "url": spec.url,
                        "remediation": "Pass API keys in headers instead of query parameters",
                    })

            # Check for unauthenticated endpoints
            for operation in spec.operations:
                if not operation.security and self._is_sensitive_endpoint(operation):
                    self.security_issues.append({
                        "title": f"Unauthenticated Sensitive Endpoint: {operation.method} {operation.path}",
                        "severity": "high",
                        "description": f"Potentially sensitive endpoint has no security requirements",
                        "url": spec.url,
                        "remediation": "Add appropriate security requirements to sensitive endpoints",
                    })

            # Check for deprecated endpoints
            deprecated_ops = [op for op in spec.operations if op.deprecated]
            if deprecated_ops:
                self.security_issues.append({
                    "title": f"Deprecated Endpoints Found ({len(deprecated_ops)})",
                    "severity": "info",
                    "description": f"Deprecated endpoints are still documented: {', '.join([op.path for op in deprecated_ops[:5]])}",
                    "url": spec.url,
                    "remediation": "Remove deprecated endpoints from production",
                })

    def _is_sensitive_endpoint(self, operation: APIOperation) -> bool:
        """Check if endpoint is potentially sensitive."""
        sensitive_patterns = [
            r"admin", r"user", r"account", r"profile", r"password",
            r"auth", r"login", r"token", r"secret", r"key",
            r"payment", r"billing", r"credit", r"card",
            r"internal", r"private", r"debug", r"config",
            r"delete", r"remove", r"drop", r"truncate",
        ]

        path_lower = operation.path.lower()
        return any(re.search(pattern, path_lower) for pattern in sensitive_patterns)

    def _count_by_method(self) -> Dict[str, int]:
        """Count operations by HTTP method."""
        counts: Dict[str, int] = {}
        for op in self.all_operations:
            counts[op.method] = counts.get(op.method, 0) + 1
        return counts

    def _count_by_tag(self) -> Dict[str, int]:
        """Count operations by tag."""
        counts: Dict[str, int] = {}
        for op in self.all_operations:
            for tag in op.tags:
                counts[tag] = counts.get(tag, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"openapi_{self.target_domain}")

        if self.specs:
            # Save all endpoints
            endpoints_path = self.output_dir / f"openapi_endpoints_{self.target_domain}.txt"
            with open(endpoints_path, "w") as f:
                for op in sorted(self.all_operations, key=lambda x: (x.path, x.method)):
                    security = "[AUTH]" if op.security else "[OPEN]"
                    f.write(f"{op.method:7} {op.path} {security}\n")
            paths["endpoints"] = str(endpoints_path)

            # Save detailed JSON
            detailed_path = self.output_dir / f"openapi_{self.target_domain}_detailed.json"
            with open(detailed_path, "w") as f:
                json.dump(
                    {
                        "target": self.target,
                        "timestamp": timestamp_now(),
                        "specs": [s.to_dict() for s in self.specs],
                        "security_issues": self.security_issues,
                    },
                    f,
                    indent=2,
                )
            paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="OpenAPI/Swagger specification discovery"
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

    discovery = OpenAPIDiscovery(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
    )

    result = await discovery.discover()
    paths = discovery.save_results(result)

    print(f"\n{'='*60}")
    print(f"OpenAPI Discovery Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Specs Found: {len(discovery.specs)}")
    print(f"Total Operations: {len(discovery.all_operations)}")
    print(f"Security Issues: {len(discovery.security_issues)}")

    if discovery.specs:
        for spec in discovery.specs:
            print(f"\nSpec: {spec.title or 'Untitled'}")
            print(f"  URL: {spec.url}")
            print(f"  Version: {spec.version}")
            print(f"  Operations: {len(spec.operations)}")
            print(f"  Security Schemes: {list(spec.security_schemes.keys())}")

    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    # Show security issues
    if discovery.security_issues:
        print(f"\n*** SECURITY ISSUES ***")
        for issue in discovery.security_issues[:10]:
            print(f"  [{issue['severity'].upper()}] {issue['title']}")


if __name__ == "__main__":
    asyncio.run(main())

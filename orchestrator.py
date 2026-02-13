#!/usr/bin/env python3
"""
SHADOW Bug Bounty Framework - Pipeline Orchestrator.

Coordinates all phases of security testing:
1. Reconnaissance
2. Discovery
3. Vulnerability Testing
4. Exploitation
5. Reporting

Usage:
    python orchestrator.py --target example.com --output results/ --config config.yaml
"""

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir
from core.result_manager import ResultManager, ScanResult, Finding, Severity

logger = setup_logging("orchestrator")


@dataclass
class PipelineConfig:
    """Pipeline configuration."""

    target: str
    output_dir: str = "results"
    config_file: Optional[str] = None
    proxy: Optional[str] = None
    timeout: int = 30
    threads: int = 10
    verbose: bool = False

    # Phase toggles
    run_recon: bool = True
    run_discovery: bool = True
    run_testing: bool = True

    # Module toggles
    modules: Dict[str, bool] = field(default_factory=dict)

    # Authentication
    auth_cookie: Optional[str] = None
    auth_header: Optional[str] = None
    auth_token: Optional[str] = None

    def __post_init__(self):
        if not self.modules:
            self.modules = {
                # Recon
                "subdomain_enum": True,
                "port_scanner": True,
                "tech_fingerprint": True,
                "cert_transparency": True,
                "wayback_extractor": True,
                "dns_enum": True,
                # Discovery
                "js_analyzer": True,
                "directory_bruteforce": True,
                "parameter_discovery": True,
                "api_endpoint_extractor": True,
                "graphql_introspect": True,
                "openapi_discovery": True,
                # Testing
                "sqli_tester": True,
                "xss_tester": True,
                "ssrf_tester": True,
                "idor_tester": True,
                "jwt_tester": True,
                "csrf_tester": True,
                "file_upload": True,
                "business_logic": True,
            }


@dataclass
class PipelineResult:
    """Result from pipeline execution."""

    target: str
    started_at: str
    completed_at: str = ""
    duration_seconds: float = 0.0
    phases_completed: List[str] = field(default_factory=list)
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    all_findings: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_results: Dict[str, ScanResult] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "phases_completed": self.phases_completed,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "errors": self.errors,
        }


class ShadowOrchestrator:
    """
    Main orchestrator for SHADOW Bug Bounty Framework.

    Coordinates execution of all security testing phases.
    """

    def __init__(self, config: PipelineConfig):
        self.config = config
        self.target = config.target
        self.target_domain = extract_domain(config.target)
        self.output_dir = Path(config.output_dir)
        self.result_manager = ResultManager(config.output_dir)

        ensure_dir(self.output_dir)
        ensure_dir(self.output_dir / "recon")
        ensure_dir(self.output_dir / "discovery")
        ensure_dir(self.output_dir / "testing")

        self.discovered_subdomains: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.discovered_params: Set[str] = set()

        self.pipeline_result = PipelineResult(
            target=self.target,
            started_at=timestamp_now(),
        )

    async def run(self) -> PipelineResult:
        """Execute the full security testing pipeline."""
        logger.info(f"Starting SHADOW pipeline for: {self.target}")
        start_time = datetime.now()

        try:
            # Phase 1: Reconnaissance
            if self.config.run_recon:
                await self._run_recon_phase()
                self.pipeline_result.phases_completed.append("recon")

            # Phase 2: Discovery
            if self.config.run_discovery:
                await self._run_discovery_phase()
                self.pipeline_result.phases_completed.append("discovery")

            # Phase 3: Vulnerability Testing
            if self.config.run_testing:
                await self._run_testing_phase()
                self.pipeline_result.phases_completed.append("testing")

            # Aggregate results
            self._aggregate_findings()

        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            self.pipeline_result.errors.append(str(e))

        # Finalize
        end_time = datetime.now()
        self.pipeline_result.completed_at = timestamp_now()
        self.pipeline_result.duration_seconds = (end_time - start_time).total_seconds()

        # Save pipeline summary
        self._save_summary()

        return self.pipeline_result

    async def _run_recon_phase(self):
        """Run reconnaissance phase."""
        logger.info("=" * 60)
        logger.info("PHASE 1: RECONNAISSANCE")
        logger.info("=" * 60)

        recon_dir = str(self.output_dir / "recon")

        # Subdomain Enumeration
        if self.config.modules.get("subdomain_enum", True):
            await self._run_module(
                "subdomain_enum",
                "phase1_recon.subdomain_enum",
                "SubdomainEnumerator",
                target=self.target_domain,
                output_dir=recon_dir,
                proxy=self.config.proxy,
            )

        # Certificate Transparency
        if self.config.modules.get("cert_transparency", True):
            await self._run_module(
                "cert_transparency",
                "phase1_recon.cert_transparency",
                "CertTransparency",
                target=self.target_domain,
                output_dir=recon_dir,
            )

        # DNS Enumeration
        if self.config.modules.get("dns_enum", True):
            await self._run_module(
                "dns_enum",
                "phase1_recon.dns_enum",
                "DNSEnumerator",
                target=self.target_domain,
                output_dir=recon_dir,
            )

        # Port Scanning
        if self.config.modules.get("port_scanner", True):
            await self._run_module(
                "port_scanner",
                "phase1_recon.port_scanner",
                "PortScanner",
                target=self.target_domain,
                output_dir=recon_dir,
            )

        # Technology Fingerprinting
        if self.config.modules.get("tech_fingerprint", True):
            target_url = normalize_url(self.config.target)
            await self._run_module(
                "tech_fingerprint",
                "phase1_recon.tech_fingerprint",
                "TechFingerprinter",
                target=target_url,
                output_dir=recon_dir,
                proxy=self.config.proxy,
            )

        # Wayback Extraction
        if self.config.modules.get("wayback_extractor", True):
            await self._run_module(
                "wayback_extractor",
                "phase1_recon.wayback_extractor",
                "WaybackExtractor",
                target=self.target_domain,
                output_dir=recon_dir,
            )

    async def _run_discovery_phase(self):
        """Run discovery phase."""
        logger.info("=" * 60)
        logger.info("PHASE 2: DISCOVERY")
        logger.info("=" * 60)

        discovery_dir = str(self.output_dir / "discovery")
        target_url = normalize_url(self.config.target)

        # JavaScript Analysis
        if self.config.modules.get("js_analyzer", True):
            await self._run_module(
                "js_analyzer",
                "phase2_discovery.js_analyzer",
                "JSAnalyzer",
                target=target_url,
                output_dir=discovery_dir,
                proxy=self.config.proxy,
            )

        # Directory Brute Force
        if self.config.modules.get("directory_bruteforce", True):
            await self._run_module(
                "directory_bruteforce",
                "phase2_discovery.directory_bruteforce",
                "DirectoryBruteforcer",
                target=target_url,
                output_dir=discovery_dir,
                proxy=self.config.proxy,
            )

        # Parameter Discovery
        if self.config.modules.get("parameter_discovery", True):
            await self._run_module(
                "parameter_discovery",
                "phase2_discovery.parameter_discovery",
                "ParameterDiscovery",
                target=target_url,
                output_dir=discovery_dir,
                proxy=self.config.proxy,
            )

        # API Endpoint Extraction
        if self.config.modules.get("api_endpoint_extractor", True):
            await self._run_module(
                "api_endpoint_extractor",
                "phase2_discovery.api_endpoint_extractor",
                "APIEndpointExtractor",
                target=target_url,
                output_dir=discovery_dir,
                proxy=self.config.proxy,
            )

        # GraphQL Introspection
        if self.config.modules.get("graphql_introspect", True):
            await self._run_module(
                "graphql_introspect",
                "phase2_discovery.graphql_introspect",
                "GraphQLIntrospector",
                target=target_url,
                output_dir=discovery_dir,
                proxy=self.config.proxy,
            )

        # OpenAPI Discovery
        if self.config.modules.get("openapi_discovery", True):
            await self._run_module(
                "openapi_discovery",
                "phase2_discovery.openapi_discovery",
                "OpenAPIDiscovery",
                target=target_url,
                output_dir=discovery_dir,
                proxy=self.config.proxy,
            )

    async def _run_testing_phase(self):
        """Run vulnerability testing phase."""
        logger.info("=" * 60)
        logger.info("PHASE 3: VULNERABILITY TESTING")
        logger.info("=" * 60)

        testing_dir = str(self.output_dir / "testing")
        target_url = normalize_url(self.config.target)

        # SQL Injection
        if self.config.modules.get("sqli_tester", True):
            await self._run_module(
                "sqli_tester",
                "phase3_testing.injection.sqli_tester",
                "SQLiTester",
                target=target_url,
                output_dir=testing_dir,
                proxy=self.config.proxy,
            )

        # XSS Testing
        if self.config.modules.get("xss_tester", True):
            await self._run_module(
                "xss_tester",
                "phase3_testing.injection.xss_tester",
                "XSSTester",
                target=target_url,
                output_dir=testing_dir,
                proxy=self.config.proxy,
            )

        # SSRF Testing
        if self.config.modules.get("ssrf_tester", True):
            await self._run_module(
                "ssrf_tester",
                "phase3_testing.ssrf_tester",
                "SSRFTester",
                target=target_url,
                output_dir=testing_dir,
                proxy=self.config.proxy,
            )

        # IDOR Testing
        if self.config.modules.get("idor_tester", True):
            await self._run_module(
                "idor_tester",
                "phase3_testing.access.idor_tester",
                "IDORTester",
                target=target_url,
                output_dir=testing_dir,
                proxy=self.config.proxy,
            )

        # JWT Testing (if token provided)
        if self.config.modules.get("jwt_tester", True) and self.config.auth_token:
            await self._run_module(
                "jwt_tester",
                "phase3_testing.auth.jwt_tester",
                "JWTTester",
                target=target_url,
                output_dir=testing_dir,
                token=self.config.auth_token,
                proxy=self.config.proxy,
            )

        # CSRF Testing
        if self.config.modules.get("csrf_tester", True):
            await self._run_module(
                "csrf_tester",
                "phase3_testing.csrf_tester",
                "CSRFTester",
                target=target_url,
                output_dir=testing_dir,
                auth_cookie=self.config.auth_cookie,
                proxy=self.config.proxy,
            )

        # File Upload Testing
        if self.config.modules.get("file_upload", True):
            await self._run_module(
                "file_upload",
                "phase3_testing.file_upload",
                "FileUploadTester",
                target=target_url,
                output_dir=testing_dir,
                auth_cookie=self.config.auth_cookie,
                proxy=self.config.proxy,
            )

        # Business Logic Testing
        if self.config.modules.get("business_logic", True):
            await self._run_module(
                "business_logic",
                "phase3_testing.business_logic",
                "BusinessLogicTester",
                target=target_url,
                output_dir=testing_dir,
                auth_cookie=self.config.auth_cookie,
                auth_header=self.config.auth_header,
                proxy=self.config.proxy,
            )

    async def _run_module(
        self,
        name: str,
        module_path: str,
        class_name: str,
        **kwargs
    ):
        """Run a single module and collect results."""
        logger.info(f"Running module: {name}")

        try:
            # Dynamic import
            module = __import__(module_path, fromlist=[class_name])
            tester_class = getattr(module, class_name)

            # Filter kwargs to only pass what the class accepts
            import inspect
            sig = inspect.signature(tester_class.__init__)
            valid_params = set(sig.parameters.keys()) - {"self"}
            filtered_kwargs = {k: v for k, v in kwargs.items() if k in valid_params and v is not None}

            # Create instance and run
            tester = tester_class(**filtered_kwargs)

            if hasattr(tester, "test"):
                result = await tester.test()
            elif hasattr(tester, "scan"):
                result = await tester.scan()
            elif hasattr(tester, "enumerate"):
                result = await tester.enumerate()
            elif hasattr(tester, "run"):
                result = await tester.run()
            else:
                logger.warning(f"Module {name} has no standard entry point")
                return

            # Store result
            self.pipeline_result.scan_results[name] = result

            # Save individual result
            if hasattr(tester, "save_results"):
                tester.save_results(result)

            logger.info(f"Module {name} completed: {len(result.findings)} findings")

        except ImportError as e:
            error_msg = f"Failed to import {module_path}: {e}"
            logger.error(error_msg)
            self.pipeline_result.errors.append(error_msg)

        except Exception as e:
            error_msg = f"Error running {name}: {e}"
            logger.error(error_msg)
            self.pipeline_result.errors.append(error_msg)

    def _aggregate_findings(self):
        """Aggregate findings from all modules."""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        all_findings = []

        for module_name, result in self.pipeline_result.scan_results.items():
            for finding in result.findings:
                finding_dict = finding.to_dict()
                finding_dict["module"] = module_name
                all_findings.append(finding_dict)

                severity = finding.severity.value.lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        self.pipeline_result.total_findings = len(all_findings)
        self.pipeline_result.findings_by_severity = severity_counts
        self.pipeline_result.all_findings = all_findings

    def _save_summary(self):
        """Save pipeline execution summary."""
        summary_path = self.output_dir / f"shadow_summary_{self.target_domain}.json"

        summary = {
            "target": self.target,
            "domain": self.target_domain,
            "started_at": self.pipeline_result.started_at,
            "completed_at": self.pipeline_result.completed_at,
            "duration_seconds": self.pipeline_result.duration_seconds,
            "phases_completed": self.pipeline_result.phases_completed,
            "total_findings": self.pipeline_result.total_findings,
            "findings_by_severity": self.pipeline_result.findings_by_severity,
            "errors": self.pipeline_result.errors,
            "findings": self.pipeline_result.all_findings,
        }

        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Summary saved to: {summary_path}")

        # Also save markdown report
        self._save_markdown_report()

    def _save_markdown_report(self):
        """Save markdown summary report."""
        report_path = self.output_dir / f"shadow_report_{self.target_domain}.md"

        lines = [
            f"# SHADOW Security Assessment Report",
            f"",
            f"**Target:** {self.target}",
            f"**Domain:** {self.target_domain}",
            f"**Date:** {self.pipeline_result.started_at}",
            f"**Duration:** {self.pipeline_result.duration_seconds:.2f} seconds",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]

        for severity, count in self.pipeline_result.findings_by_severity.items():
            lines.append(f"| {severity.upper()} | {count} |")

        lines.extend([
            f"",
            f"**Total Findings:** {self.pipeline_result.total_findings}",
            f"",
            f"---",
            f"",
            f"## Findings",
            f"",
        ])

        # Group by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            findings = [f for f in self.pipeline_result.all_findings
                       if f.get("severity", "").lower() == severity]

            if findings:
                lines.append(f"### {severity.upper()} ({len(findings)})")
                lines.append("")

                for i, finding in enumerate(findings, 1):
                    lines.extend([
                        f"#### {i}. {finding.get('title', 'Untitled')}",
                        f"",
                        f"- **URL:** {finding.get('url', 'N/A')}",
                        f"- **Module:** {finding.get('module', 'N/A')}",
                        f"- **CWE:** {finding.get('cwe_id', 'N/A')}",
                        f"",
                        f"**Description:** {finding.get('description', 'N/A')}",
                        f"",
                        f"**Evidence:**",
                        f"```",
                        f"{finding.get('evidence', 'N/A')[:500]}",
                        f"```",
                        f"",
                        f"**Remediation:** {finding.get('remediation', 'N/A')}",
                        f"",
                        f"---",
                        f"",
                    ])

        if self.pipeline_result.errors:
            lines.extend([
                f"## Errors",
                f"",
            ])
            for error in self.pipeline_result.errors:
                lines.append(f"- {error}")

        lines.extend([
            f"",
            f"---",
            f"",
            f"*Generated by SHADOW Bug Bounty Framework*",
        ])

        with open(report_path, "w") as f:
            f.write("\n".join(lines))

        logger.info(f"Report saved to: {report_path}")


async def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Bug Bounty Framework - Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan
  python orchestrator.py -t example.com -o results/

  # Recon only
  python orchestrator.py -t example.com -o results/ --recon-only

  # Skip recon, run discovery and testing
  python orchestrator.py -t https://example.com -o results/ --skip-recon

  # With authentication
  python orchestrator.py -t https://example.com -o results/ --auth-cookie "session=abc123"
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Target domain or URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # Phase controls
    parser.add_argument("--recon-only", action="store_true", help="Run recon phase only")
    parser.add_argument("--discovery-only", action="store_true", help="Run discovery phase only")
    parser.add_argument("--testing-only", action="store_true", help="Run testing phase only")
    parser.add_argument("--skip-recon", action="store_true", help="Skip recon phase")
    parser.add_argument("--skip-discovery", action="store_true", help="Skip discovery phase")
    parser.add_argument("--skip-testing", action="store_true", help="Skip testing phase")

    # Authentication
    parser.add_argument("--auth-cookie", help="Authentication cookie")
    parser.add_argument("--auth-header", help="Authorization header value")
    parser.add_argument("--auth-token", help="JWT or API token")

    # Module controls
    parser.add_argument("--modules", help="Comma-separated list of modules to run")
    parser.add_argument("--exclude-modules", help="Comma-separated list of modules to exclude")

    args = parser.parse_args()

    # Determine phases to run
    run_recon = True
    run_discovery = True
    run_testing = True

    if args.recon_only:
        run_discovery = False
        run_testing = False
    elif args.discovery_only:
        run_recon = False
        run_testing = False
    elif args.testing_only:
        run_recon = False
        run_discovery = False

    if args.skip_recon:
        run_recon = False
    if args.skip_discovery:
        run_discovery = False
    if args.skip_testing:
        run_testing = False

    # Build module config
    modules = {}
    if args.modules:
        # Only enable specified modules
        for mod in args.modules.split(","):
            modules[mod.strip()] = True
    if args.exclude_modules:
        # Disable specified modules
        for mod in args.exclude_modules.split(","):
            modules[mod.strip()] = False

    config = PipelineConfig(
        target=args.target,
        output_dir=args.output,
        config_file=args.config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
        run_recon=run_recon,
        run_discovery=run_discovery,
        run_testing=run_testing,
        modules=modules if modules else None,
        auth_cookie=args.auth_cookie,
        auth_header=args.auth_header,
        auth_token=args.auth_token,
    )

    orchestrator = ShadowOrchestrator(config)
    result = await orchestrator.run()

    # Print summary
    print("\n" + "=" * 60)
    print("SHADOW ASSESSMENT COMPLETE")
    print("=" * 60)
    print(f"Target: {result.target}")
    print(f"Duration: {result.duration_seconds:.2f} seconds")
    print(f"Phases: {', '.join(result.phases_completed)}")
    print(f"\nFindings by Severity:")
    for severity, count in result.findings_by_severity.items():
        if count > 0:
            print(f"  {severity.upper()}: {count}")
    print(f"\nTotal Findings: {result.total_findings}")

    if result.errors:
        print(f"\nErrors: {len(result.errors)}")

    print(f"\nResults saved to: {args.output}/")


if __name__ == "__main__":
    asyncio.run(main())

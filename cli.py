#!/usr/bin/env python3
"""
SHADOW Bug Bounty Framework - Command Line Interface.

Main entry point for the SHADOW security testing framework.

Usage:
    shadow --help
    shadow scan -t example.com
    shadow recon -t example.com
    shadow test -t https://example.com/api
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.utils import setup_logging, normalize_url, extract_domain

logger = setup_logging("shadow")

VERSION = "1.0.0"
BANNER = f"""
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
                                          v{VERSION}
        Bug Bounty Automation Framework
"""


def print_banner():
    """Print SHADOW banner."""
    print(BANNER)


async def cmd_scan(args):
    """Run full security scan."""
    from orchestrator import ShadowOrchestrator, PipelineConfig

    config = PipelineConfig(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
        run_recon=not args.skip_recon,
        run_discovery=not args.skip_discovery,
        run_testing=not args.skip_testing,
        auth_cookie=args.auth_cookie,
        auth_header=args.auth_header,
        auth_token=args.auth_token,
    )

    orchestrator = ShadowOrchestrator(config)
    result = await orchestrator.run()

    return result


async def cmd_recon(args):
    """Run reconnaissance only."""
    from orchestrator import ShadowOrchestrator, PipelineConfig

    config = PipelineConfig(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        timeout=args.timeout,
        verbose=args.verbose,
        run_recon=True,
        run_discovery=False,
        run_testing=False,
    )

    orchestrator = ShadowOrchestrator(config)
    result = await orchestrator.run()

    return result


async def cmd_discover(args):
    """Run discovery only."""
    from orchestrator import ShadowOrchestrator, PipelineConfig

    config = PipelineConfig(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        timeout=args.timeout,
        verbose=args.verbose,
        run_recon=False,
        run_discovery=True,
        run_testing=False,
    )

    orchestrator = ShadowOrchestrator(config)
    result = await orchestrator.run()

    return result


async def cmd_test(args):
    """Run vulnerability testing only."""
    from orchestrator import ShadowOrchestrator, PipelineConfig

    config = PipelineConfig(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        timeout=args.timeout,
        verbose=args.verbose,
        run_recon=False,
        run_discovery=False,
        run_testing=True,
        auth_cookie=args.auth_cookie,
        auth_header=args.auth_header,
        auth_token=args.auth_token,
    )

    orchestrator = ShadowOrchestrator(config)
    result = await orchestrator.run()

    return result


async def cmd_module(args):
    """Run a specific module."""
    module_map = {
        # Recon modules
        "subdomain": ("phase1_recon.subdomain_enum", "SubdomainEnumerator"),
        "ports": ("phase1_recon.port_scanner", "PortScanner"),
        "tech": ("phase1_recon.tech_fingerprint", "TechFingerprinter"),
        "certs": ("phase1_recon.cert_transparency", "CertTransparency"),
        "wayback": ("phase1_recon.wayback_extractor", "WaybackExtractor"),
        "dns": ("phase1_recon.dns_enum", "DNSEnumerator"),
        # Discovery modules
        "js": ("phase2_discovery.js_analyzer", "JSAnalyzer"),
        "dirs": ("phase2_discovery.directory_bruteforce", "DirectoryBruteforcer"),
        "params": ("phase2_discovery.parameter_discovery", "ParameterDiscovery"),
        "api": ("phase2_discovery.api_endpoint_extractor", "APIEndpointExtractor"),
        "graphql": ("phase2_discovery.graphql_introspect", "GraphQLIntrospector"),
        "openapi": ("phase2_discovery.openapi_discovery", "OpenAPIDiscovery"),
        # Testing modules
        "sqli": ("phase3_testing.injection.sqli_tester", "SQLiTester"),
        "xss": ("phase3_testing.injection.xss_tester", "XSSTester"),
        "xxe": ("phase3_testing.injection.xxe_tester", "XXETester"),
        "ssti": ("phase3_testing.injection.ssti_tester", "SSTITester"),
        "cmdi": ("phase3_testing.injection.command_injection", "CommandInjectionTester"),
        "ssrf": ("phase3_testing.ssrf_tester", "SSRFTester"),
        "csrf": ("phase3_testing.csrf_tester", "CSRFTester"),
        "idor": ("phase3_testing.access.idor_tester", "IDORTester"),
        "privesc": ("phase3_testing.access.privilege_escalation", "PrivilegeEscalationTester"),
        "access": ("phase3_testing.access.access_control", "AccessControlTester"),
        "jwt": ("phase3_testing.auth.jwt_tester", "JWTTester"),
        "login": ("phase3_testing.auth.login_bypass", "LoginBypassTester"),
        "session": ("phase3_testing.auth.session_tester", "SessionTester"),
        "pwreset": ("phase3_testing.auth.password_reset", "PasswordResetTester"),
        "race": ("phase3_testing.race_condition", "RaceConditionTester"),
        "upload": ("phase3_testing.file_upload", "FileUploadTester"),
        "bizlogic": ("phase3_testing.business_logic", "BusinessLogicTester"),
    }

    if args.module not in module_map:
        print(f"Unknown module: {args.module}")
        print(f"Available modules: {', '.join(sorted(module_map.keys()))}")
        return None

    module_path, class_name = module_map[args.module]

    try:
        module = __import__(module_path, fromlist=[class_name])
        tester_class = getattr(module, class_name)

        # Build kwargs based on module requirements
        kwargs = {
            "target": args.target,
            "targets": [args.target] if args.target else [],
            "output_dir": args.output,
            "proxy": args.proxy,
            "timeout": args.timeout,
            "verbose": args.verbose,
        }

        # Add auth params if provided
        if hasattr(args, "auth_cookie") and args.auth_cookie:
            kwargs["auth_cookie"] = args.auth_cookie
        if hasattr(args, "auth_header") and args.auth_header:
            kwargs["auth_header"] = args.auth_header
        if hasattr(args, "auth_token") and args.auth_token:
            kwargs["token"] = args.auth_token
        if hasattr(args, "deep_extract") and args.deep_extract:
            kwargs["deep_extract"] = args.deep_extract

        # Filter kwargs
        import inspect
        sig = inspect.signature(tester_class.__init__)
        valid_params = set(sig.parameters.keys()) - {"self"}
        filtered_kwargs = {k: v for k, v in kwargs.items() if k in valid_params and v is not None}

        tester = tester_class(**filtered_kwargs)

        # Run appropriate method
        if hasattr(tester, "test"):
            result = await tester.test()
        elif hasattr(tester, "scan"):
            result = await tester.scan()
        elif hasattr(tester, "enumerate"):
            result = await tester.enumerate()
        elif hasattr(tester, "run"):
            result = await tester.run()
        elif hasattr(tester, "fingerprint"):
            result = await tester.fingerprint()
        elif hasattr(tester, "analyze"):
            result = await tester.analyze()
        elif hasattr(tester, "bruteforce"):
            result = await tester.bruteforce()
        elif hasattr(tester, "extract"):
            result = await tester.extract()
        elif hasattr(tester, "discover"):
            result = await tester.discover()
        elif hasattr(tester, "detect"):
            result = await tester.detect()
        elif hasattr(tester, "introspect"):
            result = await tester.introspect()
        elif hasattr(tester, "search"):
            result = await tester.search()
        else:
            print(f"Module {args.module} has no standard entry point")
            return None

        # Save results
        if hasattr(tester, "save_results"):
            paths = tester.save_results(result)
            print(f"\nResults saved:")
            for name, path in paths.items():
                print(f"  {name}: {path}")

        return result

    except ImportError as e:
        print(f"Failed to import module: {e}")
        return None
    except Exception as e:
        print(f"Error running module: {e}")
        return None


def cmd_list_modules(args):
    """List available modules."""
    modules = {
        "Reconnaissance": [
            ("subdomain", "Subdomain enumeration"),
            ("ports", "Port scanning"),
            ("tech", "Technology fingerprinting"),
            ("certs", "Certificate transparency"),
            ("wayback", "Wayback Machine extraction"),
            ("dns", "DNS enumeration"),
        ],
        "Discovery": [
            ("js", "JavaScript analysis"),
            ("dirs", "Directory brute force"),
            ("params", "Parameter discovery"),
            ("api", "API endpoint extraction"),
            ("graphql", "GraphQL introspection"),
            ("openapi", "OpenAPI/Swagger discovery"),
        ],
        "Vulnerability Testing": [
            ("sqli", "SQL injection"),
            ("xss", "Cross-site scripting"),
            ("xxe", "XML external entity"),
            ("ssti", "Server-side template injection"),
            ("cmdi", "Command injection"),
            ("ssrf", "Server-side request forgery"),
            ("csrf", "Cross-site request forgery"),
            ("idor", "Insecure direct object reference"),
            ("privesc", "Privilege escalation"),
            ("access", "Access control"),
            ("jwt", "JWT vulnerabilities"),
            ("login", "Login bypass"),
            ("session", "Session management"),
            ("pwreset", "Password reset flaws"),
            ("race", "Race conditions"),
            ("upload", "File upload"),
            ("bizlogic", "Business logic"),
        ],
    }

    print("\nAvailable Modules:\n")
    for category, mods in modules.items():
        print(f"  {category}:")
        for name, desc in mods:
            print(f"    {name:12} - {desc}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Bug Bounty Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"SHADOW v{VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command (full pipeline)
    scan_parser = subparsers.add_parser("scan", help="Run full security scan")
    scan_parser.add_argument("-t", "--target", required=True, help="Target domain or URL")
    scan_parser.add_argument("-o", "--output", default="results", help="Output directory")
    scan_parser.add_argument("-p", "--proxy", help="Proxy URL")
    scan_parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    scan_parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    scan_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    scan_parser.add_argument("--skip-recon", action="store_true", help="Skip recon phase")
    scan_parser.add_argument("--skip-discovery", action="store_true", help="Skip discovery")
    scan_parser.add_argument("--skip-testing", action="store_true", help="Skip testing")
    scan_parser.add_argument("--auth-cookie", help="Authentication cookie")
    scan_parser.add_argument("--auth-header", help="Authorization header")
    scan_parser.add_argument("--auth-token", help="JWT/API token")

    # Recon command
    recon_parser = subparsers.add_parser("recon", help="Run reconnaissance only")
    recon_parser.add_argument("-t", "--target", required=True, help="Target domain")
    recon_parser.add_argument("-o", "--output", default="results", help="Output directory")
    recon_parser.add_argument("-p", "--proxy", help="Proxy URL")
    recon_parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    recon_parser.add_argument("--verbose", action="store_true", help="Verbose output")

    # Discover command
    discover_parser = subparsers.add_parser("discover", help="Run discovery only")
    discover_parser.add_argument("-t", "--target", required=True, help="Target URL")
    discover_parser.add_argument("-o", "--output", default="results", help="Output directory")
    discover_parser.add_argument("-p", "--proxy", help="Proxy URL")
    discover_parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    discover_parser.add_argument("--verbose", action="store_true", help="Verbose output")

    # Test command
    test_parser = subparsers.add_parser("test", help="Run vulnerability testing only")
    test_parser.add_argument("-t", "--target", required=True, help="Target URL")
    test_parser.add_argument("-o", "--output", default="results", help="Output directory")
    test_parser.add_argument("-p", "--proxy", help="Proxy URL")
    test_parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    test_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    test_parser.add_argument("--auth-cookie", help="Authentication cookie")
    test_parser.add_argument("--auth-header", help="Authorization header")
    test_parser.add_argument("--auth-token", help="JWT/API token")

    # Module command (run specific module)
    module_parser = subparsers.add_parser("module", help="Run a specific module")
    module_parser.add_argument("module", help="Module name (use 'list' to see all)")
    module_parser.add_argument("-t", "--target", help="Target URL/domain")
    module_parser.add_argument("-o", "--output", default="results", help="Output directory")
    module_parser.add_argument("-p", "--proxy", help="Proxy URL")
    module_parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    module_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    module_parser.add_argument("--auth-cookie", help="Authentication cookie")
    module_parser.add_argument("--auth-header", help="Authorization header")
    module_parser.add_argument("--auth-token", help="JWT/API token")
    module_parser.add_argument("--deep-extract", action="store_true", help="Enable deep extraction (e.g., for JS analysis)")

    # List command
    list_parser = subparsers.add_parser("list", help="List available modules")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        return

    print_banner()

    if args.command == "list":
        cmd_list_modules(args)
        return

    if args.command == "module" and args.module == "list":
        cmd_list_modules(args)
        return

    # Validate target for commands that need it
    if args.command in ["scan", "recon", "discover", "test", "module"]:
        if args.command == "module" and args.module == "list":
            pass
        elif not args.target:
            print("Error: --target is required")
            return

    # Run async command
    try:
        if args.command == "scan":
            result = asyncio.run(cmd_scan(args))
        elif args.command == "recon":
            result = asyncio.run(cmd_recon(args))
        elif args.command == "discover":
            result = asyncio.run(cmd_discover(args))
        elif args.command == "test":
            result = asyncio.run(cmd_test(args))
        elif args.command == "module":
            result = asyncio.run(cmd_module(args))
        else:
            parser.print_help()
            return

        if result:
            print("\n" + "=" * 60)
            print("SCAN COMPLETE")
            print("=" * 60)

            if hasattr(result, "total_findings"):
                print(f"Total Findings: {result.total_findings}")
            if hasattr(result, "findings") and result.findings:
                print(f"Findings: {len(result.findings)}")

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose if hasattr(args, "verbose") else False:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()

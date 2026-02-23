#!/usr/bin/env python3
"""
C_quickstart.py — Single-command entrypoint for SHADOW security testing framework.

Replaces 15+ bash commands with one unified interface. Wraps the ShadowOrchestrator
pipeline with mode-based configuration, persistent state, and compact output.

Usage:
    python3 C_quickstart.py --target grammarly.com --mode full
    python3 C_quickstart.py --target superhuman.com --mode ctf --resume
    python3 C_quickstart.py --target robinhood.com --mode hunt --auth-cookie "session=abc"
    python3 C_quickstart.py --target example.com --mode recon --verbose
    python3 C_quickstart.py --target example.com --mode hunt --vector xss,ssrf --proxy http://127.0.0.1:8080
"""

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Ensure shadow-bounty is on the path for sibling imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from C_attack_state import AttackState
from orchestrator import ShadowOrchestrator, PipelineConfig
from C_wrappers.C_tool_router import ToolRouter

# Project root: shadow-bounty/../ = SHADOW/
PROJECT_ROOT = Path(__file__).resolve().parent.parent

VERSION = "1.0.0"

BANNER = r"""
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
  Bug Bounty Framework v{version}
"""

# Valid modes
VALID_MODES = ("full", "recon", "discover", "test", "hunt", "ctf")

# Valid vectors for hunt mode
VALID_VECTORS = ("xss", "ssrf", "idor", "sqli", "jwt", "csrf", "file_upload", "business_logic")

# Mapping from vector shortnames to module keys in PipelineConfig.modules
VECTOR_TO_MODULE = {
    "xss": "xss_tester",
    "ssrf": "ssrf_tester",
    "idor": "idor_tester",
    "sqli": "sqli_tester",
    "jwt": "jwt_tester",
    "csrf": "csrf_tester",
    "file_upload": "file_upload",
    "business_logic": "business_logic",
}

# Recon modules
RECON_MODULES = {
    "subdomain_enum", "port_scanner", "tech_fingerprint",
    "cert_transparency", "wayback_extractor", "dns_enum",
}

# Discovery modules
DISCOVERY_MODULES = {
    "js_analyzer", "directory_bruteforce", "parameter_discovery",
    "api_endpoint_extractor", "graphql_introspect", "openapi_discovery",
}

# Testing modules
TESTING_MODULES = {
    "sqli_tester", "xss_tester", "ssrf_tester", "idor_tester",
    "jwt_tester", "csrf_tester", "file_upload", "business_logic",
}

# Core tools to check at startup
CORE_TOOLS = [
    "nmap", "subfinder", "httpx", "nuclei", "ffuf", "sqlmap",
    "nikto", "whatweb", "katana", "gobuster", "dnsx", "naabu",
]

# Global state reference for SIGINT handler
_global_state: Optional[AttackState] = None
_global_start_time: float = 0.0


def _sigint_handler(signum, frame):
    """Save state and exit cleanly on Ctrl+C."""
    print("\n[!] SIGINT received — saving state...", file=sys.stderr)
    if _global_state is not None:
        try:
            path = _global_state.save()
            print(f"[+] State saved to: {path}", file=sys.stderr)
        except Exception as e:
            print(f"[-] Failed to save state: {e}", file=sys.stderr)
    elapsed = time.monotonic() - _global_start_time if _global_start_time else 0
    print(f"[*] Interrupted after {elapsed:.1f}s", file=sys.stderr)
    sys.exit(130)


def log(msg: str, level: str = "info") -> None:
    """Print a log message to stderr."""
    prefix = {"info": "[*]", "warn": "[!]", "error": "[-]", "ok": "[+]"}.get(level, "[*]")
    print(f"{prefix} {msg}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="C_quickstart.py",
        description="SHADOW Bug Bounty Framework — Single-command entrypoint",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes:\n"
            "  full      Run all phases: recon + discovery + testing\n"
            "  recon     Phase 1 only: subdomain enum, port scan, tech fingerprint\n"
            "  discover  Phase 2 only: JS analysis, dir brute, param discovery, API extraction\n"
            "  test      Phase 3 only: vulnerability testing\n"
            "  hunt      Targeted testing with specific vectors (use --vector)\n"
            "  ctf       Iterative mode with persistent state, loads previous sessions\n"
            "\n"
            "Examples:\n"
            "  python3 C_quickstart.py --target grammarly.com --mode full\n"
            "  python3 C_quickstart.py --target superhuman.com --mode ctf --resume\n"
            "  python3 C_quickstart.py --target robinhood.com --mode hunt --vector xss,ssrf\n"
            "  python3 C_quickstart.py --target example.com --mode recon --verbose --proxy http://127.0.0.1:8080\n"
        ),
    )

    # Required
    parser.add_argument(
        "--target", "-t", required=True,
        help="Target domain or URL (e.g., grammarly.com, https://api.example.com)",
    )
    parser.add_argument(
        "--mode", "-m", required=True, choices=VALID_MODES,
        help="Execution mode",
    )

    # Optional session/state
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume from saved state (auto-enabled in ctf mode)",
    )

    # Authentication
    parser.add_argument("--auth-cookie", help="Authentication cookie string")
    parser.add_argument("--auth-header", help="Authorization header value")
    parser.add_argument("--auth-token", help="JWT or API token")

    # Network
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads (default: 10)")

    # Output
    parser.add_argument("--output-dir", help="Override output directory (default: auto-created under targets/)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging to stderr")

    # Hunt mode
    parser.add_argument(
        "--vector",
        help="Comma-separated vectors for hunt mode: xss,ssrf,idor,sqli,jwt,csrf,file_upload,business_logic",
    )

    # Version
    parser.add_argument("--version", action="version", version=f"SHADOW v{VERSION}")

    return parser


def sanitize_target_name(target: str) -> str:
    """Convert target URL/domain to a safe directory name."""
    name = target.strip()
    if not name:
        raise ValueError("Target name cannot be empty")
    name = name.lower()
    # Strip protocol
    for prefix in ("https://", "http://", "www."):
        if name.startswith(prefix):
            name = name[len(prefix):]
    # Strip trailing slashes/paths
    name = name.split("/")[0]
    # Replace unsafe chars
    name = name.replace(":", "_").replace("*", "_")
    # Strip path traversal, null bytes, newlines
    name = name.replace("..", "").replace("\x00", "").replace("\n", "").replace("\r", "")
    # Final safety: strip leading/trailing dots and whitespace
    name = name.strip(". \t")
    if not name:
        raise ValueError(f"Target name resolves to empty after sanitization: {target!r}")
    return name


def check_tools(verbose: bool = False) -> ToolRouter:
    """Check tool availability and print summary."""
    router = ToolRouter(verbose=verbose)
    results = router.check_tools(CORE_TOOLS)

    available = [t for t, p in results.items() if p is not None]
    missing = [t for t, p in results.items() if p is None]

    log(f"Tools: {len(available)}/{len(results)} available")

    if missing and verbose:
        log(f"Missing: {', '.join(sorted(missing))}", "warn")

    if len(available) == 0:
        log("No Kali tools found — Python fallbacks will be used", "warn")

    return router


def create_workspace(target_name: str) -> Path:
    """Create workspace directories under PROJECT_ROOT/targets/<target>/."""
    target_dir = PROJECT_ROOT / "targets" / target_name
    findings_dir = target_dir / "C_findings"
    recon_dir = target_dir / "C_recon"

    for d in (target_dir, findings_dir, recon_dir):
        d.mkdir(parents=True, exist_ok=True)

    return target_dir


def build_pipeline_config(
    args: argparse.Namespace,
    target_name: str,
    state: Optional[AttackState] = None,
) -> PipelineConfig:
    """Build PipelineConfig based on mode and arguments."""
    output_dir = args.output_dir or str(PROJECT_ROOT / "targets" / target_name / "C_recon")

    # Start with all modules disabled, then enable based on mode
    modules: Dict[str, bool] = {}

    # Phase flags
    run_recon = False
    run_discovery = False
    run_testing = False

    mode = args.mode

    if mode == "full":
        run_recon = True
        run_discovery = True
        run_testing = True
        # Leave modules empty to get defaults from PipelineConfig.__post_init__

    elif mode == "recon":
        run_recon = True
        run_discovery = False
        run_testing = False
        for mod in RECON_MODULES:
            modules[mod] = True

    elif mode == "discover":
        run_recon = False
        run_discovery = True
        run_testing = False
        for mod in DISCOVERY_MODULES:
            modules[mod] = True

    elif mode == "test":
        run_recon = False
        run_discovery = False
        run_testing = True
        for mod in TESTING_MODULES:
            modules[mod] = True

    elif mode == "hunt":
        run_recon = False
        run_discovery = False
        run_testing = True

        # Parse vectors
        requested_vectors = _parse_vectors(args.vector)
        # Disable all testing modules first, then enable requested ones
        for mod in TESTING_MODULES:
            modules[mod] = False
        for vec in requested_vectors:
            mod_key = VECTOR_TO_MODULE.get(vec)
            if mod_key:
                modules[mod_key] = True

    elif mode == "ctf":
        # CTF mode: targeted testing based on state
        run_recon = False
        run_discovery = False
        run_testing = True

        if state and state.promising_leads:
            # Enable modules based on untested leads
            # By default enable all testing modules for CTF
            for mod in TESTING_MODULES:
                modules[mod] = True
        else:
            # No state or no leads: run full testing
            for mod in TESTING_MODULES:
                modules[mod] = True

    config = PipelineConfig(
        target=args.target,
        output_dir=output_dir,
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

    return config


def _parse_vectors(vector_str: Optional[str]) -> List[str]:
    """Parse comma-separated vector string, validate each."""
    if not vector_str:
        return list(VALID_VECTORS)  # Default: all vectors

    vectors = []
    for v in vector_str.split(","):
        v = v.strip().lower()
        if v in VALID_VECTORS:
            vectors.append(v)
        else:
            log(f"Unknown vector '{v}' — skipping (valid: {', '.join(VALID_VECTORS)})", "warn")

    if not vectors:
        log("No valid vectors specified, using all", "warn")
        return list(VALID_VECTORS)

    return vectors


def print_ctf_status(state: AttackState) -> None:
    """Print CTF mode status summary to stderr."""
    stats = state.get_stats()
    untested = state.get_untested_vectors()
    top_leads = sorted(untested, key=lambda x: x.get("priority", 5))[:5]

    log("=" * 60)
    log(f"CTF MODE — {state.target} — Session {state.session_number}")
    log("=" * 60)
    log(f"Subdomains: {stats['subdomains']} | Endpoints: {stats['endpoints_total']} ({stats['endpoints_tested']} tested)")
    log(f"Findings: {stats['findings_total']} | Eliminated: {stats['vectors_eliminated']} vectors")
    log(f"Untested leads: {stats['untested_leads']} / {stats['promising_leads']} total")

    if top_leads:
        log("--- Top Untested Leads ---")
        for i, lead in enumerate(top_leads, 1):
            log(f"  {i}. [P{lead.get('priority', '?')}] {lead['description']}")

    recent_findings = state.findings[-3:] if state.findings else []
    if recent_findings:
        log("--- Recent Findings ---")
        for f in reversed(recent_findings):
            log(f"  [{f.get('exploitation_level', '??')}] {f.get('title', 'untitled')} — {f.get('severity', '?')}")

    log("=" * 60)


def build_summary(pipeline_result, state: Optional[AttackState], elapsed: float) -> dict:
    """Build a compact JSON summary for stdout (machine-readable)."""
    severity_counts = pipeline_result.findings_by_severity or {}

    # Build compact severity string
    severity_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        if count > 0:
            severity_parts.append(f"{count} {sev.upper()}")

    summary = {
        "target": pipeline_result.target,
        "mode": "shadow",
        "duration_seconds": round(elapsed, 2),
        "phases_completed": pipeline_result.phases_completed,
        "findings_total": pipeline_result.total_findings,
        "findings_by_severity": severity_counts,
        "errors_count": len(pipeline_result.errors),
        "compact": (
            f"FINDINGS: {', '.join(severity_parts) or '0'} | "
            f"PHASES: {', '.join(pipeline_result.phases_completed) or 'none'} | "
            f"ERRORS: {len(pipeline_result.errors)} | "
            f"TIME: {elapsed:.1f}s"
        ),
    }

    if state:
        stats = state.get_stats()
        summary["state"] = {
            "session": state.session_number,
            "subdomains": stats["subdomains"],
            "endpoints": stats["endpoints_total"],
            "endpoints_tested": stats["endpoints_tested"],
            "eliminated_vectors": stats["vectors_eliminated"],
            "untested_leads": stats["untested_leads"],
        }

    return summary


def print_compact_summary(summary: dict) -> None:
    """Print the human-readable compact summary to stderr."""
    log("=" * 60)
    log("SHADOW ASSESSMENT COMPLETE")
    log("=" * 60)
    log(summary["compact"])

    if summary.get("state"):
        s = summary["state"]
        log(f"STATE: Session {s['session']} | "
            f"Subs: {s['subdomains']} | "
            f"Endpoints: {s['endpoints']}/{s['endpoints_tested']} tested | "
            f"Eliminated: {s['eliminated_vectors']} | "
            f"Leads: {s['untested_leads']} untested")

    if summary["errors_count"] > 0:
        log(f"Errors encountered: {summary['errors_count']}", "warn")

    log("=" * 60)


async def run(args: argparse.Namespace) -> int:
    """Main execution flow."""
    global _global_state, _global_start_time

    _global_start_time = time.monotonic()

    target_name = sanitize_target_name(args.target)

    # Print banner
    if args.verbose:
        print(BANNER.format(version=VERSION), file=sys.stderr)

    # 1. Check tools
    log(f"Target: {args.target} | Mode: {args.mode}")
    router = check_tools(verbose=args.verbose)

    # 2. Create workspace
    workspace = create_workspace(target_name)
    log(f"Workspace: {workspace}", "ok")

    # 3. Load/create state
    state: Optional[AttackState] = None
    use_state = args.resume or args.mode == "ctf"

    if use_state:
        state = AttackState.load(target_name)
        _global_state = state

        if state.session_number > 0:
            log(f"Resumed state: session {state.session_number}, "
                f"{len(state.findings)} findings, "
                f"{len(state.eliminated_vectors)} eliminated", "ok")
        else:
            log("No previous state found — starting fresh")

        # Start new session
        state.new_session(summary=f"C_quickstart {args.mode} mode")
        log(f"Session {state.session_number} started")

        if args.mode == "ctf":
            print_ctf_status(state)
    else:
        # Create transient state for tracking even in non-resume modes
        state = AttackState(
            target=target_name,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        state.new_session(summary=f"C_quickstart {args.mode} mode")
        _global_state = state

    # 4. Build pipeline config
    config = build_pipeline_config(args, target_name, state)

    if args.verbose:
        enabled_modules = [m for m, v in (config.modules or {}).items() if v]
        if enabled_modules:
            log(f"Enabled modules: {', '.join(sorted(enabled_modules))}")
        log(f"Phases: recon={config.run_recon}, discovery={config.run_discovery}, testing={config.run_testing}")

    # 5. Run the orchestrator
    log("Starting pipeline...")
    orchestrator = ShadowOrchestrator(config)

    try:
        pipeline_result = await orchestrator.run()
    except Exception as e:
        log(f"Pipeline failed: {e}", "error")
        if state:
            state.save()
        return 1

    # 6. Sync findings to state
    if state and pipeline_result.all_findings:
        for finding_dict in pipeline_result.all_findings:
            state.add_finding(
                title=finding_dict.get("title", "Untitled"),
                severity=finding_dict.get("severity", "info"),
                exploitation_level="E4",  # Default — needs manual triage
                description=finding_dict.get("description", ""),
                evidence=finding_dict.get("evidence", ""),
            )

    # 7. Save state
    if state:
        state_path = state.save()
        if args.verbose:
            log(f"State saved: {state_path}", "ok")

    # 8. Build and output summary
    elapsed = time.monotonic() - _global_start_time
    summary = build_summary(pipeline_result, state if use_state else None, elapsed)

    # Compact summary to stderr (human-readable)
    print_compact_summary(summary)

    # JSON summary to stdout (machine-readable)
    json.dump(summary, sys.stdout, indent=2)
    print()  # trailing newline

    return 0 if not pipeline_result.errors else 1


def main() -> None:
    """CLI entrypoint."""
    # Install SIGINT handler
    signal.signal(signal.SIGINT, _sigint_handler)

    parser = build_parser()
    args = parser.parse_args()

    # Validate hunt mode requires --vector (or we default to all)
    if args.mode == "hunt" and not args.vector:
        log("Hunt mode with no --vector specified: running all test vectors", "warn")

    # Run
    exit_code = asyncio.run(run(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

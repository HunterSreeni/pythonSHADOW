#!/usr/bin/env python3
"""
SHADOW Port Scanner - Intelligent routing wrapper.

Routing:
1. Try nmap (PRIMARY, with service detection)
2. Fall back to Python port_scanner.py
3. Parse nmap XML output into unified format

Usage (CLI):
    python C_scan_ports.py -t example.com -o results/
    python C_scan_ports.py -t example.com --all-ports --scripts

Usage (importable):
    from C_wrappers.C_scan_ports import PortScanner
    scanner = PortScanner(target="example.com")
    result = await scanner.run()
"""

import argparse
import asyncio
import json
import sys
import tempfile
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils import setup_logging, extract_domain, timestamp_now, ensure_dir
from C_wrappers.C_tool_router import ToolRouter, UnifiedResult

logger = setup_logging("scan_ports")


class PortScanner:
    """
    Intelligent port scanning with nmap/Python routing.

    Priority: nmap (with service detection) -> Python port_scanner.py
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        ports: Optional[str] = None,
        all_ports: bool = False,
        scripts: bool = False,
        timeout: int = 600,
        proxy: Optional[str] = None,
    ):
        self.target = extract_domain(target) if "://" in target else target
        self.output_dir = Path(output_dir)
        self.ports = ports
        self.all_ports = all_ports
        self.scripts = scripts
        self.timeout = timeout
        self.proxy = proxy
        self.router = ToolRouter()

    async def run(self) -> UnifiedResult:
        """Run port scanning with intelligent routing."""
        logger.info(f"Starting port scan for: {self.target}")

        decision = self.router.select_tool(
            primary="nmap",
            fallbacks=["naabu"],
            category="port_scanning",
        )

        if decision.chosen_tool == "nmap":
            result = await self._run_nmap()
        elif decision.chosen_tool == "naabu":
            result = await self._run_naabu()
        else:
            result = await self._run_python_scanner()

        result.routing_decision = decision
        return result

    async def _run_nmap(self) -> UnifiedResult:
        """Run nmap with service detection and XML output."""
        xml_file = self.router.get_temp_file(suffix=".xml")

        args = ["-sV"]  # Service version detection

        if self.scripts:
            args.append("-sC")  # Default scripts

        if self.all_ports:
            args += ["-p-"]
        elif self.ports:
            args += ["-p", self.ports]
        else:
            args += ["--top-ports", "1000"]

        args += [
            "-oX", xml_file,
            "--open",
            "-T4",
            self.target,
        ]

        tool_result = await self.router.run_tool(
            "nmap", args, target=self.target, timeout=self.timeout
        )

        # Parse XML output
        try:
            if os.path.exists(xml_file):
                with open(xml_file, "r") as f:
                    xml_data = f.read()
                hosts = ToolRouter.parse_nmap_xml(xml_data)
                tool_result.parsed_data = {"hosts": hosts}

                # Convert to findings
                for host in hosts:
                    for port in host.get("ports", []):
                        if port.get("state") == "open":
                            service = port.get("service", "unknown")
                            product = port.get("product", "")
                            version = port.get("version", "")
                            svc_str = f"{service}"
                            if product:
                                svc_str += f" ({product}"
                                if version:
                                    svc_str += f" {version}"
                                svc_str += ")"

                            tool_result.findings.append({
                                "port": port["port"],
                                "protocol": port.get("protocol", "tcp"),
                                "state": "open",
                                "service": service,
                                "product": product,
                                "version": version,
                                "description": svc_str,
                                "host": host.get("ip", self.target),
                            })
        except Exception as e:
            logger.warning(f"Failed to parse nmap XML: {e}")
        finally:
            if os.path.exists(xml_file):
                os.unlink(xml_file)

        return tool_result

    async def _run_naabu(self) -> UnifiedResult:
        """Run naabu for fast port discovery."""
        args = ["-host", self.target, "-json"]

        if self.all_ports:
            args += ["-p", "-"]
        elif self.ports:
            args += ["-p", self.ports]
        else:
            args += ["-top-ports", "1000"]

        tool_result = await self.router.run_tool(
            "naabu", args, target=self.target, timeout=self.timeout
        )

        # Parse JSONL output
        if tool_result.raw_output:
            ports = []
            for line in tool_result.raw_output.strip().splitlines():
                try:
                    data = json.loads(line)
                    ports.append({
                        "port": data.get("port", 0),
                        "protocol": "tcp",
                        "state": "open",
                        "host": data.get("ip", data.get("host", self.target)),
                    })
                except json.JSONDecodeError:
                    continue
            tool_result.findings = ports
            tool_result.parsed_data = {"ports": ports}

        return tool_result

    async def _run_python_scanner(self) -> UnifiedResult:
        """Fall back to Python port_scanner.py."""
        result = UnifiedResult(tool_used="python_port_scanner", target=self.target)

        try:
            from phase1_recon.port_scanner import PortScanner as PyPortScanner

            scanner = PyPortScanner(
                target=self.target,
                output_dir=str(self.output_dir),
            )

            if hasattr(scanner, "scan"):
                scan_result = await scanner.scan()
            elif hasattr(scanner, "run"):
                scan_result = await scanner.run()
            else:
                result.errors.append("PortScanner has no standard entry point")
                return result

            # Convert scan_result findings
            if hasattr(scan_result, "findings"):
                for finding in scan_result.findings:
                    result.findings.append(finding.to_dict() if hasattr(finding, "to_dict") else {
                        "description": str(finding),
                    })

            result.parsed_data = scan_result.to_dict() if hasattr(scan_result, "to_dict") else {}

        except Exception as e:
            logger.error(f"Python port scanner fallback failed: {e}")
            result.errors.append(str(e))

        return result


async def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Port Scanner - Kali/Python intelligent routing",
    )
    parser.add_argument("-t", "--target", required=True, help="Target host/IP")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-p", "--ports", help="Port range (e.g., '80,443,8080' or '1-1000')")
    parser.add_argument("--all-ports", action="store_true", help="Scan all 65535 ports")
    parser.add_argument("--scripts", action="store_true", help="Run nmap default scripts")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    ensure_dir(args.output)

    scanner = PortScanner(
        target=args.target,
        output_dir=args.output,
        ports=args.ports,
        all_ports=args.all_ports,
        scripts=args.scripts,
        timeout=args.timeout,
    )

    result = await scanner.run()

    if args.json:
        print(result.to_json())
    else:
        print(f"\nPort Scan Results: {len(result.findings)} open ports")
        if result.routing_decision:
            print(f"Tool used: {result.routing_decision.chosen_tool}\n")
        for port_info in result.findings:
            port = port_info.get("port", "?")
            service = port_info.get("service", "unknown")
            desc = port_info.get("description", service)
            print(f"  {port}/tcp  open  {desc}")


if __name__ == "__main__":
    asyncio.run(main())

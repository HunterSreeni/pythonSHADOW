#!/usr/bin/env python3
"""
SHADOW Tool Router - Central routing engine for Kali/Python tool selection.

Checks tool availability at runtime, routes to the best available tool,
handles subprocess calls, parses output formats, and provides unified results.

Usage (standalone):
    python C_tool_router.py --check-all
    python C_tool_router.py --check nmap sqlmap nuclei

Usage (importable):
    from C_wrappers.C_tool_router import ToolRouter, UnifiedResult
    router = ToolRouter()
    if router.is_available("nmap"):
        result = await router.run_tool("nmap", ["-sV", target])
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils import setup_logging, timestamp_now

logger = setup_logging("tool_router")


# Known tool paths for Go/pdtm tools that may not be on PATH
PDTM_BIN = os.path.expanduser("~/.pdtm/go/bin")

KNOWN_TOOL_PATHS: Dict[str, List[str]] = {
    "subfinder": [f"{PDTM_BIN}/subfinder"],
    "nuclei": [f"{PDTM_BIN}/nuclei"],
    "httpx": [f"{PDTM_BIN}/httpx"],
    "katana": [f"{PDTM_BIN}/katana"],
    "dnsx": [f"{PDTM_BIN}/dnsx"],
    "naabu": [f"{PDTM_BIN}/naabu"],
    "urlfinder": [f"{PDTM_BIN}/urlfinder"],
    "interactsh-client": [f"{PDTM_BIN}/interactsh-client"],
    "shuffledns": [f"{PDTM_BIN}/shuffledns"],
    "tlsx": [f"{PDTM_BIN}/tlsx"],
    "alterx": [f"{PDTM_BIN}/alterx"],
}


@dataclass
class RoutingDecision:
    """Records which tool was chosen and why."""

    requested_tool: str
    chosen_tool: str
    reason: str
    is_fallback: bool = False
    tool_path: Optional[str] = None
    timestamp: str = field(default_factory=timestamp_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested_tool": self.requested_tool,
            "chosen_tool": self.chosen_tool,
            "reason": self.reason,
            "is_fallback": self.is_fallback,
            "tool_path": self.tool_path,
            "timestamp": self.timestamp,
        }


@dataclass
class UnifiedResult:
    """Standardized result format for all tool outputs."""

    tool_used: str
    target: str
    timestamp: str = field(default_factory=timestamp_now)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    routing_decision: Optional[RoutingDecision] = None
    exit_code: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_used": self.tool_used,
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": self.findings,
            "raw_output": self.raw_output[:10000] if self.raw_output else "",
            "parsed_data": self.parsed_data,
            "errors": self.errors,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "routing_decision": self.routing_decision.to_dict() if self.routing_decision else None,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.errors


class ToolRouter:
    """
    Central routing engine for Kali/Python tool selection.

    Features:
    - Runtime tool availability checking via shutil.which()
    - Known path resolution for Go/pdtm tools
    - Subprocess execution with timeout and error handling
    - Output parsing for JSON, XML, and plain text formats
    - Unified result format
    - Routing decision logging
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._tool_cache: Dict[str, Optional[str]] = {}
        self._routing_log: List[RoutingDecision] = []

    def find_tool(self, tool_name: str) -> Optional[str]:
        """
        Find tool binary path. Checks cache, then shutil.which(), then known paths.

        Args:
            tool_name: Name of the tool (e.g., 'nmap', 'subfinder')

        Returns:
            Absolute path to tool binary, or None if not found.
        """
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]

        # Try shutil.which first (covers PATH)
        path = shutil.which(tool_name)
        if path:
            self._tool_cache[tool_name] = path
            return path

        # Try known paths (Go/pdtm tools)
        for known_path in KNOWN_TOOL_PATHS.get(tool_name, []):
            if os.path.isfile(known_path) and os.access(known_path, os.X_OK):
                self._tool_cache[tool_name] = known_path
                return known_path

        # Not found
        self._tool_cache[tool_name] = None
        return None

    def is_available(self, tool_name: str) -> bool:
        """Check if a tool is available on the system."""
        return self.find_tool(tool_name) is not None

    def check_tools(self, tool_names: List[str]) -> Dict[str, Optional[str]]:
        """
        Check availability of multiple tools.

        Returns:
            Dict mapping tool name to path (None if unavailable).
        """
        return {name: self.find_tool(name) for name in tool_names}

    def select_tool(
        self,
        primary: str,
        fallbacks: Optional[List[str]] = None,
        category: str = "",
    ) -> RoutingDecision:
        """
        Select the best available tool from primary and fallbacks.

        Args:
            primary: Preferred tool name
            fallbacks: Fallback tool names in priority order
            category: Category label for logging

        Returns:
            RoutingDecision with the chosen tool.
        """
        fallbacks = fallbacks or []

        # Try primary
        primary_path = self.find_tool(primary)
        if primary_path:
            decision = RoutingDecision(
                requested_tool=primary,
                chosen_tool=primary,
                reason=f"Primary tool '{primary}' available at {primary_path}",
                is_fallback=False,
                tool_path=primary_path,
            )
            self._routing_log.append(decision)
            logger.info(f"[{category}] Routing to PRIMARY: {primary} ({primary_path})")
            return decision

        # Try fallbacks
        for fallback in fallbacks:
            fallback_path = self.find_tool(fallback)
            if fallback_path:
                decision = RoutingDecision(
                    requested_tool=primary,
                    chosen_tool=fallback,
                    reason=f"Primary '{primary}' not found. Falling back to '{fallback}' at {fallback_path}",
                    is_fallback=True,
                    tool_path=fallback_path,
                )
                self._routing_log.append(decision)
                logger.warning(f"[{category}] Fallback to: {fallback} ({fallback_path})")
                return decision

        # Nothing available - fall back to Python
        decision = RoutingDecision(
            requested_tool=primary,
            chosen_tool="python_fallback",
            reason=f"No Kali tools available ({primary}, {fallbacks}). Using Python fallback.",
            is_fallback=True,
            tool_path=None,
        )
        self._routing_log.append(decision)
        logger.warning(f"[{category}] No Kali tools found. Using Python fallback.")
        return decision

    async def run_tool(
        self,
        tool_name: str,
        args: List[str],
        target: str = "",
        timeout: int = 300,
        stdin_data: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        parse_json: bool = False,
        parse_xml: bool = False,
    ) -> UnifiedResult:
        """
        Run a Kali tool as subprocess and capture output.

        Args:
            tool_name: Tool binary name
            args: Command-line arguments
            target: Target identifier for the result
            timeout: Execution timeout in seconds
            stdin_data: Data to pipe to stdin
            env: Additional environment variables
            parse_json: Attempt to parse stdout as JSON
            parse_xml: Attempt to parse stdout as XML

        Returns:
            UnifiedResult with captured output.
        """
        tool_path = self.find_tool(tool_name)
        if not tool_path:
            return UnifiedResult(
                tool_used=tool_name,
                target=target,
                errors=[f"Tool '{tool_name}' not found on system"],
                exit_code=-1,
            )

        cmd = [tool_path] + args
        logger.info(f"Executing: {' '.join(cmd[:5])}{'...' if len(cmd) > 5 else ''}")

        # Build environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        start_time = time.monotonic()
        result = UnifiedResult(tool_used=tool_name, target=target)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                env=run_env,
            )

            stdin_bytes = stdin_data.encode() if stdin_data else None
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes),
                timeout=timeout,
            )

            result.exit_code = proc.returncode or 0
            result.raw_output = stdout.decode("utf-8", errors="replace")
            result.duration_seconds = time.monotonic() - start_time

            if stderr:
                stderr_text = stderr.decode("utf-8", errors="replace").strip()
                if stderr_text:
                    # Only treat as error if exit code is non-zero
                    if result.exit_code != 0:
                        result.errors.append(stderr_text[:2000])
                    else:
                        logger.debug(f"stderr (info): {stderr_text[:200]}")

            # Parse output
            if parse_json and result.raw_output.strip():
                result.parsed_data = self._parse_json_output(result.raw_output)
            elif parse_xml and result.raw_output.strip():
                result.parsed_data = self._parse_xml_output(result.raw_output)

        except asyncio.TimeoutError:
            result.errors.append(f"Tool '{tool_name}' timed out after {timeout}s")
            result.exit_code = -2
            result.duration_seconds = timeout
            logger.error(f"Timeout: {tool_name} exceeded {timeout}s")

        except FileNotFoundError:
            result.errors.append(f"Tool binary not found at '{tool_path}'")
            result.exit_code = -1
            logger.error(f"Binary not found: {tool_path}")

        except Exception as e:
            result.errors.append(f"Execution error: {str(e)}")
            result.exit_code = -3
            result.duration_seconds = time.monotonic() - start_time
            logger.error(f"Error running {tool_name}: {e}")

        return result

    def run_tool_sync(
        self,
        tool_name: str,
        args: List[str],
        target: str = "",
        timeout: int = 300,
        stdin_data: Optional[str] = None,
    ) -> UnifiedResult:
        """Synchronous version of run_tool for simpler use cases."""
        tool_path = self.find_tool(tool_name)
        if not tool_path:
            return UnifiedResult(
                tool_used=tool_name,
                target=target,
                errors=[f"Tool '{tool_name}' not found on system"],
                exit_code=-1,
            )

        cmd = [tool_path] + args
        start_time = time.monotonic()
        result = UnifiedResult(tool_used=tool_name, target=target)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=stdin_data,
            )
            result.exit_code = proc.returncode
            result.raw_output = proc.stdout
            result.duration_seconds = time.monotonic() - start_time

            if proc.stderr and proc.returncode != 0:
                result.errors.append(proc.stderr[:2000])

        except subprocess.TimeoutExpired:
            result.errors.append(f"Tool '{tool_name}' timed out after {timeout}s")
            result.exit_code = -2
        except Exception as e:
            result.errors.append(f"Execution error: {str(e)}")
            result.exit_code = -3

        return result

    # --- Output Parsers ---

    def _parse_json_output(self, raw: str) -> Dict[str, Any]:
        """Parse JSON output (handles JSONL / line-delimited JSON too)."""
        raw = raw.strip()
        if not raw:
            return {}

        # Try single JSON object/array
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Try JSONL (one JSON object per line)
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if items:
            return {"items": items, "count": len(items)}

        return {"raw_lines": raw.splitlines()[:100]}

    def _parse_xml_output(self, raw: str) -> Dict[str, Any]:
        """Parse XML output (primarily for nmap)."""
        try:
            root = ET.fromstring(raw)
            return self._xml_to_dict(root)
        except ET.ParseError as e:
            logger.warning(f"XML parse error: {e}")
            return {"parse_error": str(e)}

    def _xml_to_dict(self, element: ET.Element) -> Dict[str, Any]:
        """Recursively convert XML element to dict."""
        result: Dict[str, Any] = {}

        # Attributes
        if element.attrib:
            result["@attributes"] = dict(element.attrib)

        # Text content
        if element.text and element.text.strip():
            result["@text"] = element.text.strip()

        # Children
        children: Dict[str, List] = {}
        for child in element:
            tag = child.tag
            child_dict = self._xml_to_dict(child)
            if tag not in children:
                children[tag] = []
            children[tag].append(child_dict)

        for tag, items in children.items():
            result[tag] = items[0] if len(items) == 1 else items

        return result

    @staticmethod
    def parse_nmap_xml(xml_data: str) -> List[Dict[str, Any]]:
        """
        Parse nmap XML output into a list of host/port results.

        Returns list of dicts with: host, ports [{port, protocol, state, service, version}]
        """
        hosts = []
        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError:
            return hosts

        for host_elem in root.findall(".//host"):
            host_info: Dict[str, Any] = {"ports": []}

            # Get address
            addr = host_elem.find("address")
            if addr is not None:
                host_info["ip"] = addr.get("addr", "")
                host_info["addr_type"] = addr.get("addrtype", "")

            # Get hostname
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    host_info["hostname"] = hn.get("name", "")

            # Get ports
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_info = {
                        "port": int(port_elem.get("portid", 0)),
                        "protocol": port_elem.get("protocol", "tcp"),
                    }
                    state = port_elem.find("state")
                    if state is not None:
                        port_info["state"] = state.get("state", "")

                    service = port_elem.find("service")
                    if service is not None:
                        port_info["service"] = service.get("name", "")
                        port_info["version"] = service.get("version", "")
                        port_info["product"] = service.get("product", "")
                        port_info["extra_info"] = service.get("extrainfo", "")

                    host_info["ports"].append(port_info)

            # Get OS detection
            os_elem = host_elem.find("os")
            if os_elem is not None:
                os_match = os_elem.find("osmatch")
                if os_match is not None:
                    host_info["os"] = os_match.get("name", "")
                    host_info["os_accuracy"] = os_match.get("accuracy", "")

            hosts.append(host_info)

        return hosts

    @staticmethod
    def parse_ffuf_json(json_data: str) -> List[Dict[str, Any]]:
        """
        Parse ffuf JSON output into a list of discovered results.

        Returns list of dicts with: url, status, length, words, lines, input.
        """
        results = []
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError:
            return results

        for item in data.get("results", []):
            results.append({
                "url": item.get("url", ""),
                "status": item.get("status", 0),
                "length": item.get("length", 0),
                "words": item.get("words", 0),
                "lines": item.get("lines", 0),
                "input": item.get("input", {}).get("FUZZ", ""),
                "redirect_location": item.get("redirectlocation", ""),
                "content_type": item.get("content-type", ""),
            })

        return results

    @staticmethod
    def parse_nuclei_jsonl(jsonl_data: str) -> List[Dict[str, Any]]:
        """
        Parse nuclei JSONL output into a list of findings.

        Returns list of dicts with: template_id, name, severity, url, matched_at, etc.
        """
        findings = []
        for line in jsonl_data.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                findings.append({
                    "template_id": item.get("template-id", ""),
                    "name": item.get("info", {}).get("name", ""),
                    "severity": item.get("info", {}).get("severity", "info"),
                    "description": item.get("info", {}).get("description", ""),
                    "url": item.get("matched-at", item.get("host", "")),
                    "matched_at": item.get("matched-at", ""),
                    "matcher_name": item.get("matcher-name", ""),
                    "extracted_results": item.get("extracted-results", []),
                    "curl_command": item.get("curl-command", ""),
                    "tags": item.get("info", {}).get("tags", []),
                    "reference": item.get("info", {}).get("reference", []),
                })
            except json.JSONDecodeError:
                continue

        return findings

    @staticmethod
    def parse_whatweb_json(json_data: str) -> List[Dict[str, Any]]:
        """Parse whatweb JSON output into tech stack results."""
        results = []
        try:
            data = json.loads(json_data)
            if isinstance(data, list):
                for item in data:
                    result = {
                        "target": item.get("target", ""),
                        "status": item.get("http_status", 0),
                        "technologies": [],
                    }
                    plugins = item.get("plugins", {})
                    for plugin_name, plugin_data in plugins.items():
                        tech = {"name": plugin_name}
                        if isinstance(plugin_data, dict):
                            if "version" in plugin_data:
                                version = plugin_data["version"]
                                if isinstance(version, list):
                                    tech["version"] = version[0] if version else ""
                                else:
                                    tech["version"] = str(version)
                            if "string" in plugin_data:
                                tech["details"] = plugin_data["string"]
                        result["technologies"].append(tech)
                    results.append(result)
        except json.JSONDecodeError:
            pass
        return results

    @staticmethod
    def parse_line_output(raw: str) -> List[str]:
        """Parse line-delimited output (subfinder, httpx, etc.)."""
        return [line.strip() for line in raw.strip().splitlines() if line.strip()]

    def get_routing_log(self) -> List[Dict[str, Any]]:
        """Get all routing decisions made during this session."""
        return [d.to_dict() for d in self._routing_log]

    def get_temp_file(self, suffix: str = ".tmp") -> str:
        """Create a temporary file path for tool output."""
        fd, path = tempfile.mkstemp(suffix=suffix, prefix="shadow_")
        os.close(fd)
        return path

    def get_wordlist(self, category: str) -> str:
        """
        Get the best available wordlist for a category.

        Prefers Kali wordlists, falls back to custom SHADOW wordlists.
        """
        project_root = Path(__file__).parent.parent

        wordlist_map = {
            "directories": [
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
                str(project_root / "config" / "wordlists" / "directories.txt"),
            ],
            "subdomains": [
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/wordlists/dnsmap.txt",
                str(project_root / "config" / "wordlists" / "subdomains.txt"),
            ],
            "parameters": [
                "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
                str(project_root / "config" / "wordlists" / "parameters.txt"),
            ],
            "sqli_payloads": [
                str(project_root / "config" / "payloads" / "sqli" / "payloads.txt"),
            ],
            "xss_payloads": [
                str(project_root / "config" / "payloads" / "xss" / "payloads.txt"),
            ],
        }

        for path in wordlist_map.get(category, []):
            if os.path.isfile(path):
                logger.debug(f"Wordlist [{category}]: {path}")
                return path

        logger.warning(f"No wordlist found for category: {category}")
        return ""


async def main():
    """CLI for checking tool availability."""
    parser = argparse.ArgumentParser(
        description="SHADOW Tool Router - Check Kali tool availability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--check", nargs="*", default=None,
        help="Check specific tools (space-separated)"
    )
    parser.add_argument(
        "--check-all", action="store_true",
        help="Check all known tools"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON"
    )

    args = parser.parse_args()
    router = ToolRouter()

    all_tools = [
        "nmap", "naabu", "subfinder", "amass", "httpx", "nuclei", "nikto",
        "sqlmap", "commix", "ffuf", "gobuster", "dirb", "wfuzz", "whatweb",
        "wafw00f", "wpscan", "droopescan", "hydra", "john", "hashcat",
        "sslscan", "sslyze", "katana", "dnsx", "dnsrecon", "fierce",
        "shodan", "theHarvester", "cewl", "urlfinder", "interactsh-client",
        "msfconsole", "burpsuite", "responder", "netexec",
    ]

    if args.check_all:
        tools_to_check = all_tools
    elif args.check is not None:
        tools_to_check = args.check if args.check else all_tools
    else:
        tools_to_check = all_tools

    results = router.check_tools(tools_to_check)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        available = sum(1 for v in results.values() if v is not None)
        print(f"\nSHADOW Tool Router - {available}/{len(results)} tools available\n")
        print(f"{'Tool':<25} {'Status':<10} {'Path'}")
        print("-" * 70)
        for tool, path in sorted(results.items()):
            status = "OK" if path else "MISSING"
            path_str = path or "not found"
            print(f"{tool:<25} {status:<10} {path_str}")


if __name__ == "__main__":
    asyncio.run(main())

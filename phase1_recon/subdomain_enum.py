#!/usr/bin/env python3
"""
Subdomain enumeration module using multiple sources.

Usage:
    python subdomain_enum.py --target example.com --output results/
"""

import argparse
import asyncio
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("subdomain_enum")


@dataclass
class Subdomain:
    """Represents a discovered subdomain."""

    name: str
    source: str
    resolved: bool = False
    ip_addresses: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "resolved": self.resolved,
            "ip_addresses": self.ip_addresses,
            "cname": self.cname,
            "status_code": self.status_code,
            "title": self.title,
        }


class SubdomainEnumerator:
    """
    Subdomain enumeration using multiple sources and tools.

    Sources:
    - Certificate Transparency (crt.sh)
    - DNS brute forcing
    - Subfinder (if available)
    - Amass (if available)
    - Web archives
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        threads: int = 50,
        wordlist: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.wordlist = wordlist
        self.verbose = verbose

        self.subdomains: Dict[str, Subdomain] = {}
        self.result_manager = ResultManager(output_dir)

        ensure_dir(self.output_dir)

    async def enumerate(self) -> ScanResult:
        """Run all enumeration methods and return results."""
        result = ScanResult(
            tool="subdomain_enum",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "wordlist": self.wordlist,
            },
        )

        logger.info(f"Starting subdomain enumeration for: {self.target}")

        # Run enumeration methods concurrently
        tasks = [
            self._enumerate_crtsh(),
            self._enumerate_hackertarget(),
            self._enumerate_threatcrowd(),
            self._enumerate_urlscan(),
        ]

        # Add tool-based enumeration if available
        if self._tool_exists("subfinder"):
            tasks.append(self._enumerate_subfinder())
        if self._tool_exists("amass"):
            tasks.append(self._enumerate_amass())
        if self._tool_exists("assetfinder"):
            tasks.append(self._enumerate_assetfinder())

        # Run DNS brute force if wordlist provided
        if self.wordlist:
            tasks.append(self._dns_bruteforce())

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            result.add_error(f"Enumeration error: {e}")
            logger.error(f"Enumeration error: {e}")

        # Resolve and probe discovered subdomains
        await self._resolve_subdomains()
        await self._probe_http()

        # Calculate statistics
        result.stats = {
            "total_found": len(self.subdomains),
            "resolved": sum(1 for s in self.subdomains.values() if s.resolved),
            "http_alive": sum(1 for s in self.subdomains.values() if s.status_code),
            "sources": self._get_source_stats(),
        }

        # Add findings for live subdomains
        for subdomain in self.subdomains.values():
            if subdomain.status_code:
                severity = Severity.INFO
                if subdomain.status_code in [200, 301, 302]:
                    severity = Severity.LOW

                result.add_finding(Finding(
                    title=f"Subdomain Found: {subdomain.name}",
                    severity=severity,
                    description=f"Live subdomain discovered via {subdomain.source}",
                    url=f"https://{subdomain.name}",
                    metadata={
                        "ip_addresses": subdomain.ip_addresses,
                        "status_code": subdomain.status_code,
                        "title": subdomain.title,
                    },
                ))

        result.finalize()
        return result

    async def _enumerate_crtsh(self):
        """Enumerate subdomains using crt.sh certificate transparency."""
        logger.info("Querying crt.sh...")
        url = f"https://crt.sh/?q=%.{self.target}&output=json"

        try:
            async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
                response = await client.get(url)

                if response.ok and response.body:
                    try:
                        data = json.loads(response.body)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub.endswith(self.target) and "*" not in sub:
                                    self._add_subdomain(sub, "crt.sh")
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse crt.sh response")

        except Exception as e:
            logger.error(f"crt.sh error: {e}")

        logger.info(f"crt.sh: Found {len([s for s in self.subdomains.values() if s.source == 'crt.sh'])} subdomains")

    async def _enumerate_hackertarget(self):
        """Enumerate subdomains using HackerTarget API."""
        logger.info("Querying HackerTarget...")
        url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"

        try:
            async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
                response = await client.get(url)

                if response.ok and response.body:
                    for line in response.body.split("\n"):
                        if "," in line:
                            subdomain = line.split(",")[0].strip().lower()
                            if subdomain.endswith(self.target):
                                self._add_subdomain(subdomain, "hackertarget")

        except Exception as e:
            logger.error(f"HackerTarget error: {e}")

    async def _enumerate_threatcrowd(self):
        """Enumerate subdomains using ThreatCrowd API."""
        logger.info("Querying ThreatCrowd...")
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target}"

        try:
            async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
                response = await client.get(url)

                if response.ok and response.body:
                    try:
                        data = json.loads(response.body)
                        subdomains = data.get("subdomains", [])
                        for sub in subdomains:
                            sub = sub.strip().lower()
                            if sub.endswith(self.target):
                                self._add_subdomain(sub, "threatcrowd")
                    except json.JSONDecodeError:
                        pass

        except Exception as e:
            logger.error(f"ThreatCrowd error: {e}")

    async def _enumerate_urlscan(self):
        """Enumerate subdomains using urlscan.io."""
        logger.info("Querying urlscan.io...")
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.target}"

        try:
            async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
                response = await client.get(url)

                if response.ok and response.body:
                    try:
                        data = json.loads(response.body)
                        for result in data.get("results", []):
                            page = result.get("page", {})
                            domain = page.get("domain", "").lower()
                            if domain.endswith(self.target):
                                self._add_subdomain(domain, "urlscan")
                    except json.JSONDecodeError:
                        pass

        except Exception as e:
            logger.error(f"urlscan.io error: {e}")

    async def _enumerate_subfinder(self):
        """Enumerate subdomains using subfinder."""
        logger.info("Running subfinder...")

        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", self.target, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)

            for line in stdout.decode().split("\n"):
                sub = line.strip().lower()
                if sub and sub.endswith(self.target):
                    self._add_subdomain(sub, "subfinder")

        except asyncio.TimeoutError:
            logger.warning("subfinder timed out")
        except Exception as e:
            logger.error(f"subfinder error: {e}")

    async def _enumerate_amass(self):
        """Enumerate subdomains using amass."""
        logger.info("Running amass (passive)...")

        try:
            proc = await asyncio.create_subprocess_exec(
                "amass", "enum", "-passive", "-d", self.target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)

            for line in stdout.decode().split("\n"):
                sub = line.strip().lower()
                if sub and sub.endswith(self.target):
                    self._add_subdomain(sub, "amass")

        except asyncio.TimeoutError:
            logger.warning("amass timed out")
        except Exception as e:
            logger.error(f"amass error: {e}")

    async def _enumerate_assetfinder(self):
        """Enumerate subdomains using assetfinder."""
        logger.info("Running assetfinder...")

        try:
            proc = await asyncio.create_subprocess_exec(
                "assetfinder", "--subs-only", self.target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)

            for line in stdout.decode().split("\n"):
                sub = line.strip().lower()
                if sub and sub.endswith(self.target):
                    self._add_subdomain(sub, "assetfinder")

        except asyncio.TimeoutError:
            logger.warning("assetfinder timed out")
        except Exception as e:
            logger.error(f"assetfinder error: {e}")

    async def _dns_bruteforce(self):
        """Brute force subdomains using wordlist."""
        if not self.wordlist or not Path(self.wordlist).exists():
            logger.warning(f"Wordlist not found: {self.wordlist}")
            return

        logger.info(f"Running DNS brute force with {self.wordlist}...")

        with open(self.wordlist, "r") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        semaphore = asyncio.Semaphore(self.threads)

        async def check_subdomain(word: str):
            async with semaphore:
                subdomain = f"{word}.{self.target}"
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, resolver.resolve, subdomain, "A")
                    self._add_subdomain(subdomain, "bruteforce")
                except Exception:
                    pass

        tasks = [check_subdomain(word) for word in words[:10000]]  # Limit to 10k
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _resolve_subdomains(self):
        """Resolve IP addresses for discovered subdomains."""
        logger.info("Resolving subdomains...")

        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        semaphore = asyncio.Semaphore(self.threads)

        async def resolve_one(subdomain: Subdomain):
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        None, resolver.resolve, subdomain.name, "A"
                    )
                    subdomain.ip_addresses = [str(rdata) for rdata in answers]
                    subdomain.resolved = True
                except Exception:
                    pass

                # Try CNAME
                try:
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        None, resolver.resolve, subdomain.name, "CNAME"
                    )
                    subdomain.cname = str(answers[0].target)
                except Exception:
                    pass

        tasks = [resolve_one(sub) for sub in self.subdomains.values()]
        await asyncio.gather(*tasks, return_exceptions=True)

        resolved_count = sum(1 for s in self.subdomains.values() if s.resolved)
        logger.info(f"Resolved {resolved_count}/{len(self.subdomains)} subdomains")

    async def _probe_http(self):
        """Probe subdomains for HTTP/HTTPS services."""
        logger.info("Probing HTTP services...")

        resolved_subs = [s for s in self.subdomains.values() if s.resolved]

        async with AsyncHTTPClient(
            timeout=10,
            proxy=self.proxy,
            max_retries=1,
            follow_redirects=True,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)

            async def probe_one(subdomain: Subdomain):
                async with semaphore:
                    for scheme in ["https", "http"]:
                        url = f"{scheme}://{subdomain.name}"
                        try:
                            response = await client.get(url)
                            if response.status > 0:
                                subdomain.status_code = response.status
                                # Extract title
                                title_match = re.search(
                                    r"<title[^>]*>([^<]+)</title>",
                                    response.body,
                                    re.IGNORECASE,
                                )
                                if title_match:
                                    subdomain.title = title_match.group(1).strip()[:100]
                                break
                        except Exception:
                            pass

            tasks = [probe_one(sub) for sub in resolved_subs]
            await asyncio.gather(*tasks, return_exceptions=True)

        alive_count = sum(1 for s in self.subdomains.values() if s.status_code)
        logger.info(f"HTTP alive: {alive_count}/{len(resolved_subs)}")

    def _add_subdomain(self, name: str, source: str):
        """Add a subdomain to the results."""
        name = name.strip().lower()
        if not name or not name.endswith(self.target):
            return

        if name not in self.subdomains:
            self.subdomains[name] = Subdomain(name=name, source=source)
        elif self.verbose:
            logger.debug(f"Duplicate: {name} (existing: {self.subdomains[name].source}, new: {source})")

    def _get_source_stats(self) -> Dict[str, int]:
        """Get count of subdomains per source."""
        stats: Dict[str, int] = {}
        for sub in self.subdomains.values():
            stats[sub.source] = stats.get(sub.source, 0) + 1
        return stats

    def _tool_exists(self, tool: str) -> bool:
        """Check if a tool is available in PATH."""
        try:
            subprocess.run(
                ["which", tool],
                capture_output=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        # Save via result manager
        paths = self.result_manager.save(result, f"subdomains_{self.target}")

        # Save raw subdomain list
        txt_path = self.output_dir / f"subdomains_{self.target}.txt"
        with open(txt_path, "w") as f:
            for name in sorted(self.subdomains.keys()):
                f.write(f"{name}\n")
        paths["txt"] = str(txt_path)

        # Save detailed JSON
        detailed_path = self.output_dir / f"subdomains_{self.target}_detailed.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "total": len(self.subdomains),
                    "subdomains": [s.to_dict() for s in self.subdomains.values()],
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="Subdomain enumeration using multiple sources"
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("-w", "--wordlist", help="Wordlist for DNS brute force")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    enumerator = SubdomainEnumerator(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        wordlist=args.wordlist,
        verbose=args.verbose,
    )

    result = await enumerator.enumerate()
    paths = enumerator.save_results(result)

    print(f"\n{'='*60}")
    print(f"Subdomain Enumeration Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Total Found: {len(enumerator.subdomains)}")
    print(f"Resolved: {result.stats.get('resolved', 0)}")
    print(f"HTTP Alive: {result.stats.get('http_alive', 0)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

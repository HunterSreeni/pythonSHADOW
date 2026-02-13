#!/usr/bin/env python3
"""
DNS enumeration module for comprehensive DNS record discovery.

Usage:
    python dns_enum.py --target example.com --output results/
"""

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, extract_domain, timestamp_now, ensure_dir, read_lines

logger = setup_logging("dns_enum")

# Import dns.resolver
try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed. Install with: pip install dnspython")


# Common DNS record types to query
DNS_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME",
    "SRV", "CAA", "PTR", "DMARC", "SPF"
]

# SPF and DMARC specific record names
SPECIAL_RECORDS = {
    "DMARC": "_dmarc",
    "SPF": "",
}


@dataclass
class DNSRecord:
    """Represents a DNS record."""

    record_type: str
    name: str
    value: str
    ttl: int = 0
    priority: Optional[int] = None  # For MX records

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "type": self.record_type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
        }
        if self.priority is not None:
            data["priority"] = self.priority
        return data


@dataclass
class DNSResult:
    """DNS enumeration result for a domain."""

    domain: str
    records: List[DNSRecord] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    mail_servers: List[str] = field(default_factory=list)
    zone_transfer_possible: bool = False
    zone_transfer_data: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "records": [r.to_dict() for r in self.records],
            "nameservers": self.nameservers,
            "mail_servers": self.mail_servers,
            "zone_transfer_possible": self.zone_transfer_possible,
            "zone_transfer_data": self.zone_transfer_data[:100],
        }


class DNSEnumerator:
    """
    DNS enumeration tool.

    Features:
    - Multiple record type queries
    - Zone transfer attempts
    - DNS brute forcing
    - Security record analysis (SPF, DMARC, CAA)
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        nameservers: Optional[List[str]] = None,
        timeout: float = 5.0,
        threads: int = 50,
        wordlist: Optional[str] = None,
        try_zone_transfer: bool = True,
        verbose: bool = False,
    ):
        if not DNS_AVAILABLE:
            raise ImportError("dnspython is required. Install with: pip install dnspython")

        self.target = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.threads = threads
        self.wordlist = wordlist
        self.try_zone_transfer = try_zone_transfer
        self.verbose = verbose

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

        if nameservers:
            self.resolver.nameservers = nameservers
        else:
            self.resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

        self.dns_result = DNSResult(domain=self.target)
        self.discovered_subdomains: Set[str] = set()
        self.result_manager = ResultManager(output_dir)

        ensure_dir(self.output_dir)

    async def enumerate(self) -> ScanResult:
        """Run comprehensive DNS enumeration."""
        result = ScanResult(
            tool="dns_enum",
            target=self.target,
            config={
                "timeout": self.timeout,
                "threads": self.threads,
                "zone_transfer": self.try_zone_transfer,
            },
        )

        logger.info(f"Starting DNS enumeration for: {self.target}")

        # Query all record types
        await self._query_all_records()

        # Try zone transfer
        if self.try_zone_transfer:
            await self._attempt_zone_transfer()

        # DNS brute force if wordlist provided
        if self.wordlist:
            await self._dns_bruteforce()

        # Analyze security records
        self._analyze_security_records(result)

        # Generate findings
        self._generate_findings(result)

        # Statistics
        result.stats = {
            "total_records": len(self.dns_result.records),
            "record_types": self._count_record_types(),
            "nameservers": len(self.dns_result.nameservers),
            "mail_servers": len(self.dns_result.mail_servers),
            "zone_transfer_vulnerable": self.dns_result.zone_transfer_possible,
            "subdomains_discovered": len(self.discovered_subdomains),
        }

        result.finalize()
        return result

    async def _query_all_records(self):
        """Query all DNS record types."""
        logger.info("Querying DNS records...")

        for record_type in DNS_RECORD_TYPES:
            await self._query_record(self.target, record_type)

        # Query special records
        await self._query_record(f"_dmarc.{self.target}", "TXT", record_name="DMARC")

        logger.info(f"Found {len(self.dns_result.records)} DNS records")

    async def _query_record(
        self,
        domain: str,
        record_type: str,
        record_name: Optional[str] = None,
    ):
        """Query a specific DNS record type."""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, record_type)
            )

            for rdata in answers:
                record = DNSRecord(
                    record_type=record_name or record_type,
                    name=domain,
                    value=str(rdata),
                    ttl=answers.ttl,
                )

                # Extract priority for MX records
                if record_type == "MX":
                    record.priority = rdata.preference
                    record.value = str(rdata.exchange)
                    self.dns_result.mail_servers.append(str(rdata.exchange))

                # Track nameservers
                if record_type == "NS":
                    self.dns_result.nameservers.append(str(rdata))

                self.dns_result.records.append(record)

                if self.verbose:
                    logger.debug(f"{record_type}: {record.value}")

        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            pass
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error querying {record_type} for {domain}: {e}")

    async def _attempt_zone_transfer(self):
        """Attempt zone transfer from nameservers."""
        logger.info("Attempting zone transfer...")

        # Get authoritative nameservers
        nameservers = self.dns_result.nameservers or []

        if not nameservers:
            try:
                loop = asyncio.get_event_loop()
                ns_answers = await loop.run_in_executor(
                    None,
                    lambda: self.resolver.resolve(self.target, "NS")
                )
                nameservers = [str(ns) for ns in ns_answers]
            except Exception:
                pass

        for ns in nameservers:
            try:
                # Resolve NS to IP
                ns_ip = None
                try:
                    loop = asyncio.get_event_loop()
                    a_answers = await loop.run_in_executor(
                        None,
                        lambda: self.resolver.resolve(ns.rstrip("."), "A")
                    )
                    ns_ip = str(a_answers[0])
                except Exception:
                    continue

                if not ns_ip:
                    continue

                # Attempt zone transfer
                loop = asyncio.get_event_loop()
                zone = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: dns.zone.from_xfr(
                            dns.query.xfr(ns_ip, self.target, timeout=10)
                        )
                    ),
                    timeout=15
                )

                if zone:
                    self.dns_result.zone_transfer_possible = True
                    logger.warning(f"Zone transfer successful from {ns}!")

                    for name, node in zone.nodes.items():
                        name_str = str(name)
                        if name_str != "@":
                            subdomain = f"{name_str}.{self.target}"
                            self.discovered_subdomains.add(subdomain)
                            self.dns_result.zone_transfer_data.append(subdomain)

                    break

            except asyncio.TimeoutError:
                if self.verbose:
                    logger.debug(f"Zone transfer timeout: {ns}")
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Zone transfer failed for {ns}: {e}")

        if not self.dns_result.zone_transfer_possible:
            logger.info("Zone transfer not possible (good security)")

    async def _dns_bruteforce(self):
        """Brute force subdomains using wordlist."""
        if not self.wordlist or not Path(self.wordlist).exists():
            logger.warning(f"Wordlist not found: {self.wordlist}")
            return

        logger.info(f"Starting DNS brute force with {self.wordlist}...")

        words = read_lines(self.wordlist)
        if not words:
            return

        semaphore = asyncio.Semaphore(self.threads)

        async def check_subdomain(word: str):
            async with semaphore:
                subdomain = f"{word}.{self.target}"
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        lambda: self.resolver.resolve(subdomain, "A")
                    )
                    self.discovered_subdomains.add(subdomain)

                    if self.verbose:
                        logger.debug(f"Found: {subdomain}")

                except Exception:
                    pass

        # Limit to prevent excessive queries
        words_to_check = words[:10000]
        tasks = [check_subdomain(word) for word in words_to_check]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Brute force found {len(self.discovered_subdomains)} subdomains")

    def _analyze_security_records(self, result: ScanResult):
        """Analyze security-related DNS records."""
        txt_records = [r for r in self.dns_result.records if r.record_type == "TXT"]
        dmarc_records = [r for r in self.dns_result.records if r.record_type == "DMARC"]
        caa_records = [r for r in self.dns_result.records if r.record_type == "CAA"]

        # Check SPF
        spf_found = any("v=spf1" in r.value.lower() for r in txt_records)
        if not spf_found:
            result.add_finding(Finding(
                title="Missing SPF Record",
                severity=Severity.LOW,
                description="No SPF record found. Domain may be vulnerable to email spoofing.",
                url=self.target,
            ))

        # Check DMARC
        dmarc_found = any("v=dmarc1" in r.value.lower() for r in txt_records + dmarc_records)
        if not dmarc_found:
            result.add_finding(Finding(
                title="Missing DMARC Record",
                severity=Severity.LOW,
                description="No DMARC record found. Domain may be vulnerable to email spoofing.",
                url=self.target,
            ))

        # Check CAA
        if not caa_records:
            result.add_finding(Finding(
                title="Missing CAA Record",
                severity=Severity.INFO,
                description="No CAA record found. Any CA can issue certificates for this domain.",
                url=self.target,
            ))

        # Check for wildcard DNS
        self._check_wildcard_dns(result)

    def _check_wildcard_dns(self, result: ScanResult):
        """Check for wildcard DNS configuration."""
        import random
        import string

        random_subdomain = "".join(random.choices(string.ascii_lowercase, k=20))
        test_domain = f"{random_subdomain}.{self.target}"

        try:
            self.resolver.resolve(test_domain, "A")
            result.add_finding(Finding(
                title="Wildcard DNS Detected",
                severity=Severity.INFO,
                description="Domain has wildcard DNS configured. All subdomains resolve.",
                url=self.target,
            ))
        except Exception:
            pass

    def _generate_findings(self, result: ScanResult):
        """Generate findings from enumeration results."""
        # Zone transfer vulnerability
        if self.dns_result.zone_transfer_possible:
            result.add_finding(Finding(
                title="DNS Zone Transfer Possible",
                severity=Severity.HIGH,
                description="Zone transfer is allowed, exposing all DNS records and subdomains.",
                url=self.target,
                metadata={
                    "subdomains_exposed": len(self.dns_result.zone_transfer_data),
                    "samples": self.dns_result.zone_transfer_data[:20],
                },
            ))

        # Multiple nameservers (good) or single (bad)
        if len(self.dns_result.nameservers) < 2:
            result.add_finding(Finding(
                title="Single Point of Failure - DNS",
                severity=Severity.LOW,
                description="Only one nameserver found. No redundancy for DNS.",
                url=self.target,
            ))

        # Add finding for discovered subdomains
        if self.discovered_subdomains:
            result.add_finding(Finding(
                title=f"Subdomains Discovered: {len(self.discovered_subdomains)}",
                severity=Severity.INFO,
                description=f"Found {len(self.discovered_subdomains)} subdomains via DNS enumeration",
                url=self.target,
                metadata={
                    "subdomains": sorted(list(self.discovered_subdomains))[:50],
                },
            ))

    def _count_record_types(self) -> Dict[str, int]:
        """Count records by type."""
        counts: Dict[str, int] = {}
        for record in self.dns_result.records:
            counts[record.record_type] = counts.get(record.record_type, 0) + 1
        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"dns_{self.target}")

        # Save detailed JSON
        detailed_path = self.output_dir / f"dns_{self.target}_detailed.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "dns_result": self.dns_result.to_dict(),
                    "discovered_subdomains": sorted(list(self.discovered_subdomains)),
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        # Save subdomains
        if self.discovered_subdomains:
            subdomains_path = self.output_dir / f"dns_subdomains_{self.target}.txt"
            with open(subdomains_path, "w") as f:
                for subdomain in sorted(self.discovered_subdomains):
                    f.write(f"{subdomain}\n")
            paths["subdomains"] = str(subdomains_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="DNS enumeration")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-n", "--nameservers", help="Custom nameservers (comma-separated)")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout")
    parser.add_argument("-w", "--wordlist", help="Wordlist for brute force")
    parser.add_argument("--no-zone-transfer", action="store_true", help="Skip zone transfer")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    nameservers = None
    if args.nameservers:
        nameservers = [ns.strip() for ns in args.nameservers.split(",")]

    enumerator = DNSEnumerator(
        target=args.target,
        output_dir=args.output,
        nameservers=nameservers,
        timeout=args.timeout,
        threads=args.threads,
        wordlist=args.wordlist,
        try_zone_transfer=not args.no_zone_transfer,
        verbose=args.verbose,
    )

    result = await enumerator.enumerate()
    paths = enumerator.save_results(result)

    print(f"\n{'='*60}")
    print(f"DNS Enumeration Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Total Records: {result.stats.get('total_records', 0)}")
    print(f"Nameservers: {result.stats.get('nameservers', 0)}")
    print(f"Mail Servers: {result.stats.get('mail_servers', 0)}")
    print(f"Zone Transfer: {'VULNERABLE' if result.stats.get('zone_transfer_vulnerable') else 'Protected'}")
    print(f"Subdomains Discovered: {result.stats.get('subdomains_discovered', 0)}")

    if result.stats.get('record_types'):
        print(f"\nRecord Types:")
        for rtype, count in result.stats['record_types'].items():
            print(f"  {rtype}: {count}")

    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

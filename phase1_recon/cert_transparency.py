#!/usr/bin/env python3
"""
Certificate Transparency log parser for subdomain discovery.

Usage:
    python cert_transparency.py --target example.com --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("cert_transparency")


@dataclass
class Certificate:
    """Represents a certificate from CT logs."""

    id: int
    issuer: str
    common_name: str
    domains: List[str]
    not_before: str
    not_after: str
    serial: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "issuer": self.issuer,
            "common_name": self.common_name,
            "domains": self.domains,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial": self.serial,
        }

    @property
    def is_expired(self) -> bool:
        try:
            not_after = datetime.strptime(self.not_after, "%Y-%m-%dT%H:%M:%S")
            return datetime.utcnow() > not_after
        except Exception:
            return False

    @property
    def is_wildcard(self) -> bool:
        return any("*" in d for d in self.domains)


class CertTransparency:
    """
    Certificate Transparency log parser.

    Sources:
    - crt.sh (primary)
    - certspotter
    - Google CT logs
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        proxy: Optional[str] = None,
        timeout: int = 60,
        include_expired: bool = False,
        include_wildcards: bool = True,
        verbose: bool = False,
    ):
        self.target = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.proxy = proxy
        self.timeout = timeout
        self.include_expired = include_expired
        self.include_wildcards = include_wildcards
        self.verbose = verbose

        self.certificates: List[Certificate] = []
        self.subdomains: Set[str] = set()
        self.result_manager = ResultManager(output_dir)

        ensure_dir(self.output_dir)

    async def search(self) -> ScanResult:
        """Search CT logs for certificates."""
        result = ScanResult(
            tool="cert_transparency",
            target=self.target,
            config={
                "include_expired": self.include_expired,
                "include_wildcards": self.include_wildcards,
            },
        )

        logger.info(f"Searching CT logs for: {self.target}")

        # Search multiple sources
        tasks = [
            self._search_crtsh(),
            self._search_certspotter(),
        ]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            result.add_error(f"CT search error: {e}")
            logger.error(f"CT search error: {e}")

        # Extract unique subdomains
        for cert in self.certificates:
            for domain in cert.domains:
                domain = domain.lower().strip()
                if domain.startswith("*."):
                    if self.include_wildcards:
                        # Add both wildcard and base domain
                        self.subdomains.add(domain)
                        self.subdomains.add(domain[2:])  # Remove *.
                elif domain.endswith(self.target):
                    self.subdomains.add(domain)

        # Filter expired if needed
        if not self.include_expired:
            valid_certs = [c for c in self.certificates if not c.is_expired]
            self.certificates = valid_certs

        # Generate findings
        # Group by issuer
        issuers: Dict[str, int] = {}
        for cert in self.certificates:
            issuers[cert.issuer] = issuers.get(cert.issuer, 0) + 1

        # Add finding for each unique subdomain
        for subdomain in sorted(self.subdomains):
            if subdomain.startswith("*."):
                continue  # Skip wildcards in findings

            result.add_finding(Finding(
                title=f"Subdomain from CT: {subdomain}",
                severity=Severity.INFO,
                description=f"Subdomain discovered via Certificate Transparency logs",
                url=f"https://{subdomain}",
                metadata={"source": "certificate_transparency"},
            ))

        # Statistics
        result.stats = {
            "total_certificates": len(self.certificates),
            "unique_subdomains": len([s for s in self.subdomains if not s.startswith("*.")]),
            "wildcard_certs": len([c for c in self.certificates if c.is_wildcard]),
            "expired_certs": len([c for c in self.certificates if c.is_expired]),
            "certificate_issuers": issuers,
        }

        result.finalize()
        return result

    async def _search_crtsh(self):
        """Search crt.sh for certificates."""
        logger.info("Searching crt.sh...")

        url = f"https://crt.sh/?q=%.{self.target}&output=json"

        try:
            async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
                response = await client.get(url)

                if response.ok and response.body:
                    try:
                        data = json.loads(response.body)
                        for entry in data:
                            cert = Certificate(
                                id=entry.get("id", 0),
                                issuer=entry.get("issuer_name", "Unknown"),
                                common_name=entry.get("common_name", ""),
                                domains=self._parse_names(entry.get("name_value", "")),
                                not_before=entry.get("not_before", ""),
                                not_after=entry.get("not_after", ""),
                                serial=entry.get("serial_number", ""),
                            )
                            self.certificates.append(cert)

                        logger.info(f"crt.sh: Found {len(data)} certificates")

                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse crt.sh response: {e}")

        except Exception as e:
            logger.error(f"crt.sh error: {e}")

    async def _search_certspotter(self):
        """Search Cert Spotter for certificates."""
        logger.info("Searching Cert Spotter...")

        url = f"https://api.certspotter.com/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names"

        try:
            async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
                response = await client.get(url)

                if response.ok and response.body:
                    try:
                        data = json.loads(response.body)
                        for entry in data:
                            dns_names = entry.get("dns_names", [])
                            cert = Certificate(
                                id=hash(entry.get("id", "")),
                                issuer=entry.get("issuer", {}).get("name", "Unknown"),
                                common_name=dns_names[0] if dns_names else "",
                                domains=dns_names,
                                not_before=entry.get("not_before", ""),
                                not_after=entry.get("not_after", ""),
                            )
                            self.certificates.append(cert)

                        logger.info(f"Cert Spotter: Found {len(data)} certificates")

                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse Cert Spotter response: {e}")

        except Exception as e:
            logger.error(f"Cert Spotter error: {e}")

    def _parse_names(self, name_value: str) -> List[str]:
        """Parse certificate name values."""
        names = []
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name:
                names.append(name)
        return list(set(names))

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"ct_{self.target}")

        # Save subdomain list
        txt_path = self.output_dir / f"ct_subdomains_{self.target}.txt"
        with open(txt_path, "w") as f:
            for subdomain in sorted(self.subdomains):
                if not subdomain.startswith("*."):
                    f.write(f"{subdomain}\n")
        paths["subdomains"] = str(txt_path)

        # Save detailed certificate info
        detailed_path = self.output_dir / f"ct_certificates_{self.target}.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "certificates": [c.to_dict() for c in self.certificates],
                    "subdomains": sorted(list(self.subdomains)),
                },
                f,
                indent=2,
            )
        paths["certificates"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Certificate Transparency search")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--timeout", type=int, default=60, help="Request timeout")
    parser.add_argument("--include-expired", action="store_true", help="Include expired certs")
    parser.add_argument("--no-wildcards", action="store_true", help="Exclude wildcard domains")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    ct = CertTransparency(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        timeout=args.timeout,
        include_expired=args.include_expired,
        include_wildcards=not args.no_wildcards,
        verbose=args.verbose,
    )

    result = await ct.search()
    paths = ct.save_results(result)

    print(f"\n{'='*60}")
    print(f"Certificate Transparency Search Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Certificates Found: {result.stats.get('total_certificates', 0)}")
    print(f"Unique Subdomains: {result.stats.get('unique_subdomains', 0)}")
    print(f"Wildcard Certs: {result.stats.get('wildcard_certs', 0)}")

    if result.stats.get('certificate_issuers'):
        print(f"\nTop Issuers:")
        for issuer, count in sorted(
            result.stats['certificate_issuers'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]:
            print(f"  {issuer[:50]}: {count}")

    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

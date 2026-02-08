#!/usr/bin/env python3
"""
Wayback Machine URL extractor for historical URL discovery.

Usage:
    python wayback_extractor.py --target example.com --output results/
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("wayback_extractor")


# Interesting file extensions for security testing
INTERESTING_EXTENSIONS = {
    "sensitive": [".sql", ".bak", ".backup", ".old", ".db", ".sqlite", ".mdb",
                  ".log", ".env", ".config", ".cfg", ".ini", ".conf"],
    "source_code": [".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".pl", ".java"],
    "config": [".xml", ".yml", ".yaml", ".json", ".properties"],
    "documents": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt"],
    "scripts": [".js", ".ts"],
    "archives": [".zip", ".tar", ".gz", ".rar", ".7z"],
}

# Interesting paths for security testing
INTERESTING_PATHS = [
    r"/admin", r"/api", r"/backup", r"/config", r"/debug", r"/dev",
    r"/internal", r"/login", r"/panel", r"/private", r"/secret",
    r"/staging", r"/test", r"/upload", r"/wp-admin", r"/graphql",
    r"/swagger", r"/api-docs", r"\.git", r"\.svn", r"\.env",
]


@dataclass
class WaybackURL:
    """Represents a URL from Wayback Machine."""

    url: str
    timestamp: str
    mime_type: str = ""
    status_code: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "timestamp": self.timestamp,
            "mime_type": self.mime_type,
            "status_code": self.status_code,
        }

    @property
    def path(self) -> str:
        return urlparse(self.url).path

    @property
    def extension(self) -> str:
        path = self.path.lower()
        if "." in path:
            return "." + path.rsplit(".", 1)[-1]
        return ""

    @property
    def has_params(self) -> bool:
        return "?" in self.url

    @property
    def params(self) -> Dict[str, List[str]]:
        return parse_qs(urlparse(self.url).query)


class WaybackExtractor:
    """
    Wayback Machine URL extractor.

    Features:
    - Historical URL discovery
    - Parameter extraction
    - Interesting file detection
    - Subdomain discovery
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        proxy: Optional[str] = None,
        timeout: int = 120,
        limit: int = 10000,
        filter_extensions: Optional[List[str]] = None,
        include_subdomains: bool = True,
        verbose: bool = False,
    ):
        self.target = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.proxy = proxy
        self.timeout = timeout
        self.limit = limit
        self.filter_extensions = filter_extensions
        self.include_subdomains = include_subdomains
        self.verbose = verbose

        self.urls: List[WaybackURL] = []
        self.unique_urls: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = {}  # param -> values
        self.subdomains: Set[str] = set()
        self.result_manager = ResultManager(output_dir)

        ensure_dir(self.output_dir)

    async def extract(self) -> ScanResult:
        """Extract URLs from Wayback Machine."""
        result = ScanResult(
            tool="wayback_extractor",
            target=self.target,
            config={
                "limit": self.limit,
                "include_subdomains": self.include_subdomains,
            },
        )

        logger.info(f"Extracting URLs from Wayback Machine for: {self.target}")

        # Query multiple sources
        tasks = [
            self._query_wayback_cdx(),
            self._query_commoncrawl(),
        ]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            result.add_error(f"Wayback extraction error: {e}")
            logger.error(f"Wayback extraction error: {e}")

        # Process and categorize URLs
        self._process_urls()

        # Generate findings for interesting URLs
        interesting = self._find_interesting_urls()

        for category, urls in interesting.items():
            if urls:
                result.add_finding(Finding(
                    title=f"Interesting URLs ({category}): {len(urls)} found",
                    severity=Severity.LOW if category in ["sensitive", "config"] else Severity.INFO,
                    description=f"Found {len(urls)} URLs with {category} patterns",
                    url=self.target,
                    metadata={
                        "category": category,
                        "count": len(urls),
                        "samples": list(urls)[:10],
                    },
                ))

        # Add finding for discovered parameters
        if self.parameters:
            result.add_finding(Finding(
                title=f"URL Parameters Discovered: {len(self.parameters)}",
                severity=Severity.INFO,
                description=f"Found {len(self.parameters)} unique URL parameters",
                url=self.target,
                metadata={
                    "parameters": list(self.parameters.keys())[:50],
                },
            ))

        # Statistics
        ext_counts = self._count_extensions()

        result.stats = {
            "total_urls": len(self.urls),
            "unique_urls": len(self.unique_urls),
            "urls_with_params": len([u for u in self.urls if u.has_params]),
            "unique_parameters": len(self.parameters),
            "subdomains_found": len(self.subdomains),
            "extension_breakdown": dict(sorted(ext_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
        }

        result.finalize()
        return result

    async def _query_wayback_cdx(self):
        """Query Wayback Machine CDX API."""
        logger.info("Querying Wayback Machine CDX API...")

        # Build query
        match_type = "domain" if self.include_subdomains else "host"
        url = (
            f"http://web.archive.org/cdx/search/cdx?"
            f"url={self.target}&matchType={match_type}"
            f"&output=json&collapse=urlkey"
            f"&limit={self.limit}"
            f"&fl=timestamp,original,mimetype,statuscode"
        )

        try:
            async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
                response = await client.get(url)

                if response.ok and response.body:
                    try:
                        lines = response.body.strip().split("\n")
                        for line in lines[1:]:  # Skip header
                            try:
                                data = json.loads(line)
                                if len(data) >= 4:
                                    wb_url = WaybackURL(
                                        url=data[1],
                                        timestamp=data[0],
                                        mime_type=data[2],
                                        status_code=int(data[3]) if data[3].isdigit() else 0,
                                    )
                                    self.urls.append(wb_url)
                                    self.unique_urls.add(wb_url.url)
                            except (json.JSONDecodeError, IndexError):
                                continue

                        logger.info(f"Wayback CDX: Found {len(self.urls)} URLs")

                    except Exception as e:
                        logger.warning(f"Error parsing Wayback response: {e}")

        except Exception as e:
            logger.error(f"Wayback CDX API error: {e}")

    async def _query_commoncrawl(self):
        """Query Common Crawl index."""
        logger.info("Querying Common Crawl...")

        # Get latest index
        index_url = "https://index.commoncrawl.org/collinfo.json"

        try:
            async with AsyncHTTPClient(timeout=30, proxy=self.proxy) as client:
                index_response = await client.get(index_url)

                if not index_response.ok:
                    return

                indexes = json.loads(index_response.body)
                if not indexes:
                    return

                # Query most recent index
                latest = indexes[0]["cdx-api"]
                query_url = f"{latest}?url=*.{self.target}&output=json&limit=1000"

                response = await client.get(query_url)

                if response.ok and response.body:
                    for line in response.body.strip().split("\n"):
                        try:
                            data = json.loads(line)
                            url = data.get("url", "")
                            if url and url not in self.unique_urls:
                                wb_url = WaybackURL(
                                    url=url,
                                    timestamp=data.get("timestamp", ""),
                                    mime_type=data.get("mime", ""),
                                    status_code=int(data.get("status", 0)),
                                )
                                self.urls.append(wb_url)
                                self.unique_urls.add(url)
                        except json.JSONDecodeError:
                            continue

                    logger.info(f"Common Crawl: Added {len(self.urls)} total URLs")

        except Exception as e:
            logger.error(f"Common Crawl error: {e}")

    def _process_urls(self):
        """Process URLs to extract parameters and subdomains."""
        for wb_url in self.urls:
            # Extract subdomain
            try:
                parsed = urlparse(wb_url.url)
                host = parsed.netloc.lower()
                if host.endswith(self.target):
                    self.subdomains.add(host)
            except Exception:
                pass

            # Extract parameters
            for param, values in wb_url.params.items():
                if param not in self.parameters:
                    self.parameters[param] = set()
                self.parameters[param].update(values[:5])  # Limit values

    def _find_interesting_urls(self) -> Dict[str, Set[str]]:
        """Find URLs matching interesting patterns."""
        interesting: Dict[str, Set[str]] = {
            "sensitive": set(),
            "source_code": set(),
            "config": set(),
            "documents": set(),
            "archives": set(),
            "interesting_paths": set(),
        }

        for wb_url in self.urls:
            url_lower = wb_url.url.lower()

            # Check extensions
            for category, extensions in INTERESTING_EXTENSIONS.items():
                for ext in extensions:
                    if url_lower.endswith(ext):
                        interesting[category].add(wb_url.url)
                        break

            # Check paths
            for pattern in INTERESTING_PATHS:
                if re.search(pattern, url_lower):
                    interesting["interesting_paths"].add(wb_url.url)
                    break

        return interesting

    def _count_extensions(self) -> Dict[str, int]:
        """Count URLs by file extension."""
        counts: Dict[str, int] = {}

        for wb_url in self.urls:
            ext = wb_url.extension or "(none)"
            counts[ext] = counts.get(ext, 0) + 1

        return counts

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"wayback_{self.target}")

        # Save all URLs
        urls_path = self.output_dir / f"wayback_urls_{self.target}.txt"
        with open(urls_path, "w") as f:
            for url in sorted(self.unique_urls):
                f.write(f"{url}\n")
        paths["urls"] = str(urls_path)

        # Save parameters
        params_path = self.output_dir / f"wayback_params_{self.target}.txt"
        with open(params_path, "w") as f:
            for param in sorted(self.parameters.keys()):
                f.write(f"{param}\n")
        paths["parameters"] = str(params_path)

        # Save URLs with parameters
        parameterized_path = self.output_dir / f"wayback_parameterized_{self.target}.txt"
        with open(parameterized_path, "w") as f:
            for wb_url in self.urls:
                if wb_url.has_params:
                    f.write(f"{wb_url.url}\n")
        paths["parameterized"] = str(parameterized_path)

        # Save subdomains
        subdomains_path = self.output_dir / f"wayback_subdomains_{self.target}.txt"
        with open(subdomains_path, "w") as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        paths["subdomains"] = str(subdomains_path)

        # Save detailed JSON
        detailed_path = self.output_dir / f"wayback_{self.target}_detailed.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "parameters": {p: list(v)[:10] for p, v in self.parameters.items()},
                    "subdomains": sorted(list(self.subdomains)),
                    "interesting": {
                        k: list(v)[:50]
                        for k, v in self._find_interesting_urls().items()
                        if v
                    },
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="Wayback Machine URL extractor")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--timeout", type=int, default=120, help="Request timeout")
    parser.add_argument("--limit", type=int, default=10000, help="Max URLs to fetch")
    parser.add_argument("--no-subdomains", action="store_true", help="Exclude subdomains")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    extractor = WaybackExtractor(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        timeout=args.timeout,
        limit=args.limit,
        include_subdomains=not args.no_subdomains,
        verbose=args.verbose,
    )

    result = await extractor.extract()
    paths = extractor.save_results(result)

    print(f"\n{'='*60}")
    print(f"Wayback Extraction Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Total URLs: {result.stats.get('total_urls', 0)}")
    print(f"Unique URLs: {result.stats.get('unique_urls', 0)}")
    print(f"URLs with Parameters: {result.stats.get('urls_with_params', 0)}")
    print(f"Unique Parameters: {result.stats.get('unique_parameters', 0)}")
    print(f"Subdomains Found: {result.stats.get('subdomains_found', 0)}")

    if result.stats.get('extension_breakdown'):
        print(f"\nTop Extensions:")
        for ext, count in list(result.stats['extension_breakdown'].items())[:10]:
            print(f"  {ext}: {count}")

    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""
Directory and file brute forcing module with ffuf wrapper and native support.

Usage:
    python directory_bruteforce.py --target https://example.com --output results/
"""

import argparse
import asyncio
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir, read_lines, parse_cookies

logger = setup_logging("directory_bruteforce")


@dataclass
class DiscoveredPath:
    """Represents a discovered directory or file."""

    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    redirect_url: str = ""
    title: str = ""
    interesting: bool = False
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "redirect_url": self.redirect_url,
            "title": self.title,
            "interesting": self.interesting,
            "reason": self.reason,
        }


class DirectoryBruteforcer:
    """
    Directory and file brute forcing with multiple methods.

    Features:
    - Native async HTTP brute forcing
    - ffuf wrapper for high-speed fuzzing
    - Gobuster wrapper support
    - Smart filtering (response size, status codes)
    - Extension fuzzing
    - Recursive discovery
    """

    # Interesting paths that warrant higher attention
    INTERESTING_PATHS = [
        "admin", "administrator", "login", "wp-admin", "phpmyadmin",
        "dashboard", "panel", "console", "manager", "portal",
        "backup", "backups", "bak", "old", "temp", "tmp",
        ".git", ".svn", ".env", ".htaccess", ".htpasswd",
        "config", "configuration", "settings", "conf",
        "api", "v1", "v2", "graphql", "swagger", "docs",
        "debug", "test", "dev", "development", "staging",
        "upload", "uploads", "files", "data", "db", "database",
        "private", "secret", "internal", "restricted",
    ]

    # File extensions to fuzz
    COMMON_EXTENSIONS = [
        "", ".php", ".asp", ".aspx", ".jsp", ".html", ".htm",
        ".js", ".json", ".xml", ".txt", ".bak", ".old", ".inc",
        ".config", ".conf", ".ini", ".log", ".sql", ".zip", ".tar.gz",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        wordlist: Optional[str] = None,
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 10,
        threads: int = 50,
        extensions: Optional[List[str]] = None,
        recursive: bool = False,
        recursion_depth: int = 2,
        filter_codes: Optional[List[int]] = None,
        filter_size: Optional[List[int]] = None,
        use_ffuf: bool = True,
        verbose: bool = False,
        auth_cookie: Optional[str] = None,
    ):
        self.target = normalize_url(target).rstrip('/')
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.wordlist = wordlist
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.extensions = extensions or [""]
        self.recursive = recursive
        self.recursion_depth = recursion_depth
        self.filter_codes = filter_codes or [404, 400, 500]
        self.filter_size = filter_size or []
        self.use_ffuf = use_ffuf and self._tool_exists("ffuf")
        self.verbose = verbose
        self.auth_cookie = auth_cookie

        self.discovered: Dict[str, DiscoveredPath] = {}
        self.dirs_to_scan: List[str] = ["/"]
        self.baseline_responses: Dict[str, int] = {}

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def bruteforce(self) -> ScanResult:
        """Run directory brute forcing and return results."""
        result = ScanResult(
            tool="directory_bruteforce",
            target=self.target,
            config={
                "wordlist": self.wordlist,
                "threads": self.threads,
                "extensions": self.extensions,
                "recursive": self.recursive,
                "use_ffuf": self.use_ffuf,
            },
        )

        logger.info(f"Starting directory brute force for: {self.target}")

        # Load wordlist
        wordlist_path = self.wordlist or self._get_default_wordlist()
        if not Path(wordlist_path).exists():
            result.add_error(f"Wordlist not found: {wordlist_path}")
            logger.error(f"Wordlist not found: {wordlist_path}")
            result.finalize()
            return result

        words = read_lines(wordlist_path)
        logger.info(f"Loaded {len(words)} words from wordlist")

        try:
            # Get baseline responses for filtering
            await self._calibrate_baseline()

            if self.use_ffuf:
                # Use ffuf for high-speed fuzzing
                await self._run_ffuf(wordlist_path)
            else:
                # Use native async bruteforcing
                await self._native_bruteforce(words)

            # Recursive scanning
            if self.recursive:
                await self._recursive_scan(words)

            # Calculate statistics
            result.stats = {
                "total_discovered": len(self.discovered),
                "status_200": sum(1 for p in self.discovered.values() if p.status_code == 200),
                "status_301_302": sum(1 for p in self.discovered.values() if p.status_code in [301, 302]),
                "status_403": sum(1 for p in self.discovered.values() if p.status_code == 403),
                "interesting_paths": sum(1 for p in self.discovered.values() if p.interesting),
                "words_tested": len(words),
            }

            # Add findings
            for path in self.discovered.values():
                if path.interesting:
                    severity = Severity.MEDIUM
                    if any(x in path.url.lower() for x in [".git", ".env", "backup", "config", "admin"]):
                        severity = Severity.HIGH
                else:
                    severity = Severity.LOW if path.status_code == 200 else Severity.INFO

                result.add_finding(Finding(
                    title=f"Directory/File Found: {path.url.split('/')[-1] or path.url}",
                    severity=severity,
                    description=f"Discovered path via brute force (Status: {path.status_code}, Size: {path.content_length})",
                    url=path.url,
                    metadata={
                        "status_code": path.status_code,
                        "content_length": path.content_length,
                        "content_type": path.content_type,
                        "redirect_url": path.redirect_url,
                        "interesting": path.interesting,
                        "reason": path.reason,
                    },
                ))

        except Exception as e:
            result.add_error(f"Brute force error: {e}")
            logger.error(f"Brute force error: {e}")

        result.finalize()
        return result

    async def _calibrate_baseline(self):
        """Get baseline response for filtering false positives."""
        logger.info("Calibrating baseline responses...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
            cookies=parse_cookies(self.auth_cookie) if self.auth_cookie else None,
        ) as client:
            # Test random non-existent paths
            test_paths = [
                f"/nonexistent_{i}_{asyncio.get_event_loop().time()}"
                for i in range(3)
            ]

            for path in test_paths:
                url = f"{self.target}{path}"
                response = await client.get(url)
                if response.status not in self.filter_codes:
                    self.baseline_responses[response.status] = len(response.body)

        logger.info(f"Baseline responses: {self.baseline_responses}")

    async def _run_ffuf(self, wordlist_path: str):
        """Run ffuf for high-speed fuzzing."""
        logger.info("Running ffuf...")

        output_file = self.output_dir / f"ffuf_{self.target_domain}.json"

        cmd = [
            "ffuf",
            "-u", f"{self.target}/FUZZ",
            "-w", wordlist_path,
            "-o", str(output_file),
            "-of", "json",
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-mc", "all",
            "-fc", ",".join(str(c) for c in self.filter_codes),
            "-ac",  # Auto-calibrate
            "-sf",  # Stop on spurious responses
        ]

        if self.proxy:
            cmd.extend(["-x", self.proxy])

        if self.auth_cookie:
            cmd.extend(["-b", self.auth_cookie])

        if self.extensions:
            ext_list = ",".join(e.lstrip('.') for e in self.extensions if e)
            if ext_list:
                cmd.extend(["-e", ext_list])

        if self.filter_size:
            cmd.extend(["-fs", ",".join(str(s) for s in self.filter_size)])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

            if output_file.exists():
                await self._parse_ffuf_output(output_file)

        except asyncio.TimeoutError:
            logger.warning("ffuf timed out")
        except Exception as e:
            logger.error(f"ffuf error: {e}")
            # Fall back to native
            logger.info("Falling back to native brute forcing...")
            words = read_lines(wordlist_path)
            await self._native_bruteforce(words)

    async def _parse_ffuf_output(self, output_file: Path):
        """Parse ffuf JSON output."""
        try:
            with open(output_file) as f:
                data = json.load(f)

            results = data.get("results", [])
            logger.info(f"ffuf found {len(results)} results")

            for item in results:
                url = item.get("url", "")
                status = item.get("status", 0)
                length = item.get("length", 0)
                content_type = item.get("content-type", "")
                redirect = item.get("redirectlocation", "")

                if url and status not in self.filter_codes:
                    path = DiscoveredPath(
                        url=url,
                        status_code=status,
                        content_length=length,
                        content_type=content_type,
                        redirect_url=redirect,
                        interesting=self._is_interesting(url),
                        reason=self._get_interesting_reason(url),
                    )
                    self.discovered[url] = path

        except Exception as e:
            logger.error(f"Error parsing ffuf output: {e}")

    async def _native_bruteforce(self, words: List[str]):
        """Native async brute forcing."""
        logger.info(f"Starting native brute force with {len(words)} words...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
            rate_limit=self.threads,
            cookies=parse_cookies(self.auth_cookie) if self.auth_cookie else None,
        ) as client:
            semaphore = asyncio.Semaphore(self.threads)
            progress = {"count": 0, "total": len(words) * len(self.extensions)}

            async def check_path(word: str, extension: str):
                async with semaphore:
                    path = f"/{word}{extension}"
                    url = f"{self.target}{path}"

                    try:
                        response = await client.get(url)

                        # Filter by status code
                        if response.status in self.filter_codes:
                            return

                        # Filter by baseline size
                        if response.status in self.baseline_responses:
                            baseline_size = self.baseline_responses[response.status]
                            if abs(len(response.body) - baseline_size) < 50:
                                return

                        # Filter by specified sizes
                        if self.filter_size and len(response.body) in self.filter_size:
                            return

                        # Extract title
                        title = ""
                        import re
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.body, re.IGNORECASE)
                        if title_match:
                            title = title_match.group(1).strip()[:100]

                        # Get redirect location
                        redirect_url = ""
                        if response.status in [301, 302, 303, 307, 308]:
                            redirect_url = response.headers.get("location", "")

                        discovered_path = DiscoveredPath(
                            url=url,
                            status_code=response.status,
                            content_length=len(response.body),
                            content_type=response.headers.get("content-type", ""),
                            redirect_url=redirect_url,
                            title=title,
                            interesting=self._is_interesting(path),
                            reason=self._get_interesting_reason(path),
                        )

                        self.discovered[url] = discovered_path

                        if self.verbose or discovered_path.interesting:
                            logger.info(f"Found: {url} [{response.status}] [{len(response.body)} bytes]")

                    except Exception as e:
                        logger.debug(f"Error checking {url}: {e}")

                    progress["count"] += 1
                    if progress["count"] % 500 == 0:
                        pct = (progress["count"] / progress["total"]) * 100
                        logger.info(f"Progress: {progress['count']}/{progress['total']} ({pct:.1f}%)")

            # Create tasks for all word+extension combinations
            tasks = []
            for word in words:
                for ext in self.extensions:
                    tasks.append(check_path(word, ext))

            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Native brute force complete: {len(self.discovered)} paths found")

    async def _recursive_scan(self, words: List[str]):
        """Recursively scan discovered directories."""
        if not self.recursive:
            return

        logger.info("Starting recursive directory scanning...")

        # Find directories to scan
        dirs_found = []
        for path in self.discovered.values():
            if path.status_code in [200, 301, 302, 403]:
                # Check if looks like a directory
                url_path = path.url.replace(self.target, "")
                if not url_path.split("/")[-1].count("."):
                    dirs_found.append(url_path.rstrip('/'))

        for depth in range(self.recursion_depth):
            if not dirs_found:
                break

            new_dirs = []
            logger.info(f"Recursion depth {depth + 1}: scanning {len(dirs_found)} directories")

            async with AsyncHTTPClient(
                timeout=self.timeout,
                proxy=self.proxy,
                max_retries=1,
                cookies=parse_cookies(self.auth_cookie) if self.auth_cookie else None,
            ) as client:
                semaphore = asyncio.Semaphore(self.threads)

                async def check_recursive(base_dir: str, word: str):
                    async with semaphore:
                        url = f"{self.target}{base_dir}/{word}"
                        if url in self.discovered:
                            return

                        try:
                            response = await client.get(url)
                            if response.status not in self.filter_codes:
                                path = DiscoveredPath(
                                    url=url,
                                    status_code=response.status,
                                    content_length=len(response.body),
                                    content_type=response.headers.get("content-type", ""),
                                    interesting=self._is_interesting(url),
                                    reason=self._get_interesting_reason(url),
                                )
                                self.discovered[url] = path

                                # Add to new dirs if looks like directory
                                if response.status in [200, 301, 302, 403] and "." not in word:
                                    new_dirs.append(f"{base_dir}/{word}")

                        except Exception:
                            pass

                tasks = []
                for dir_path in dirs_found[:50]:  # Limit directories per level
                    for word in words[:1000]:  # Limit words for recursive
                        tasks.append(check_recursive(dir_path, word))

                await asyncio.gather(*tasks, return_exceptions=True)

            dirs_found = new_dirs

    def _is_interesting(self, path: str) -> bool:
        """Check if path is interesting."""
        path_lower = path.lower()
        return any(interesting in path_lower for interesting in self.INTERESTING_PATHS)

    def _get_interesting_reason(self, path: str) -> str:
        """Get reason why path is interesting."""
        path_lower = path.lower()
        for interesting in self.INTERESTING_PATHS:
            if interesting in path_lower:
                return f"Contains '{interesting}'"
        return ""

    def _tool_exists(self, tool: str) -> bool:
        """Check if a tool is available in PATH."""
        try:
            subprocess.run(["which", tool], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _get_default_wordlist(self) -> str:
        """Get path to default wordlist."""
        # Check in config directory
        config_wordlist = Path(__file__).parent.parent / "config" / "wordlists" / "directories.txt"
        if config_wordlist.exists():
            return str(config_wordlist)

        # Check common locations
        common_paths = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ]
        for path in common_paths:
            if Path(path).exists():
                return path

        return str(config_wordlist)

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"directories_{self.target_domain}")

        # Save discovered paths list
        txt_path = self.output_dir / f"directories_{self.target_domain}.txt"
        with open(txt_path, "w") as f:
            for url in sorted(self.discovered.keys()):
                p = self.discovered[url]
                f.write(f"{url} [{p.status_code}] [{p.content_length}]\n")
        paths["txt"] = str(txt_path)

        # Save detailed JSON
        detailed_path = self.output_dir / f"directories_{self.target_domain}_detailed.json"
        with open(detailed_path, "w") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": timestamp_now(),
                    "total": len(self.discovered),
                    "paths": [p.to_dict() for p in self.discovered.values()],
                },
                f,
                indent=2,
            )
        paths["detailed"] = str(detailed_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(
        description="Directory and file brute forcing"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-w", "--wordlist", help="Wordlist file path")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-e", "--extensions", help="File extensions (comma-separated)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursive scanning")
    parser.add_argument("--recursion-depth", type=int, default=2, help="Recursion depth")
    parser.add_argument("--filter-codes", help="Status codes to filter (comma-separated)")
    parser.add_argument("--filter-size", help="Response sizes to filter (comma-separated)")
    parser.add_argument("--no-ffuf", action="store_true", help="Disable ffuf (use native)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    extensions = args.extensions.split(",") if args.extensions else None
    filter_codes = [int(c) for c in args.filter_codes.split(",")] if args.filter_codes else None
    filter_size = [int(s) for s in args.filter_size.split(",")] if args.filter_size else None

    bruteforcer = DirectoryBruteforcer(
        target=args.target,
        output_dir=args.output,
        wordlist=args.wordlist,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        extensions=extensions,
        recursive=args.recursive,
        recursion_depth=args.recursion_depth,
        filter_codes=filter_codes,
        filter_size=filter_size,
        use_ffuf=not args.no_ffuf,
        verbose=args.verbose,
    )

    result = await bruteforcer.bruteforce()
    paths = bruteforcer.save_results(result)

    print(f"\n{'='*60}")
    print(f"Directory Brute Force Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Paths Discovered: {len(bruteforcer.discovered)}")
    print(f"Interesting Paths: {result.stats.get('interesting_paths', 0)}")
    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    # Show interesting paths
    interesting = [p for p in bruteforcer.discovered.values() if p.interesting]
    if interesting:
        print(f"\n*** INTERESTING PATHS FOUND ***")
        for path in interesting[:10]:
            print(f"  [{path.status_code}] {path.url} - {path.reason}")


if __name__ == "__main__":
    asyncio.run(main())

"""
Async HTTP client with rate limiting, proxy support, and retry logic.
"""

import asyncio
import random
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from .utils import setup_logging, normalize_url, cookies_to_string, parse_cookies

logger = setup_logging("http_client")


@dataclass
class HTTPResponse:
    """Standardized HTTP response container."""

    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    error: Optional[str] = None
    redirects: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def length(self) -> int:
        return len(self.body)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "body_length": self.length,
            "elapsed": self.elapsed,
            "error": self.error,
            "redirects": self.redirects,
        }


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, rate: float, burst: int = 1):
        self.rate = rate  # requests per second
        self.burst = burst
        self.tokens = burst
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class AsyncHTTPClient:
    """
    Async HTTP client with advanced features for security testing.

    Features:
    - Async with aiohttp
    - Rate limiting (requests/sec)
    - Proxy support (Burp/Caido)
    - Header rotation
    - Cookie persistence
    - Retry with exponential backoff
    - Configurable timeout
    """

    DEFAULT_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: int = 30,
        rate_limit: float = 10.0,
        max_retries: int = 3,
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        rotate_user_agent: bool = True,
        user_agents: Optional[List[str]] = None,
    ):
        self.proxy = proxy
        self.timeout = ClientTimeout(total=timeout)
        self.rate_limiter = RateLimiter(rate_limit, burst=int(rate_limit))
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.rotate_user_agent = rotate_user_agent
        self.user_agents = user_agents or self.DEFAULT_USER_AGENTS

        self.default_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if headers:
            self.default_headers.update(headers)

        self.cookies: Dict[str, str] = cookies or {}
        self._session: Optional[ClientSession] = None
        self._request_count = 0

    def _get_user_agent(self) -> str:
        """Get user agent (random if rotation enabled)."""
        if self.rotate_user_agent:
            return random.choice(self.user_agents)
        return self.user_agents[0]

    def _get_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Build request headers."""
        headers = self.default_headers.copy()
        headers["User-Agent"] = self._get_user_agent()

        if self.cookies:
            headers["Cookie"] = cookies_to_string(self.cookies)

        if custom_headers:
            headers.update(custom_headers)

        return headers

    async def _create_session(self) -> ClientSession:
        """Create aiohttp session with configured settings."""
        ssl_context = None
        if not self.verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        connector = TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=20,
        )

        return ClientSession(
            connector=connector,
            timeout=self.timeout,
            trust_env=True,
        )

    async def __aenter__(self):
        self._session = await self._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()
            self._session = None

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, Dict, bytes]] = None,
        json: Optional[Dict] = None,
        allow_redirects: Optional[bool] = None,
    ) -> HTTPResponse:
        """
        Make an HTTP request with retry logic and rate limiting.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Custom headers
            params: Query parameters
            data: Request body (form data or raw)
            json: JSON body
            allow_redirects: Override redirect behavior

        Returns:
            HTTPResponse object
        """
        url = normalize_url(url)
        request_headers = self._get_headers(headers)

        if allow_redirects is None:
            allow_redirects = self.follow_redirects

        last_error = None
        redirects = []

        for attempt in range(self.max_retries):
            try:
                # Rate limiting
                await self.rate_limiter.acquire()

                start_time = time.monotonic()

                # Create session if needed
                if not self._session:
                    self._session = await self._create_session()

                async with self._session.request(
                    method=method.upper(),
                    url=url,
                    headers=request_headers,
                    params=params,
                    data=data,
                    json=json,
                    proxy=self.proxy,
                    allow_redirects=allow_redirects,
                    max_redirects=self.max_redirects,
                ) as response:
                    elapsed = time.monotonic() - start_time
                    body = await response.text()

                    # Track redirects
                    if response.history:
                        redirects = [str(r.url) for r in response.history]

                    # Update cookies from response
                    for cookie in response.cookies.values():
                        self.cookies[cookie.key] = cookie.value

                    self._request_count += 1

                    return HTTPResponse(
                        url=str(response.url),
                        status=response.status,
                        headers=dict(response.headers),
                        body=body,
                        elapsed=elapsed,
                        redirects=redirects,
                    )

            except asyncio.TimeoutError:
                last_error = "Request timeout"
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.max_retries}: {url}")

            except aiohttp.ClientError as e:
                last_error = str(e)
                logger.warning(f"Client error on attempt {attempt + 1}/{self.max_retries}: {e}")

            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected error on attempt {attempt + 1}/{self.max_retries}: {e}")

            # Exponential backoff
            if attempt < self.max_retries - 1:
                wait_time = (2**attempt) + random.uniform(0, 1)
                await asyncio.sleep(wait_time)

        return HTTPResponse(
            url=url,
            status=0,
            headers={},
            body="",
            elapsed=0,
            error=last_error,
        )

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        """GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        """POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HTTPResponse:
        """PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        """DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse:
        """HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> HTTPResponse:
        """OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> HTTPResponse:
        """PATCH request."""
        return await self.request("PATCH", url, **kwargs)

    async def batch_requests(
        self,
        requests: List[Dict[str, Any]],
        concurrency: int = 10,
        callback: Optional[Callable[[HTTPResponse], None]] = None,
    ) -> List[HTTPResponse]:
        """
        Execute multiple requests with controlled concurrency.

        Args:
            requests: List of request dicts with keys: method, url, headers, data, etc.
            concurrency: Max concurrent requests
            callback: Optional callback for each response

        Returns:
            List of HTTPResponse objects
        """
        semaphore = asyncio.Semaphore(concurrency)
        results = []

        async def bounded_request(req: Dict) -> HTTPResponse:
            async with semaphore:
                method = req.pop("method", "GET")
                url = req.pop("url")
                response = await self.request(method, url, **req)

                if callback:
                    callback(response)

                return response

        tasks = [bounded_request(req.copy()) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error responses
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(
                    HTTPResponse(
                        url=requests[i].get("url", "unknown"),
                        status=0,
                        headers={},
                        body="",
                        elapsed=0,
                        error=str(result),
                    )
                )
            else:
                final_results.append(result)

        return final_results

    def update_cookies(self, cookies: Dict[str, str]):
        """Update stored cookies."""
        self.cookies.update(cookies)

    def set_cookie(self, name: str, value: str):
        """Set a single cookie."""
        self.cookies[name] = value

    def clear_cookies(self):
        """Clear all cookies."""
        self.cookies.clear()

    def update_headers(self, headers: Dict[str, str]):
        """Update default headers."""
        self.default_headers.update(headers)

    def set_header(self, name: str, value: str):
        """Set a single header."""
        self.default_headers[name] = value

    @property
    def request_count(self) -> int:
        """Get total request count."""
        return self._request_count


async def fetch_url(url: str, **kwargs) -> HTTPResponse:
    """Convenience function for single URL fetch."""
    async with AsyncHTTPClient(**kwargs) as client:
        return await client.get(url)


async def fetch_urls(urls: List[str], concurrency: int = 10, **kwargs) -> List[HTTPResponse]:
    """Convenience function for fetching multiple URLs."""
    async with AsyncHTTPClient(**kwargs) as client:
        requests = [{"method": "GET", "url": url} for url in urls]
        return await client.batch_requests(requests, concurrency=concurrency)

"""
Shared utility functions for SHADOW framework.
"""

import base64
import hashlib
import html
import logging
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import yaml


def setup_logging(
    name: str = "shadow",
    level: str = "INFO",
    log_file: Optional[str] = None,
    verbose: bool = False,
) -> logging.Logger:
    """Configure and return a logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else getattr(logging, level.upper()))

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path, "r") as f:
        config = yaml.safe_load(f)

    return config or {}


def normalize_url(url: str, default_scheme: str = "https") -> str:
    """Normalize URL with scheme and trailing slash handling."""
    url = url.strip()

    if not url:
        return ""

    # Add scheme if missing
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = f"{default_scheme}://{url}"

    parsed = urlparse(url)

    # Reconstruct with normalized components
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = parsed.query
    fragment = parsed.fragment

    # Remove default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    normalized = f"{scheme}://{netloc}{path}"
    if query:
        normalized += f"?{query}"
    if fragment:
        normalized += f"#{fragment}"

    return normalized


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    if not url:
        return ""

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = f"https://{url}"

    parsed = urlparse(url)
    return parsed.netloc.split(":")[0].lower()


def generate_id(prefix: str = "") -> str:
    """Generate a unique identifier."""
    unique = uuid.uuid4().hex[:12]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    if prefix:
        return f"{prefix}_{timestamp}_{unique}"
    return f"{timestamp}_{unique}"


def safe_filename(name: str, max_length: int = 200) -> str:
    """Convert string to safe filename."""
    # Replace unsafe characters
    safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    safe = re.sub(r"_+", "_", safe)
    safe = safe.strip("_. ")

    if len(safe) > max_length:
        safe = safe[:max_length]

    return safe or "unnamed"


def parse_cookies(cookie_string: str) -> Dict[str, str]:
    """Parse cookie string into dictionary."""
    cookies = {}
    if not cookie_string:
        return cookies

    for pair in cookie_string.split(";"):
        pair = pair.strip()
        if "=" in pair:
            key, value = pair.split("=", 1)
            cookies[key.strip()] = value.strip()

    return cookies


def cookies_to_string(cookies: Dict[str, str]) -> str:
    """Convert cookie dictionary to string."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def encode_payload(payload: str, encoding: str = "none") -> str:
    """Encode payload with specified encoding."""
    encodings = {
        "none": lambda p: p,
        "url": lambda p: quote(p, safe=""),
        "double_url": lambda p: quote(quote(p, safe=""), safe=""),
        "base64": lambda p: base64.b64encode(p.encode()).decode(),
        "html": lambda p: html.escape(p),
        "unicode": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
        "hex": lambda p: "".join(f"%{ord(c):02x}" for c in p),
    }

    encoder = encodings.get(encoding.lower())
    if not encoder:
        raise ValueError(f"Unknown encoding: {encoding}")

    return encoder(payload)


def decode_payload(payload: str, encoding: str = "none") -> str:
    """Decode payload with specified encoding."""
    decodings = {
        "none": lambda p: p,
        "url": lambda p: unquote(p),
        "double_url": lambda p: unquote(unquote(p)),
        "base64": lambda p: base64.b64decode(p).decode(),
        "html": lambda p: html.unescape(p),
    }

    decoder = decodings.get(encoding.lower())
    if not decoder:
        raise ValueError(f"Unknown encoding: {encoding}")

    return decoder(payload)


def hash_string(data: str, algorithm: str = "md5") -> str:
    """Hash a string using specified algorithm."""
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }

    hasher = algorithms.get(algorithm.lower())
    if not hasher:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    return hasher(data.encode()).hexdigest()


def extract_params(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def build_url(base_url: str, params: Dict[str, Any]) -> str:
    """Build URL with query parameters."""
    parsed = urlparse(base_url)
    query = urlencode(params, doseq=True)

    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"


def is_ip_address(host: str) -> bool:
    """Check if host is an IP address."""
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"

    return bool(re.match(ipv4_pattern, host) or re.match(ipv6_pattern, host))


def get_file_extension(url: str) -> str:
    """Extract file extension from URL."""
    parsed = urlparse(url)
    path = parsed.path
    if "." in path:
        return path.rsplit(".", 1)[-1].lower()
    return ""


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split list into chunks of specified size."""
    return [lst[i : i + chunk_size] for i in range(0, len(lst), chunk_size)]


def merge_dicts(base: Dict, override: Dict) -> Dict:
    """Deep merge two dictionaries."""
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value

    return result


def timestamp_now() -> str:
    """Return current timestamp in ISO format."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dir(path: str) -> Path:
    """Ensure directory exists, create if not."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def read_lines(file_path: str, skip_empty: bool = True, skip_comments: bool = True) -> List[str]:
    """Read lines from file with optional filtering."""
    path = Path(file_path)
    if not path.exists():
        return []

    lines = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if skip_empty and not line:
                continue
            if skip_comments and line.startswith("#"):
                continue
            lines.append(line)

    return lines


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0

    from collections import Counter
    import math

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def looks_like_secret(value: str) -> bool:
    """Heuristic check if a string looks like a secret/key."""
    if not value or len(value) < 8:
        return False

    # High entropy check
    if calculate_entropy(value) > 4.0:
        return True

    # Pattern matching for common secret formats
    secret_patterns = [
        r"^[A-Za-z0-9+/]{20,}={0,2}$",  # Base64
        r"^[a-f0-9]{32,}$",  # Hex hash
        r"^[A-Za-z0-9_-]{20,}$",  # API key style
        r"^sk_[a-zA-Z0-9]{20,}$",  # Stripe-style
        r"^AKIA[0-9A-Z]{16}$",  # AWS access key
    ]

    for pattern in secret_patterns:
        if re.match(pattern, value):
            return True

    return False

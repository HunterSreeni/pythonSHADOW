"""
SHADOW Bug Bounty Automation Framework - Core Module
"""

from .http_client import AsyncHTTPClient
from .result_manager import ResultManager
from .payload_manager import PayloadManager
from .response_analyzer import ResponseAnalyzer
from .session_manager import SessionManager
from .utils import (
    setup_logging,
    load_config,
    normalize_url,
    extract_domain,
    generate_id,
    safe_filename,
    parse_cookies,
    encode_payload,
)

__version__ = "1.0.0"
__all__ = [
    "AsyncHTTPClient",
    "ResultManager",
    "PayloadManager",
    "ResponseAnalyzer",
    "SessionManager",
    "setup_logging",
    "load_config",
    "normalize_url",
    "extract_domain",
    "generate_id",
    "safe_filename",
    "parse_cookies",
    "encode_payload",
]

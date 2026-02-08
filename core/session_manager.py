"""
Session manager for cookie/authentication handling and session persistence.
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .utils import setup_logging, ensure_dir, parse_cookies, cookies_to_string, timestamp_now

logger = setup_logging("session_manager")


@dataclass
class Session:
    """Represents an HTTP session with cookies and authentication."""

    name: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_type: Optional[str] = None  # basic, bearer, api_key, custom
    auth_value: Optional[str] = None
    created_at: str = field(default_factory=timestamp_now)
    last_used: str = field(default_factory=timestamp_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "cookies": self.cookies,
            "headers": self.headers,
            "auth_type": self.auth_type,
            "auth_value": self.auth_value,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        return cls(**data)

    def get_auth_header(self) -> Optional[Tuple[str, str]]:
        """Get authentication header tuple."""
        if not self.auth_type or not self.auth_value:
            return None

        if self.auth_type == "bearer":
            return ("Authorization", f"Bearer {self.auth_value}")
        elif self.auth_type == "basic":
            return ("Authorization", f"Basic {self.auth_value}")
        elif self.auth_type == "api_key":
            return ("X-API-Key", self.auth_value)
        elif self.auth_type == "custom":
            # auth_value should be "header_name:value"
            if ":" in self.auth_value:
                name, value = self.auth_value.split(":", 1)
                return (name, value)
        return None

    def update_cookie(self, name: str, value: str):
        """Update a single cookie."""
        self.cookies[name] = value
        self.last_used = timestamp_now()

    def update_cookies_from_string(self, cookie_string: str):
        """Update cookies from a cookie header string."""
        parsed = parse_cookies(cookie_string)
        self.cookies.update(parsed)
        self.last_used = timestamp_now()


class SessionManager:
    """
    Manages HTTP sessions with persistence and multi-session support.

    Features:
    - Multiple named sessions
    - Cookie persistence
    - Authentication handling (Bearer, Basic, API Key)
    - Session file storage
    - Cookie extraction from headers
    """

    def __init__(self, storage_dir: Optional[str] = None):
        """
        Initialize SessionManager.

        Args:
            storage_dir: Directory for session file storage
        """
        self.storage_dir = Path(storage_dir) if storage_dir else None
        if self.storage_dir:
            ensure_dir(self.storage_dir)

        self._sessions: Dict[str, Session] = {}
        self._active_session: Optional[str] = None

    def create_session(
        self,
        name: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth_type: Optional[str] = None,
        auth_value: Optional[str] = None,
    ) -> Session:
        """Create a new session."""
        session = Session(
            name=name,
            cookies=cookies or {},
            headers=headers or {},
            auth_type=auth_type,
            auth_value=auth_value,
        )
        self._sessions[name] = session
        logger.info(f"Created session: {name}")
        return session

    def get_session(self, name: str) -> Optional[Session]:
        """Get a session by name."""
        return self._sessions.get(name)

    def get_active_session(self) -> Optional[Session]:
        """Get the currently active session."""
        if self._active_session:
            return self._sessions.get(self._active_session)
        return None

    def set_active_session(self, name: str) -> bool:
        """Set the active session."""
        if name in self._sessions:
            self._active_session = name
            logger.info(f"Active session set to: {name}")
            return True
        return False

    def list_sessions(self) -> List[str]:
        """List all session names."""
        return list(self._sessions.keys())

    def delete_session(self, name: str) -> bool:
        """Delete a session."""
        if name in self._sessions:
            del self._sessions[name]
            if self._active_session == name:
                self._active_session = None
            logger.info(f"Deleted session: {name}")
            return True
        return False

    def get_headers_for_request(
        self,
        session_name: Optional[str] = None,
        include_cookies: bool = True,
    ) -> Dict[str, str]:
        """
        Get headers for making a request with session context.

        Args:
            session_name: Session to use (default: active session)
            include_cookies: Include cookies in headers

        Returns:
            Headers dict
        """
        name = session_name or self._active_session
        if not name or name not in self._sessions:
            return {}

        session = self._sessions[name]
        headers = session.headers.copy()

        # Add authentication header
        auth_header = session.get_auth_header()
        if auth_header:
            headers[auth_header[0]] = auth_header[1]

        # Add cookies
        if include_cookies and session.cookies:
            headers["Cookie"] = cookies_to_string(session.cookies)

        session.last_used = timestamp_now()
        return headers

    def update_from_response(
        self,
        headers: Dict[str, str],
        session_name: Optional[str] = None,
    ):
        """
        Update session cookies from response headers.

        Args:
            headers: Response headers
            session_name: Session to update (default: active session)
        """
        name = session_name or self._active_session
        if not name or name not in self._sessions:
            return

        session = self._sessions[name]

        # Extract Set-Cookie headers
        for header_name, header_value in headers.items():
            if header_name.lower() == "set-cookie":
                self._parse_set_cookie(session, header_value)

    def _parse_set_cookie(self, session: Session, set_cookie: str):
        """Parse Set-Cookie header and update session."""
        # Extract cookie name=value (first part before ;)
        parts = set_cookie.split(";")
        if parts:
            cookie_part = parts[0].strip()
            if "=" in cookie_part:
                name, value = cookie_part.split("=", 1)
                session.update_cookie(name.strip(), value.strip())

    def save_sessions(self, filename: str = "sessions.json") -> str:
        """
        Save all sessions to a file.

        Returns path to saved file.
        """
        if not self.storage_dir:
            raise ValueError("No storage directory configured")

        file_path = self.storage_dir / filename
        data = {
            "active_session": self._active_session,
            "sessions": {
                name: session.to_dict()
                for name, session in self._sessions.items()
            },
        }

        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved sessions to: {file_path}")
        return str(file_path)

    def load_sessions(self, filename: str = "sessions.json") -> int:
        """
        Load sessions from a file.

        Returns number of sessions loaded.
        """
        if not self.storage_dir:
            raise ValueError("No storage directory configured")

        file_path = self.storage_dir / filename
        if not file_path.exists():
            logger.warning(f"Session file not found: {file_path}")
            return 0

        with open(file_path, "r") as f:
            data = json.load(f)

        self._active_session = data.get("active_session")
        self._sessions = {
            name: Session.from_dict(session_data)
            for name, session_data in data.get("sessions", {}).items()
        }

        logger.info(f"Loaded {len(self._sessions)} sessions from: {file_path}")
        return len(self._sessions)

    def import_from_burp(self, cookie_string: str, session_name: str = "burp") -> Session:
        """
        Import session from Burp Suite cookie string.

        Args:
            cookie_string: Cookie header value from Burp
            session_name: Name for the imported session

        Returns:
            Created session
        """
        cookies = parse_cookies(cookie_string)
        return self.create_session(name=session_name, cookies=cookies)

    def import_from_browser(
        self,
        cookies: List[Dict[str, str]],
        session_name: str = "browser",
    ) -> Session:
        """
        Import session from browser cookie export (JSON format).

        Args:
            cookies: List of cookie dicts with 'name' and 'value' keys
            session_name: Name for the imported session

        Returns:
            Created session
        """
        cookie_dict = {c["name"]: c["value"] for c in cookies if "name" in c and "value" in c}
        return self.create_session(name=session_name, cookies=cookie_dict)

    def set_bearer_token(
        self,
        token: str,
        session_name: Optional[str] = None,
    ) -> bool:
        """Set bearer token authentication for a session."""
        name = session_name or self._active_session
        if not name or name not in self._sessions:
            return False

        session = self._sessions[name]
        session.auth_type = "bearer"
        session.auth_value = token
        return True

    def set_basic_auth(
        self,
        username: str,
        password: str,
        session_name: Optional[str] = None,
    ) -> bool:
        """Set basic authentication for a session."""
        import base64

        name = session_name or self._active_session
        if not name or name not in self._sessions:
            return False

        session = self._sessions[name]
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        session.auth_type = "basic"
        session.auth_value = credentials
        return True

    def set_api_key(
        self,
        api_key: str,
        session_name: Optional[str] = None,
    ) -> bool:
        """Set API key authentication for a session."""
        name = session_name or self._active_session
        if not name or name not in self._sessions:
            return False

        session = self._sessions[name]
        session.auth_type = "api_key"
        session.auth_value = api_key
        return True

    def set_custom_auth(
        self,
        header_name: str,
        header_value: str,
        session_name: Optional[str] = None,
    ) -> bool:
        """Set custom authentication header for a session."""
        name = session_name or self._active_session
        if not name or name not in self._sessions:
            return False

        session = self._sessions[name]
        session.auth_type = "custom"
        session.auth_value = f"{header_name}:{header_value}"
        return True

    def clone_session(self, source_name: str, new_name: str) -> Optional[Session]:
        """Clone an existing session with a new name."""
        source = self._sessions.get(source_name)
        if not source:
            return None

        return self.create_session(
            name=new_name,
            cookies=source.cookies.copy(),
            headers=source.headers.copy(),
            auth_type=source.auth_type,
            auth_value=source.auth_value,
        )

    def extract_csrf_token(
        self,
        body: str,
        patterns: Optional[List[str]] = None,
    ) -> Optional[str]:
        """
        Extract CSRF token from response body.

        Args:
            body: Response body HTML
            patterns: Custom regex patterns to search

        Returns:
            Extracted token or None
        """
        default_patterns = [
            r'name=["\']?csrf[_-]?token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?_token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?authenticity_token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'csrf[_-]?token["\']?\s*:\s*["\']?([^"\'>\s,}]+)',
            r'<meta\s+name=["\']?csrf-token["\']?\s+content=["\']?([^"\']+)',
            r'data-csrf=["\']?([^"\'>\s]+)',
            r'X-CSRF-TOKEN["\']?\s*:\s*["\']?([^"\'>\s,}]+)',
        ]

        patterns = patterns or default_patterns

        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def update_csrf_token(
        self,
        token: str,
        header_name: str = "X-CSRF-Token",
        session_name: Optional[str] = None,
    ) -> bool:
        """Update CSRF token in session headers."""
        name = session_name or self._active_session
        if not name or name not in self._sessions:
            return False

        session = self._sessions[name]
        session.headers[header_name] = token
        return True

    def get_session_info(self, session_name: Optional[str] = None) -> Dict[str, Any]:
        """Get summary info about a session."""
        name = session_name or self._active_session
        if not name or name not in self._sessions:
            return {}

        session = self._sessions[name]
        return {
            "name": session.name,
            "cookie_count": len(session.cookies),
            "header_count": len(session.headers),
            "auth_type": session.auth_type,
            "has_auth": session.auth_value is not None,
            "created_at": session.created_at,
            "last_used": session.last_used,
        }

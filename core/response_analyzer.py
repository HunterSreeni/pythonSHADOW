"""
Response analyzer for diff detection, anomaly scoring, and vulnerability indicators.
"""

import hashlib
import re
import statistics
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

from .http_client import HTTPResponse
from .utils import setup_logging, calculate_entropy

logger = setup_logging("response_analyzer")


@dataclass
class ResponseFingerprint:
    """Fingerprint of an HTTP response for comparison."""

    status: int
    length: int
    word_count: int
    line_count: int
    content_hash: str
    headers_hash: str
    elapsed: float
    error_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "length": self.length,
            "word_count": self.word_count,
            "line_count": self.line_count,
            "content_hash": self.content_hash,
            "headers_hash": self.headers_hash,
            "elapsed": self.elapsed,
            "error_indicators": self.error_indicators,
        }


@dataclass
class AnalysisResult:
    """Result of response analysis."""

    is_anomaly: bool
    confidence: float  # 0.0 to 1.0
    reasons: List[str] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_anomaly": self.is_anomaly,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "indicators": self.indicators,
            "score": self.score,
        }


class ResponseAnalyzer:
    """
    Analyzes HTTP responses for vulnerability indicators and anomalies.

    Features:
    - Response fingerprinting
    - Diff detection between responses
    - Anomaly scoring
    - Error pattern detection
    - Reflection detection
    - Time-based analysis
    """

    # SQL error patterns by database
    SQL_ERRORS = {
        "mysql": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark after the character string",
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
        ],
        "mssql": [
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"\bSQL Server\b.*Driver",
            r"Warning.*mssql_",
            r"Msg \d+, Level \d+, State \d+",
            r"Unclosed quotation mark after the character string",
            r"Microsoft SQL Native Client error",
        ],
        "oracle": [
            r"\bORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            r"oracle\.jdbc\.driver",
            r"OracleException",
        ],
        "sqlite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLite error \d+:",
        ],
        "generic": [
            r"SQL syntax",
            r"syntax error",
            r"mysql_fetch",
            r"ORA-\d+",
            r"SQLite",
            r"PostgreSQL",
            r"ODBC Driver",
            r"DB2 SQL",
            r"quoted string not properly terminated",
            r"unterminated quoted string",
            r"You have an error in your SQL syntax",
        ],
    }

    # XSS reflection indicators
    XSS_INDICATORS = [
        r"<script[^>]*>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"onmouseover\s*=",
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
        r"<iframe[^>]+src",
        r"document\.cookie",
        r"document\.location",
        r"window\.location",
        r"eval\s*\(",
        r"alert\s*\(",
        r"confirm\s*\(",
        r"prompt\s*\(",
    ]

    # SSTI indicators
    SSTI_INDICATORS = [
        r"49",  # 7*7
        r"7777777",  # 7*'7'
        r"\{\{.*\}\}",
        r"\$\{.*\}",
        r"<%.*%>",
        r"#\{.*\}",
        r"Traceback.*most recent call",
        r"TemplateSyntaxError",
        r"UndefinedError",
    ]

    # Path traversal indicators
    PATH_TRAVERSAL_INDICATORS = [
        r"root:.*:0:0:",  # /etc/passwd
        r"\[extensions\]",  # win.ini
        r"boot loader",
        r"for 16-bit app support",
        r"\\windows\\",
        r"/etc/shadow",
        r"www-data",
        r"daemon:.*:1:",
    ]

    # Command injection indicators
    CMD_INJECTION_INDICATORS = [
        r"uid=\d+.*gid=\d+",
        r"root:x:0:0",
        r"Linux.*GNU",
        r"Windows.*Microsoft",
        r"total \d+",  # ls output
        r"Directory of",  # dir output
        r"Volume Serial Number",
    ]

    # Information disclosure patterns
    INFO_DISCLOSURE_PATTERNS = [
        r"(?i)password\s*[:=]\s*['\"]?[\w@#$%^&*]+",
        r"(?i)api[_-]?key\s*[:=]\s*['\"]?[\w-]+",
        r"(?i)secret\s*[:=]\s*['\"]?[\w-]+",
        r"(?i)token\s*[:=]\s*['\"]?[\w-]+",
        r"(?i)aws[_-]?access[_-]?key[_-]?id",
        r"(?i)aws[_-]?secret[_-]?access[_-]?key",
        r"AKIA[0-9A-Z]{16}",  # AWS access key
        r"[a-zA-Z0-9+/]{40}",  # Base64 secrets
        r"-----BEGIN.*PRIVATE KEY-----",
        r"-----BEGIN CERTIFICATE-----",
        r"(?i)jdbc:.*://",
        r"(?i)mongodb://.*@",
        r"(?i)mysql://.*@",
        r"(?i)postgresql://.*@",
    ]

    def __init__(
        self,
        baseline_response: Optional[HTTPResponse] = None,
        time_threshold: float = 5.0,
        length_threshold: float = 0.1,
        similarity_threshold: float = 0.95,
    ):
        """
        Initialize ResponseAnalyzer.

        Args:
            baseline_response: Baseline response for comparison
            time_threshold: Threshold for time-based detection (seconds)
            length_threshold: Percentage difference threshold for length
            similarity_threshold: Threshold for content similarity (0-1)
        """
        self.baseline = baseline_response
        self.baseline_fingerprint: Optional[ResponseFingerprint] = None
        self.time_threshold = time_threshold
        self.length_threshold = length_threshold
        self.similarity_threshold = similarity_threshold
        self._response_history: List[ResponseFingerprint] = []

        if baseline_response:
            self.baseline_fingerprint = self.fingerprint(baseline_response)

    def fingerprint(self, response: HTTPResponse) -> ResponseFingerprint:
        """Create a fingerprint of an HTTP response."""
        body = response.body or ""

        content_hash = hashlib.md5(body.encode()).hexdigest()
        headers_hash = hashlib.md5(
            str(sorted(response.headers.items())).encode()
        ).hexdigest()

        # Detect error indicators in response
        error_indicators = []
        for db, patterns in self.SQL_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    error_indicators.append(f"sql_error:{db}")
                    break

        return ResponseFingerprint(
            status=response.status,
            length=len(body),
            word_count=len(body.split()),
            line_count=body.count("\n") + 1,
            content_hash=content_hash,
            headers_hash=headers_hash,
            elapsed=response.elapsed,
            error_indicators=error_indicators,
        )

    def set_baseline(self, response: HTTPResponse):
        """Set the baseline response for comparison."""
        self.baseline = response
        self.baseline_fingerprint = self.fingerprint(response)

    def compare(
        self,
        response: HTTPResponse,
        baseline: Optional[HTTPResponse] = None,
    ) -> Dict[str, Any]:
        """
        Compare a response against baseline.

        Returns detailed comparison metrics.
        """
        if baseline:
            baseline_fp = self.fingerprint(baseline)
        elif self.baseline_fingerprint:
            baseline_fp = self.baseline_fingerprint
        else:
            raise ValueError("No baseline response available")

        current_fp = self.fingerprint(response)

        # Calculate differences
        status_diff = current_fp.status != baseline_fp.status
        length_diff = abs(current_fp.length - baseline_fp.length)
        length_ratio = (
            length_diff / baseline_fp.length if baseline_fp.length > 0 else 0
        )
        time_diff = current_fp.elapsed - baseline_fp.elapsed
        content_same = current_fp.content_hash == baseline_fp.content_hash

        # Calculate content similarity
        if not content_same and self.baseline and response.body:
            similarity = self._calculate_similarity(
                self.baseline.body, response.body
            )
        else:
            similarity = 1.0 if content_same else 0.0

        return {
            "status_different": status_diff,
            "length_difference": length_diff,
            "length_ratio": length_ratio,
            "time_difference": time_diff,
            "content_identical": content_same,
            "content_similarity": similarity,
            "word_count_diff": abs(current_fp.word_count - baseline_fp.word_count),
            "line_count_diff": abs(current_fp.line_count - baseline_fp.line_count),
            "new_error_indicators": [
                i for i in current_fp.error_indicators
                if i not in baseline_fp.error_indicators
            ],
            "baseline": baseline_fp.to_dict(),
            "current": current_fp.to_dict(),
        }

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate text similarity ratio."""
        return SequenceMatcher(None, text1, text2).ratio()

    def analyze(self, response: HTTPResponse, payload: Optional[str] = None) -> AnalysisResult:
        """
        Comprehensive analysis of a response for vulnerabilities.

        Args:
            response: HTTP response to analyze
            payload: Payload that was sent (for reflection detection)

        Returns:
            AnalysisResult with findings
        """
        reasons = []
        indicators = {}
        score = 0.0

        body = response.body or ""
        body_lower = body.lower()

        # 1. SQL Error Detection
        sql_errors = self.detect_sql_errors(body)
        if sql_errors:
            reasons.append(f"SQL errors detected: {', '.join(sql_errors)}")
            indicators["sql_errors"] = sql_errors
            score += 0.8

        # 2. Reflection Detection
        if payload:
            reflection = self.detect_reflection(body, payload)
            if reflection["reflected"]:
                reasons.append(f"Payload reflected in response")
                indicators["reflection"] = reflection
                score += 0.6

        # 3. Time-based Analysis
        if self.baseline_fingerprint:
            time_diff = response.elapsed - self.baseline_fingerprint.elapsed
            if time_diff >= self.time_threshold:
                reasons.append(f"Significant time delay: {time_diff:.2f}s")
                indicators["time_delay"] = time_diff
                score += 0.7

        # 4. Status Code Analysis
        if response.status >= 500:
            reasons.append(f"Server error: {response.status}")
            indicators["server_error"] = response.status
            score += 0.5
        elif response.status in [401, 403]:
            indicators["access_control"] = response.status

        # 5. XSS Indicators
        xss_found = self.detect_xss_indicators(body)
        if xss_found:
            reasons.append(f"XSS indicators found")
            indicators["xss_indicators"] = xss_found
            score += 0.5

        # 6. SSTI Indicators
        ssti_found = self.detect_ssti_indicators(body)
        if ssti_found:
            reasons.append(f"SSTI indicators found")
            indicators["ssti_indicators"] = ssti_found
            score += 0.7

        # 7. Path Traversal Indicators
        path_traversal = self.detect_path_traversal(body)
        if path_traversal:
            reasons.append(f"Path traversal indicators found")
            indicators["path_traversal"] = path_traversal
            score += 0.9

        # 8. Command Injection Indicators
        cmd_injection = self.detect_cmd_injection(body)
        if cmd_injection:
            reasons.append(f"Command injection indicators found")
            indicators["cmd_injection"] = cmd_injection
            score += 0.9

        # 9. Information Disclosure
        info_disclosure = self.detect_info_disclosure(body)
        if info_disclosure:
            reasons.append(f"Potential information disclosure")
            indicators["info_disclosure"] = info_disclosure
            score += 0.6

        # 10. Length-based Analysis (if baseline exists)
        if self.baseline_fingerprint:
            comparison = self.compare(response)
            if comparison["length_ratio"] > self.length_threshold:
                reasons.append(f"Significant length change: {comparison['length_ratio']:.1%}")
                indicators["length_change"] = comparison["length_ratio"]
                score += 0.3

        # Determine if this is an anomaly
        is_anomaly = score >= 0.5 or len(reasons) >= 2
        confidence = min(score, 1.0)

        return AnalysisResult(
            is_anomaly=is_anomaly,
            confidence=confidence,
            reasons=reasons,
            indicators=indicators,
            score=score,
        )

    def detect_sql_errors(self, body: str) -> List[str]:
        """Detect SQL error messages in response body."""
        errors = []

        for db, patterns in self.SQL_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    errors.append(db)
                    break

        return list(set(errors))

    def detect_reflection(self, body: str, payload: str) -> Dict[str, Any]:
        """Detect if and how a payload is reflected in the response."""
        result = {
            "reflected": False,
            "exact_match": False,
            "encoded_match": False,
            "partial_match": False,
            "positions": [],
        }

        if not payload:
            return result

        # Exact match
        if payload in body:
            result["reflected"] = True
            result["exact_match"] = True
            result["positions"] = [m.start() for m in re.finditer(re.escape(payload), body)]

        # URL encoded match
        from urllib.parse import quote
        encoded_payload = quote(payload, safe="")
        if encoded_payload in body:
            result["reflected"] = True
            result["encoded_match"] = True

        # HTML encoded match
        import html
        html_encoded = html.escape(payload)
        if html_encoded in body and html_encoded != payload:
            result["reflected"] = True
            result["encoded_match"] = True

        # Partial match (at least half the payload)
        if not result["reflected"] and len(payload) > 4:
            half_len = len(payload) // 2
            for i in range(len(payload) - half_len + 1):
                substring = payload[i:i + half_len]
                if substring in body:
                    result["reflected"] = True
                    result["partial_match"] = True
                    break

        return result

    def detect_xss_indicators(self, body: str) -> List[str]:
        """Detect XSS indicators in response body."""
        found = []
        for pattern in self.XSS_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                found.append(pattern)
        return found

    def detect_ssti_indicators(self, body: str) -> List[str]:
        """Detect SSTI indicators in response body."""
        found = []
        for pattern in self.SSTI_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                found.append(pattern)
        return found

    def detect_path_traversal(self, body: str) -> List[str]:
        """Detect path traversal success indicators."""
        found = []
        for pattern in self.PATH_TRAVERSAL_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                found.append(pattern)
        return found

    def detect_cmd_injection(self, body: str) -> List[str]:
        """Detect command injection success indicators."""
        found = []
        for pattern in self.CMD_INJECTION_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                found.append(pattern)
        return found

    def detect_info_disclosure(self, body: str) -> List[str]:
        """Detect potential information disclosure."""
        found = []
        for pattern in self.INFO_DISCLOSURE_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                found.extend(matches[:3])  # Limit to 3 matches per pattern
        return found[:10]  # Limit total

    def is_time_based_anomaly(
        self,
        responses: List[HTTPResponse],
        threshold: Optional[float] = None,
    ) -> Tuple[bool, Dict[str, float]]:
        """
        Detect time-based anomalies across multiple responses.

        Returns (is_anomaly, stats)
        """
        threshold = threshold or self.time_threshold
        times = [r.elapsed for r in responses]

        if len(times) < 2:
            return False, {"times": times}

        avg_time = statistics.mean(times)
        max_time = max(times)
        min_time = min(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0

        stats = {
            "average": avg_time,
            "max": max_time,
            "min": min_time,
            "stdev": stdev,
            "range": max_time - min_time,
        }

        # Anomaly if max is significantly higher than average
        is_anomaly = (max_time - avg_time) >= threshold or max_time >= threshold

        return is_anomaly, stats

    def is_boolean_based_anomaly(
        self,
        true_response: HTTPResponse,
        false_response: HTTPResponse,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect boolean-based anomalies between true/false condition responses.
        """
        true_fp = self.fingerprint(true_response)
        false_fp = self.fingerprint(false_response)

        # Calculate differences
        status_diff = true_fp.status != false_fp.status
        length_diff = abs(true_fp.length - false_fp.length)
        content_diff = true_fp.content_hash != false_fp.content_hash

        similarity = self._calculate_similarity(
            true_response.body, false_response.body
        )

        stats = {
            "status_different": status_diff,
            "length_difference": length_diff,
            "content_different": content_diff,
            "similarity": similarity,
            "true_length": true_fp.length,
            "false_length": false_fp.length,
        }

        # Anomaly if responses are significantly different
        is_anomaly = (
            status_diff or
            (content_diff and similarity < self.similarity_threshold) or
            (length_diff > true_fp.length * self.length_threshold)
        )

        return is_anomaly, stats

    def add_to_history(self, response: HTTPResponse):
        """Add response fingerprint to history for statistical analysis."""
        self._response_history.append(self.fingerprint(response))

    def get_history_stats(self) -> Dict[str, Any]:
        """Get statistics from response history."""
        if not self._response_history:
            return {}

        lengths = [fp.length for fp in self._response_history]
        times = [fp.elapsed for fp in self._response_history]

        return {
            "count": len(self._response_history),
            "length_avg": statistics.mean(lengths),
            "length_stdev": statistics.stdev(lengths) if len(lengths) > 1 else 0,
            "time_avg": statistics.mean(times),
            "time_stdev": statistics.stdev(times) if len(times) > 1 else 0,
            "status_codes": list(set(fp.status for fp in self._response_history)),
        }

    def clear_history(self):
        """Clear response history."""
        self._response_history.clear()


def quick_analyze(response: HTTPResponse, payload: Optional[str] = None) -> AnalysisResult:
    """Convenience function for quick response analysis."""
    analyzer = ResponseAnalyzer()
    return analyzer.analyze(response, payload)

"""
Result manager for standardized JSON/Markdown output.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .utils import ensure_dir, safe_filename, timestamp_now, setup_logging

logger = setup_logging("result_manager")


class Severity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        scores = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return scores[self.value]


@dataclass
class Finding:
    """Individual vulnerability finding."""

    title: str
    severity: Severity
    description: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=timestamp_now)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        if isinstance(data.get("severity"), str):
            data["severity"] = Severity(data["severity"])
        return cls(**data)


@dataclass
class ScanResult:
    """Complete scan result container."""

    tool: str
    target: str
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    start_time: str = field(default_factory=timestamp_now)
    end_time: Optional[str] = None
    duration: Optional[float] = None

    def add_finding(self, finding: Finding):
        """Add a finding to the results."""
        self.findings.append(finding)

    def add_error(self, error: str):
        """Add an error message."""
        self.errors.append(error)

    def finalize(self):
        """Mark scan as complete and calculate stats."""
        self.end_time = timestamp_now()
        if self.start_time and self.end_time:
            start = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.end_time.replace("Z", "+00:00"))
            self.duration = (end - start).total_seconds()

        # Calculate severity breakdown
        severity_counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1

        self.stats.update(
            {
                "total_findings": len(self.findings),
                "severity_breakdown": severity_counts,
                "has_critical": severity_counts["critical"] > 0,
                "has_high": severity_counts["high"] > 0,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "timestamp": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats,
            "config": self.config,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(
            tool=data["tool"],
            target=data["target"],
            findings=findings,
            stats=data.get("stats", {}),
            config=data.get("config", {}),
            errors=data.get("errors", []),
            start_time=data.get("timestamp", timestamp_now()),
            end_time=data.get("end_time"),
            duration=data.get("duration"),
        )


class ResultManager:
    """
    Manages scan results with JSON and Markdown output.

    Usage:
        manager = ResultManager(output_dir="results/")
        result = ScanResult(tool="sqli_tester", target="https://example.com")

        # Add findings
        result.add_finding(Finding(
            title="SQL Injection",
            severity=Severity.HIGH,
            description="Time-based SQL injection found",
            url="https://example.com/search",
            parameter="q",
            payload="' AND SLEEP(5)--"
        ))

        # Save results
        result.finalize()
        manager.save(result)
    """

    def __init__(self, output_dir: str = "results"):
        self.output_dir = Path(output_dir)
        ensure_dir(self.output_dir)

    def save(
        self,
        result: ScanResult,
        filename: Optional[str] = None,
        include_markdown: bool = True,
    ) -> Dict[str, str]:
        """
        Save scan result to JSON and Markdown files.

        Returns dict with paths to saved files.
        """
        if not filename:
            filename = safe_filename(f"{result.tool}_{result.target}")

        json_path = self.output_dir / f"{filename}.json"
        md_path = self.output_dir / f"{filename}.md"

        # Save JSON
        with open(json_path, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        logger.info(f"Saved JSON: {json_path}")

        paths = {"json": str(json_path)}

        # Save Markdown summary
        if include_markdown:
            markdown = self._generate_markdown(result)
            with open(md_path, "w") as f:
                f.write(markdown)
            logger.info(f"Saved Markdown: {md_path}")
            paths["markdown"] = str(md_path)

        return paths

    def load(self, json_path: str) -> ScanResult:
        """Load scan result from JSON file."""
        with open(json_path, "r") as f:
            data = json.load(f)
        return ScanResult.from_dict(data)

    def _generate_markdown(self, result: ScanResult) -> str:
        """Generate Markdown summary from scan result."""
        lines = []

        # Header
        lines.append(f"# {result.tool.replace('_', ' ').title()} Results")
        lines.append("")
        lines.append(f"**Target:** {result.target}")
        lines.append(f"**Scan Time:** {result.start_time}")
        if result.duration:
            lines.append(f"**Duration:** {result.duration:.2f}s")
        lines.append("")

        # Status summary
        total = len(result.findings)
        if total == 0:
            lines.append("## Status: NO FINDINGS")
            lines.append("")
            lines.append("No vulnerabilities detected.")
        else:
            critical = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
            high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
            medium = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
            low = sum(1 for f in result.findings if f.severity == Severity.LOW)
            info = sum(1 for f in result.findings if f.severity == Severity.INFO)

            status = "VULNERABLE" if critical or high else "ISSUES FOUND"
            lines.append(f"## Status: {status} ({total} findings)")
            lines.append("")
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            if critical:
                lines.append(f"| CRITICAL | {critical} |")
            if high:
                lines.append(f"| HIGH | {high} |")
            if medium:
                lines.append(f"| MEDIUM | {medium} |")
            if low:
                lines.append(f"| LOW | {low} |")
            if info:
                lines.append(f"| INFO | {info} |")
            lines.append("")

        # Findings table
        if result.findings:
            lines.append("## Findings Summary")
            lines.append("")
            lines.append("| # | Title | Severity | Parameter | URL |")
            lines.append("|---|-------|----------|-----------|-----|")

            # Sort by severity
            sorted_findings = sorted(
                result.findings, key=lambda f: f.severity.score, reverse=True
            )

            for i, finding in enumerate(sorted_findings, 1):
                param = finding.parameter or "-"
                url_short = (
                    finding.url[:50] + "..." if len(finding.url) > 50 else finding.url
                )
                lines.append(
                    f"| {i} | {finding.title} | {finding.severity.value.upper()} | {param} | {url_short} |"
                )
            lines.append("")

        # Top findings details
        if result.findings:
            lines.append("## Top Findings Details")
            lines.append("")

            # Show top 5 most severe
            top_findings = sorted(
                result.findings, key=lambda f: f.severity.score, reverse=True
            )[:5]

            for i, finding in enumerate(top_findings, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append("")
                lines.append(f"- **Severity:** {finding.severity.value.upper()}")
                lines.append(f"- **URL:** `{finding.url}`")
                if finding.parameter:
                    lines.append(f"- **Parameter:** `{finding.parameter}`")
                if finding.payload:
                    lines.append(f"- **Payload:** `{finding.payload}`")
                if finding.cvss_score:
                    lines.append(f"- **CVSS Score:** {finding.cvss_score}")
                if finding.cwe_id:
                    lines.append(f"- **CWE:** {finding.cwe_id}")
                lines.append("")
                lines.append(f"**Description:** {finding.description}")
                lines.append("")
                if finding.evidence:
                    lines.append("**Evidence:**")
                    lines.append("```")
                    lines.append(finding.evidence[:500])
                    if len(finding.evidence) > 500:
                        lines.append("... (truncated)")
                    lines.append("```")
                    lines.append("")
                if finding.remediation:
                    lines.append(f"**Remediation:** {finding.remediation}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        # Statistics
        if result.stats:
            lines.append("## Statistics")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(result.stats, indent=2))
            lines.append("```")
            lines.append("")

        # Errors
        if result.errors:
            lines.append("## Errors")
            lines.append("")
            for error in result.errors:
                lines.append(f"- {error}")
            lines.append("")

        return "\n".join(lines)

    def merge_results(self, results: List[ScanResult]) -> ScanResult:
        """Merge multiple scan results into one."""
        if not results:
            raise ValueError("No results to merge")

        merged = ScanResult(
            tool="merged",
            target=results[0].target,
            start_time=min(r.start_time for r in results),
        )

        for result in results:
            merged.findings.extend(result.findings)
            merged.errors.extend(result.errors)

            # Merge stats
            for key, value in result.stats.items():
                if key not in merged.stats:
                    merged.stats[key] = value
                elif isinstance(value, (int, float)):
                    merged.stats[key] = merged.stats.get(key, 0) + value

        merged.finalize()
        return merged

    def filter_findings(
        self,
        result: ScanResult,
        min_severity: Severity = Severity.LOW,
        keywords: Optional[List[str]] = None,
    ) -> List[Finding]:
        """Filter findings by severity and keywords."""
        filtered = []

        for finding in result.findings:
            # Severity filter
            if finding.severity.score < min_severity.score:
                continue

            # Keyword filter
            if keywords:
                text = f"{finding.title} {finding.description}".lower()
                if not any(kw.lower() in text for kw in keywords):
                    continue

            filtered.append(finding)

        return filtered

    def get_summary(self, result: ScanResult) -> Dict[str, Any]:
        """Get concise summary of scan results."""
        return {
            "tool": result.tool,
            "target": result.target,
            "total_findings": len(result.findings),
            "critical": sum(1 for f in result.findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in result.findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in result.findings if f.severity == Severity.LOW),
            "info": sum(1 for f in result.findings if f.severity == Severity.INFO),
            "has_vulnerabilities": any(
                f.severity in [Severity.CRITICAL, Severity.HIGH] for f in result.findings
            ),
            "duration": result.duration,
            "errors": len(result.errors),
        }


def create_finding(
    title: str,
    severity: str,
    description: str,
    url: str,
    **kwargs,
) -> Finding:
    """Convenience function to create a Finding."""
    return Finding(
        title=title,
        severity=Severity(severity.lower()),
        description=description,
        url=url,
        **kwargs,
    )

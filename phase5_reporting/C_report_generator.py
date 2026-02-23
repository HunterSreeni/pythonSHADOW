#!/usr/bin/env python3
"""
SHADOW Phase 5 - Report Generator.

Produces HackerOne-format, generic, and CTF writeup reports from Finding objects.
Includes CVSS 3.1 base score calculation and pre-submission checklist enforcement.

Usage:
    python3 C_report_generator.py --finding finding.json --format hackerone --asset "*.grammarly.com"
    python3 C_report_generator.py --checklist finding.json
    python3 C_report_generator.py --cvss AV:N AC:L PR:N UI:N S:U C:H I:H A:H
"""

import argparse
import json
import math
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import Finding and Severity from core
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.result_manager import Finding, Severity

# ---------------------------------------------------------------------------
# Exploitation Evidence Levels
# ---------------------------------------------------------------------------

class ExploitationLevel(Enum):
    """Exploitation evidence rating per SHADOW CLAUDE.md framework."""

    E1 = "Proven Exploitation"
    E2 = "Confirmed Behavior"
    E3 = "Source Code Only"
    E4 = "Theoretical/Inferred"

    @property
    def submittable(self) -> str:
        mapping = {
            "E1": "YES - submit",
            "E2": "MAYBE - only if behavior IS the vuln (e.g., PII in response)",
            "E3": "NO - test live first",
            "E4": "NO - will get Informative",
        }
        return mapping[self.name]

    @property
    def rank(self) -> int:
        return {"E1": 1, "E2": 2, "E3": 3, "E4": 4}[self.name]


# ---------------------------------------------------------------------------
# CVSS 3.1 Calculator
# ---------------------------------------------------------------------------

class CVSSCalculator:
    """
    CVSS 3.1 base score calculator.

    Metric keys (pass as keyword arguments to calculate()):
        AV  - Attack Vector:         N (Network), A (Adjacent), L (Local), P (Physical)
        AC  - Attack Complexity:     L (Low), H (High)
        PR  - Privileges Required:   N (None), L (Low), H (High)
        UI  - User Interaction:      N (None), R (Required)
        S   - Scope:                 U (Unchanged), C (Changed)
        C   - Confidentiality:       H (High), L (Low), N (None)
        I   - Integrity:             H (High), L (Low), N (None)
        A   - Availability:          H (High), L (Low), N (None)
    """

    _AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    _AC = {"L": 0.77, "H": 0.44}
    _PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    _UI = {"N": 0.85, "R": 0.62}
    _CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

    VALID_METRICS = {
        "AV": set(_AV.keys()),
        "AC": set(_AC.keys()),
        "PR": {"N", "L", "H"},
        "UI": set(_UI.keys()),
        "S": {"U", "C"},
        "C": {"H", "L", "N"},
        "I": {"H", "L", "N"},
        "A": {"H", "L", "N"},
    }

    def calculate(self, **metrics) -> float:
        """
        Calculate CVSS 3.1 base score.

        Returns a float rounded to one decimal (0.0 - 10.0).
        """
        for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
            if key not in metrics:
                raise ValueError(f"Missing required CVSS metric: {key}")
            val = metrics[key].upper()
            if val not in self.VALID_METRICS[key]:
                raise ValueError(
                    f"Invalid value '{val}' for metric {key}. "
                    f"Valid: {self.VALID_METRICS[key]}"
                )
            metrics[key] = val

        av = self._AV[metrics["AV"]]
        ac = self._AC[metrics["AC"]]
        scope_changed = metrics["S"] == "C"
        pr_table = self._PR_CHANGED if scope_changed else self._PR_UNCHANGED
        pr = pr_table[metrics["PR"]]
        ui = self._UI[metrics["UI"]]

        c = self._CIA[metrics["C"]]
        i = self._CIA[metrics["I"]]
        a = self._CIA[metrics["A"]]

        # Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # Impact
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        if scope_changed:
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            base = min(impact + exploitability, 10.0)

        return self._roundup(base)

    @staticmethod
    def _roundup(value: float) -> float:
        """CVSS roundup function: round up to nearest 0.1."""
        return math.ceil(value * 10) / 10.0

    @classmethod
    def from_vector(cls, vector_string: str) -> float:
        """
        Parse a CVSS vector string and return the score.

        Accepts formats like:
            AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
            CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        """
        calc = cls()
        vector = vector_string.strip()
        if vector.upper().startswith("CVSS:"):
            # Strip the "CVSS:3.1/" prefix
            vector = vector.split("/", 1)[1] if "/" in vector else vector

        metrics = {}
        for part in vector.split("/"):
            if ":" in part:
                key, val = part.split(":", 1)
                metrics[key.upper()] = val.upper()

        return calc.calculate(**metrics)

    @classmethod
    def severity_from_score(cls, score: float) -> str:
        """Map CVSS score to severity string."""
        if score == 0.0:
            return "None"
        elif score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        else:
            return "Critical"


# ---------------------------------------------------------------------------
# Template Engine (Jinja2 with fallback)
# ---------------------------------------------------------------------------

def _get_template_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def _render_template(template_name: str, context: Dict[str, Any]) -> str:
    """Render a Jinja2 template, falling back to simple string formatting."""
    template_path = _get_template_dir() / template_name

    try:
        from jinja2 import Environment, FileSystemLoader

        env = Environment(
            loader=FileSystemLoader(str(_get_template_dir())),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template(template_name)
        return template.render(**context)
    except ImportError:
        # Fallback: read template and do basic substitution
        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        text = template_path.read_text()
        # Simple {{ var }} substitution
        for key, value in context.items():
            if isinstance(value, str):
                text = text.replace("{{ " + key + " }}", value)
                text = text.replace("{{" + key + "}}", value)
        return text


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """
    Generates vulnerability reports in multiple formats.

    Supports:
      - HackerOne submission format
      - Generic vulnerability report
      - CTF challenge writeup
      - Pre-submission checklist
    """

    def __init__(self, template_dir: Optional[str] = None):
        self.template_dir = Path(template_dir) if template_dir else _get_template_dir()
        self.cvss = CVSSCalculator()

    # ------------------------------------------------------------------
    # HackerOne Format
    # ------------------------------------------------------------------

    def generate_hackerone(
        self,
        finding: Finding,
        exploitation_level: ExploitationLevel,
        asset: str,
        cvss_metrics: Optional[Dict[str, str]] = None,
        impact_statement: Optional[str] = None,
    ) -> str:
        """
        Generate a HackerOne-format vulnerability report.

        Args:
            finding: The Finding dataclass from core.result_manager.
            exploitation_level: E1-E4 rating.
            asset: Target asset (e.g., "*.grammarly.com").
            cvss_metrics: Dict of CVSS 3.1 metrics for score calculation.
            impact_statement: Custom impact description.

        Returns:
            Markdown-formatted report string.
        """
        cvss_score = finding.cvss_score or 0.0
        if cvss_metrics:
            cvss_score = self.cvss.calculate(**cvss_metrics)

        steps = self._extract_steps(finding)
        impact = impact_statement or self._generate_impact(finding)

        context = {
            "title": finding.title,
            "severity": finding.severity.value.upper(),
            "cvss_score": f"{cvss_score:.1f}",
            "exploitation_level": exploitation_level.name,
            "exploitation_label": exploitation_level.value,
            "cwe_id": finding.cwe_id or "",
            "asset": asset,
            "description": finding.description,
            "steps": steps,
            "request": finding.request or "",
            "response": finding.response or "",
            "payload": finding.payload or "",
            "impact": impact,
            "evidence": finding.evidence or "",
            "references": finding.references or [],
            "remediation": finding.remediation or "Not specified.",
        }

        try:
            return _render_template("C_hackerone.md.j2", context)
        except (ImportError, FileNotFoundError):
            return self._fallback_hackerone(context)

    def _fallback_hackerone(self, ctx: Dict[str, Any]) -> str:
        """Plain-string fallback when Jinja2 is unavailable."""
        lines = [
            f"## Summary\n\n{ctx['title']}\n",
            f"## Severity\n\n**{ctx['severity']}** (CVSS {ctx['cvss_score']})",
            f"**Exploitation Level:** {ctx['exploitation_level']} — {ctx['exploitation_label']}\n",
        ]
        if ctx["cwe_id"]:
            lines.append(f"**CWE:** {ctx['cwe_id']}\n")
        lines.append(f"## Asset\n\n{ctx['asset']}\n")
        lines.append(f"## Description\n\n{ctx['description']}\n")
        lines.append("## Steps to Reproduce\n")
        for i, step in enumerate(ctx["steps"], 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        if ctx["request"]:
            lines.append(f"## Supporting Material\n\n**HTTP Request:**\n```http\n{ctx['request']}\n```\n")
        if ctx["response"]:
            lines.append(f"**HTTP Response (excerpt):**\n```http\n{ctx['response']}\n```\n")
        if ctx["payload"]:
            lines.append(f"**Payload Used:**\n```\n{ctx['payload']}\n```\n")
        lines.append(f"## Impact\n\n{ctx['impact']}\n")
        if ctx["evidence"]:
            lines.append(f"## Proof of Concept\n\n```\n{ctx['evidence']}\n```\n")
        if ctx["references"]:
            lines.append("## References\n")
            for ref in ctx["references"]:
                lines.append(f"- {ref}")
            lines.append("")
        lines.append(f"## Remediation\n\n{ctx['remediation']}\n")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Generic Format
    # ------------------------------------------------------------------

    def generate_generic(
        self,
        finding: Finding,
        exploitation_level: ExploitationLevel,
        asset: Optional[str] = None,
        cvss_metrics: Optional[Dict[str, str]] = None,
        impact_statement: Optional[str] = None,
    ) -> str:
        """Generate a generic vulnerability report."""
        cvss_score = finding.cvss_score or 0.0
        if cvss_metrics:
            cvss_score = self.cvss.calculate(**cvss_metrics)

        steps = self._extract_steps(finding)
        impact = impact_statement or self._generate_impact(finding)

        context = {
            "title": finding.title,
            "timestamp": finding.timestamp,
            "severity": finding.severity.value.upper(),
            "cvss_score": f"{cvss_score:.1f}",
            "exploitation_level": exploitation_level.name,
            "exploitation_label": exploitation_level.value,
            "cwe_id": finding.cwe_id or "",
            "asset": asset or "",
            "description": finding.description,
            "url": finding.url,
            "parameter": finding.parameter or "",
            "payload": finding.payload or "",
            "request": finding.request or "",
            "response": finding.response or "",
            "evidence": finding.evidence or "",
            "steps": steps,
            "impact": impact,
            "remediation": finding.remediation or "Not specified.",
            "references": finding.references or [],
        }

        try:
            return _render_template("C_generic.md.j2", context)
        except (ImportError, FileNotFoundError):
            return self._fallback_generic(context)

    def _fallback_generic(self, ctx: Dict[str, Any]) -> str:
        """Plain-string fallback for generic report."""
        lines = [
            f"# Vulnerability Report: {ctx['title']}\n",
            f"**Date:** {ctx['timestamp']}",
            f"**Severity:** {ctx['severity']} (CVSS {ctx['cvss_score']})",
            f"**Exploitation Level:** {ctx['exploitation_level']} — {ctx['exploitation_label']}",
        ]
        if ctx["cwe_id"]:
            lines.append(f"**CWE:** {ctx['cwe_id']}")
        if ctx["asset"]:
            lines.append(f"**Asset:** {ctx['asset']}")
        lines.append(f"\n---\n\n## Overview\n\n{ctx['description']}\n")
        lines.append(f"## Affected Endpoint\n\n- **URL:** `{ctx['url']}`")
        if ctx["parameter"]:
            lines.append(f"- **Parameter:** `{ctx['parameter']}`")
        if ctx["payload"]:
            lines.append(f"- **Payload:** `{ctx['payload']}`")
        lines.append("")
        if ctx["request"]:
            lines.append(f"### Request\n```http\n{ctx['request']}\n```\n")
        if ctx["response"]:
            lines.append(f"### Response\n```http\n{ctx['response']}\n```\n")
        if ctx["evidence"]:
            lines.append(f"### Evidence\n```\n{ctx['evidence']}\n```\n")
        lines.append("## Reproduction Steps\n")
        for i, step in enumerate(ctx["steps"], 1):
            lines.append(f"{i}. {step}")
        lines.append(f"\n## Impact Assessment\n\n{ctx['impact']}\n")
        lines.append(f"## Recommended Remediation\n\n{ctx['remediation']}\n")
        if ctx["references"]:
            lines.append("## References\n")
            for ref in ctx["references"]:
                lines.append(f"- {ref}")
        lines.append("\n---\n*Generated by SHADOW Framework*")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # CTF Writeup
    # ------------------------------------------------------------------

    def generate_ctf_writeup(
        self,
        title: str,
        description: str = "",
        flag: Optional[str] = None,
        steps: Optional[List[Dict[str, str]]] = None,
        tools: Optional[List[str]] = None,
        category: Optional[str] = None,
        difficulty: Optional[str] = None,
        points: Optional[int] = None,
        takeaways: Optional[List[str]] = None,
    ) -> str:
        """
        Generate a CTF challenge writeup.

        Args:
            title: Challenge name.
            description: Challenge description/prompt.
            flag: The captured flag (if found).
            steps: List of dicts with keys: title, detail, code (optional), language (optional).
            tools: List of tool names used.
            category: Challenge category (Web, Crypto, Pwn, etc.).
            difficulty: Difficulty level.
            points: Point value.
            takeaways: Key lessons learned.
        """
        steps = steps or []
        context = {
            "title": title,
            "description": description or "No description provided.",
            "flag": flag or "",
            "steps": steps,
            "tools": tools or [],
            "category": category or "",
            "difficulty": difficulty or "",
            "points": str(points) if points else "",
            "takeaways": takeaways or [],
        }

        try:
            return _render_template("C_ctf_writeup.md.j2", context)
        except (ImportError, FileNotFoundError):
            return self._fallback_ctf(context)

    def _fallback_ctf(self, ctx: Dict[str, Any]) -> str:
        """Plain-string fallback for CTF writeup."""
        lines = [f"# {ctx['title']}\n"]
        if ctx["category"]:
            lines.append(f"**Category:** {ctx['category']}")
        if ctx["difficulty"]:
            lines.append(f"**Difficulty:** {ctx['difficulty']}")
        if ctx["points"]:
            lines.append(f"**Points:** {ctx['points']}")
        lines.append(f"\n---\n\n## Challenge Description\n\n{ctx['description']}\n")
        lines.append("## Solution\n")
        for i, step in enumerate(ctx["steps"], 1):
            step_title = step.get("title", f"Step {i}")
            lines.append(f"### Step {i}: {step_title}\n")
            lines.append(step.get("detail", ""))
            code = step.get("code")
            if code:
                lang = step.get("language", "")
                lines.append(f"\n```{lang}\n{code}\n```")
            lines.append("")
        if ctx["tools"]:
            lines.append("## Tools Used\n")
            for tool in ctx["tools"]:
                lines.append(f"- {tool}")
            lines.append("")
        if ctx["flag"]:
            lines.append(f"## Flag\n\n```\n{ctx['flag']}\n```\n")
        if ctx["takeaways"]:
            lines.append("## Key Takeaways\n")
            for t in ctx["takeaways"]:
                lines.append(f"- {t}")
            lines.append("")
        lines.append("---\n*Generated by SHADOW Framework*")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Pre-Submission Checklist
    # ------------------------------------------------------------------

    def pre_submission_checklist(
        self,
        finding: Finding,
        exploitation_level: ExploitationLevel,
        asset_in_scope: Optional[bool] = None,
    ) -> str:
        """
        Generate the 5-question pre-submission checklist.

        Returns a formatted string with PASS/FAIL for each question
        based on the exploitation level.
        """
        e = exploitation_level.rank  # 1=E1, 2=E2, 3=E3, 4=E4

        checks = [
            {
                "question": "Can I show REAL data accessed/modified that shouldn't be accessible?",
                "result": "PASS" if e == 1 else "FAIL",
                "note": {
                    1: "E1: Real data access demonstrated.",
                    2: "E2: Behavior confirmed but no real data accessed.",
                    3: "E3: Source code only, no live test.",
                    4: "E4: Theoretical, no evidence.",
                }[e],
            },
            {
                "question": "Can I prove the SERVER-SIDE action actually happened?",
                "result": "PASS" if e == 1 else "FAIL",
                "note": {
                    1: "E1: Server-side impact proven.",
                    2: "E2: Server accepts input, but side-effect not confirmed.",
                    3: "E3: Not tested against live server.",
                    4: "E4: Inferred from indirect signals.",
                }[e],
            },
            {
                "question": "Is my impact statement based on EVIDENCE or INFERENCE?",
                "result": "PASS" if e <= 2 else "FAIL",
                "note": {
                    1: "E1: Based on direct evidence.",
                    2: "E2: Based on observed behavior (evidence).",
                    3: "E3: Based on source code inference.",
                    4: "E4: Based on theoretical inference.",
                }[e],
            },
            {
                "question": 'Would a skeptical triager say "so what?" to my PoC?',
                "result": self._skeptic_check(finding, exploitation_level),
                "note": self._skeptic_note(finding, exploitation_level),
            },
            {
                "question": "Is the asset EXPLICITLY listed in the program scope?",
                "result": "PASS" if asset_in_scope is True else (
                    "FAIL" if asset_in_scope is False else "MANUAL CHECK REQUIRED"
                ),
                "note": "Verify against program scope document before submission.",
            },
        ]

        lines = [
            "=" * 60,
            "  SHADOW PRE-SUBMISSION CHECKLIST",
            "=" * 60,
            "",
            f"  Finding:   {finding.title}",
            f"  Severity:  {finding.severity.value.upper()}",
            f"  E-Level:   {exploitation_level.name} — {exploitation_level.value}",
            f"  Submit?    {exploitation_level.submittable}",
            "",
            "-" * 60,
        ]

        pass_count = 0
        for i, check in enumerate(checks, 1):
            status = check["result"]
            marker = "[PASS]" if status == "PASS" else (
                "[FAIL]" if status == "FAIL" else "[????]"
            )
            if status == "PASS":
                pass_count += 1
            lines.append(f"\n  {i}. {check['question']}")
            lines.append(f"     {marker} {check['note']}")

        lines.append("")
        lines.append("-" * 60)
        lines.append(f"  Result: {pass_count}/5 checks passed")

        if pass_count >= 4 and exploitation_level.rank == 1:
            lines.append("  RECOMMENDATION: Ready to submit.")
        elif pass_count >= 3 and exploitation_level.rank <= 2:
            lines.append("  RECOMMENDATION: Review carefully, may be submittable.")
        else:
            lines.append("  RECOMMENDATION: DO NOT SUBMIT. Strengthen evidence first.")

        lines.append("=" * 60)
        return "\n".join(lines)

    def _skeptic_check(self, finding: Finding, elevel: ExploitationLevel) -> str:
        """Would a skeptical triager dismiss this?"""
        if elevel.rank >= 4:
            return "FAIL"
        if elevel.rank == 1:
            return "PASS"
        # E2/E3: depends on whether there's concrete evidence
        if finding.evidence and len(finding.evidence) > 50:
            return "PASS"
        return "FAIL"

    def _skeptic_note(self, finding: Finding, elevel: ExploitationLevel) -> str:
        if elevel.rank == 1:
            return "Proven exploitation speaks for itself."
        if elevel.rank == 2:
            if finding.evidence and len(finding.evidence) > 50:
                return "Behavior confirmed with evidence, should hold up."
            return "Evidence is thin. Triager may push back."
        if elevel.rank == 3:
            return "Source-only finding. Triager will ask for live proof."
        return "Theoretical finding. Very likely to be marked Informative."

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_steps(self, finding: Finding) -> List[str]:
        """
        Extract reproduction steps from finding metadata or generate defaults.
        """
        # Check metadata for explicit steps
        if "steps" in finding.metadata:
            return finding.metadata["steps"]

        # Build steps from available data
        steps = []
        steps.append(f"Navigate to: {finding.url}")
        if finding.parameter:
            steps.append(f"Identify the vulnerable parameter: {finding.parameter}")
        if finding.payload:
            steps.append(f"Inject the following payload: {finding.payload}")
        steps.append("Observe the application response demonstrating the vulnerability.")
        if finding.evidence:
            steps.append(f"Confirm impact by examining the evidence in the response.")
        return steps

    def _generate_impact(self, finding: Finding) -> str:
        """Generate an impact statement from finding severity and description."""
        severity_impacts = {
            Severity.CRITICAL: (
                "This vulnerability poses a critical risk to the application. "
                "An attacker could exploit this to achieve full system compromise, "
                "mass data exfiltration, or complete authentication bypass."
            ),
            Severity.HIGH: (
                "This vulnerability has high impact. An attacker could exploit it "
                "to access sensitive data, escalate privileges, or perform "
                "unauthorized actions affecting other users."
            ),
            Severity.MEDIUM: (
                "This vulnerability has moderate impact. While exploitation "
                "requires specific conditions, a successful attack could lead to "
                "partial data disclosure or limited unauthorized access."
            ),
            Severity.LOW: (
                "This vulnerability has limited impact. Exploitation may reveal "
                "minor information or require significant prerequisites."
            ),
            Severity.INFO: (
                "This is an informational finding that may contribute to a "
                "broader attack chain but does not represent a direct risk."
            ),
        }
        return severity_impacts.get(finding.severity, "Impact assessment pending.")

    # ------------------------------------------------------------------
    # Batch Operations
    # ------------------------------------------------------------------

    def generate_batch(
        self,
        findings: List[Finding],
        exploitation_levels: Dict[str, ExploitationLevel],
        asset: str,
        output_dir: str,
        report_format: str = "hackerone",
    ) -> List[str]:
        """
        Generate reports for multiple findings.

        Args:
            findings: List of Finding objects.
            exploitation_levels: Mapping of finding.title -> ExploitationLevel.
            asset: Target asset identifier.
            output_dir: Directory to write reports.
            report_format: "hackerone" or "generic".

        Returns:
            List of file paths for generated reports.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = []

        for finding in findings:
            elevel = exploitation_levels.get(finding.title, ExploitationLevel.E4)

            if report_format == "hackerone":
                content = self.generate_hackerone(finding, elevel, asset)
            else:
                content = self.generate_generic(finding, elevel, asset)

            safe_title = "".join(
                c if c.isalnum() or c in "-_ " else "_" for c in finding.title
            ).strip().replace(" ", "_")[:80]
            filename = f"C_{safe_title}.md"
            filepath = out / filename
            filepath.write_text(content)
            paths.append(str(filepath))

        return paths

    def save_report(
        self, content: str, output_path: str, also_json: bool = False,
        finding: Optional[Finding] = None,
    ) -> Dict[str, str]:
        """Save report content to file, optionally including JSON."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content)
        result = {"markdown": str(out)}

        if also_json and finding:
            json_path = out.with_suffix(".json")
            json_path.write_text(json.dumps(finding.to_dict(), indent=2))
            result["json"] = str(json_path)

        return result


# ---------------------------------------------------------------------------
# CLI Interface
# ---------------------------------------------------------------------------

def _load_finding_from_file(path: str) -> Finding:
    """Load a Finding from a JSON file."""
    with open(path, "r") as f:
        data = json.load(f)
    return Finding.from_dict(data)


def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --finding finding.json --format hackerone --asset "*.grammarly.com"
  %(prog)s --finding finding.json --format generic --elevel E2
  %(prog)s --checklist finding.json --elevel E1
  %(prog)s --cvss AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  %(prog)s --ctf --title "SQL Injection Challenge" --flag "CTF{found_it}"
        """,
    )

    parser.add_argument(
        "--finding", type=str, help="Path to finding JSON file."
    )
    parser.add_argument(
        "--format",
        choices=["hackerone", "generic"],
        default="hackerone",
        help="Report format (default: hackerone).",
    )
    parser.add_argument(
        "--asset", type=str, default="unknown", help="Target asset identifier."
    )
    parser.add_argument(
        "--elevel",
        choices=["E1", "E2", "E3", "E4"],
        default="E4",
        help="Exploitation evidence level (default: E4).",
    )
    parser.add_argument(
        "--checklist",
        type=str,
        metavar="FINDING_JSON",
        help="Run pre-submission checklist on a finding.",
    )
    parser.add_argument(
        "--cvss",
        type=str,
        help="Calculate CVSS score from vector (e.g., AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).",
    )
    parser.add_argument(
        "--output", "-o", type=str, help="Output file path."
    )

    # CTF mode
    parser.add_argument("--ctf", action="store_true", help="Generate CTF writeup.")
    parser.add_argument("--title", type=str, help="CTF challenge title.")
    parser.add_argument("--flag", type=str, help="CTF flag.")

    args = parser.parse_args()
    gen = ReportGenerator()

    # CVSS calculation mode
    if args.cvss:
        score = CVSSCalculator.from_vector(args.cvss)
        severity = CVSSCalculator.severity_from_score(score)
        print(f"CVSS 3.1 Base Score: {score:.1f} ({severity})")
        return

    # Checklist mode
    if args.checklist:
        finding = _load_finding_from_file(args.checklist)
        elevel = ExploitationLevel[args.elevel]
        result = gen.pre_submission_checklist(finding, elevel)
        print(result)
        return

    # CTF writeup mode
    if args.ctf:
        if not args.title:
            parser.error("--ctf requires --title")
        result = gen.generate_ctf_writeup(
            title=args.title,
            flag=args.flag,
        )
        if args.output:
            Path(args.output).write_text(result)
            print(f"CTF writeup saved to: {args.output}")
        else:
            print(result)
        return

    # Standard report mode
    if not args.finding:
        parser.error("--finding is required for report generation.")

    finding = _load_finding_from_file(args.finding)
    elevel = ExploitationLevel[args.elevel]

    if args.format == "hackerone":
        content = gen.generate_hackerone(finding, elevel, args.asset)
    else:
        content = gen.generate_generic(finding, elevel, args.asset)

    if args.output:
        gen.save_report(content, args.output, also_json=True, finding=finding)
        print(f"Report saved to: {args.output}")
    else:
        print(content)


if __name__ == "__main__":
    main()

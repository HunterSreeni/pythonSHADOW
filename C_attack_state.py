#!/usr/bin/env python3
"""
C_attack_state.py — Persistent attack state for SHADOW framework.
Tracks discovered assets, tested vectors, findings, and session history.
"""

import json
import argparse
import sys
from dataclasses import dataclass, field, asdict
from typing import Set, Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent  # shadow-bounty/../ = SHADOW/


class StateEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles sets and other non-serializable types."""

    def default(self, obj):
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


def _decode_state(data: dict) -> dict:
    """Convert serialized JSON back to proper Python types."""
    if "discovered_subdomains" in data and isinstance(data["discovered_subdomains"], list):
        data["discovered_subdomains"] = set(data["discovered_subdomains"])
    return data


@dataclass
class AttackState:
    target: str
    session_number: int = 0
    created_at: str = ""
    last_updated: str = ""

    # Discovery
    discovered_subdomains: Set[str] = field(default_factory=set)
    discovered_endpoints: Dict[str, dict] = field(default_factory=dict)
    # endpoint format: url -> {method, params, auth_required, tested, notes}

    # Testing tracking
    tested_vectors: Dict[str, str] = field(default_factory=dict)
    # vector_key -> "eliminated"|"promising"|"exploited"

    # Findings (E1-E4 rated)
    findings: List[dict] = field(default_factory=list)
    # Each: {title, severity, exploitation_level (E1-E4), description, evidence, session}

    eliminated_vectors: List[dict] = field(default_factory=list)
    # Each: {vector, reason, session, timestamp}

    promising_leads: List[dict] = field(default_factory=list)
    # Each: {description, priority (1-5), session, notes}

    # Auth state
    auth_tokens: Dict[str, dict] = field(default_factory=dict)
    # token_name -> {value, expires, scope, type}

    # Session history
    session_log: List[dict] = field(default_factory=list)
    # Each: {session_number, date, summary, findings_count, vectors_tested}

    # --- Core Methods ---

    @classmethod
    def load(cls, target: str) -> "AttackState":
        """Load state from targets/<target>/C_session_state.json. Returns new state if not found."""
        state_file = PROJECT_ROOT / "targets" / target / "C_session_state.json"
        if state_file.exists():
            try:
                raw = json.loads(state_file.read_text(encoding="utf-8"))
                raw = _decode_state(raw)
                state = cls(target=target)
                for k, v in raw.items():
                    if hasattr(state, k):
                        setattr(state, k, v)
                return state
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[!] Error loading state for {target}: {e}", file=sys.stderr)
                print(f"[!] Creating fresh state", file=sys.stderr)
        state = cls(target=target, created_at=datetime.now(timezone.utc).isoformat())
        return state

    def save(self) -> Path:
        """Save state to JSON. Returns the path written."""
        self.last_updated = datetime.now(timezone.utc).isoformat()
        state_dir = PROJECT_ROOT / "targets" / self.target
        state_dir.mkdir(parents=True, exist_ok=True)
        state_file = state_dir / "C_session_state.json"
        state_file.write_text(
            json.dumps(asdict(self), cls=StateEncoder, indent=2),
            encoding="utf-8",
        )
        return state_file

    def new_session(self, summary: str = "") -> int:
        """Increment session number and add session_log entry. Returns new session number."""
        self.session_number += 1
        entry = {
            "session_number": self.session_number,
            "date": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "findings_count": 0,
            "vectors_tested": 0,
        }
        self.session_log.append(entry)
        self.save()
        return self.session_number

    # --- State Management ---

    def mark_tested(self, vector_key: str, result: str, reason: str = "") -> None:
        """Mark a vector as tested. result: 'eliminated'|'promising'|'exploited'."""
        result = result.lower()
        if result not in ("eliminated", "promising", "exploited"):
            raise ValueError(f"result must be eliminated|promising|exploited, got: {result}")
        self.tested_vectors[vector_key] = result
        if result == "eliminated":
            self.eliminated_vectors.append({
                "vector": vector_key,
                "reason": reason,
                "session": self.session_number,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        # Update current session log
        if self.session_log:
            self.session_log[-1]["vectors_tested"] = sum(
                1 for s in self.session_log[-1:] for _ in [1]
            )
            # Recount vectors tested this session
            self.session_log[-1]["vectors_tested"] = sum(
                1 for v in self.eliminated_vectors
                if v.get("session") == self.session_number
            ) + sum(
                1 for k, v in self.tested_vectors.items()
                if v in ("promising", "exploited")
            )

    def add_finding(
        self,
        title: str,
        severity: str,
        exploitation_level: str,
        description: str,
        evidence: str = "",
    ) -> dict:
        """Add a finding with E1-E4 rating. Returns the finding dict."""
        exploitation_level = exploitation_level.upper()
        if exploitation_level not in ("E1", "E2", "E3", "E4"):
            raise ValueError(f"exploitation_level must be E1-E4, got: {exploitation_level}")
        finding = {
            "title": title,
            "severity": severity,
            "exploitation_level": exploitation_level,
            "description": description,
            "evidence": evidence,
            "session": self.session_number,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.findings.append(finding)
        # Update session log
        if self.session_log:
            self.session_log[-1]["findings_count"] = sum(
                1 for f in self.findings if f.get("session") == self.session_number
            )
        return finding

    def add_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: Optional[dict] = None,
        auth_required: Optional[bool] = None,
        notes: str = "",
    ) -> None:
        """Add or update a discovered endpoint."""
        self.discovered_endpoints[url] = {
            "method": method.upper(),
            "params": params or {},
            "auth_required": auth_required,
            "tested": False,
            "notes": notes,
            "discovered_session": self.session_number,
        }

    def add_subdomain(self, subdomain: str) -> None:
        """Add a discovered subdomain."""
        self.discovered_subdomains.add(subdomain.lower().strip())

    def add_lead(self, description: str, priority: int = 3, notes: str = "") -> None:
        """Add a promising lead. Priority 1 (highest) to 5 (lowest)."""
        priority = max(1, min(5, priority))
        self.promising_leads.append({
            "description": description,
            "priority": priority,
            "session": self.session_number,
            "notes": notes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def store_token(
        self,
        name: str,
        value: str,
        expires: Optional[str] = None,
        scope: Optional[str] = None,
        token_type: Optional[str] = None,
    ) -> None:
        """Store an auth token."""
        self.auth_tokens[name] = {
            "value": value,
            "expires": expires,
            "scope": scope,
            "type": token_type,
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }

    # --- Query Methods ---

    def get_untested_vectors(self) -> List[dict]:
        """Return promising_leads not yet in tested_vectors."""
        tested_keys = set(self.tested_vectors.keys())
        return [
            lead for lead in self.promising_leads
            if lead["description"] not in tested_keys
        ]

    def get_findings_by_level(self, level: str) -> List[dict]:
        """Filter findings by exploitation level (E1/E2/E3/E4)."""
        level = level.upper()
        return [f for f in self.findings if f.get("exploitation_level") == level]

    def get_stats(self) -> dict:
        """Return summary statistics."""
        e_counts = {}
        for f in self.findings:
            lvl = f.get("exploitation_level", "??")
            e_counts[lvl] = e_counts.get(lvl, 0) + 1

        tested_count = sum(
            1 for ep in self.discovered_endpoints.values() if ep.get("tested")
        )
        return {
            "target": self.target,
            "session_number": self.session_number,
            "subdomains": len(self.discovered_subdomains),
            "endpoints_total": len(self.discovered_endpoints),
            "endpoints_tested": tested_count,
            "vectors_tested": len(self.tested_vectors),
            "vectors_eliminated": len(self.eliminated_vectors),
            "findings_total": len(self.findings),
            "findings_by_level": e_counts,
            "promising_leads": len(self.promising_leads),
            "untested_leads": len(self.get_untested_vectors()),
            "auth_tokens_stored": len(self.auth_tokens),
            "sessions_total": len(self.session_log),
        }

    # --- Export Methods ---

    def export_for_claude(self) -> str:
        """Compact text summary optimized for minimal token usage in Claude context."""
        stats = self.get_stats()
        e_counts = stats["findings_by_level"]
        e_str = ", ".join(f"{ct} {lvl}" for lvl, ct in sorted(e_counts.items())) or "0"

        lines = [
            f"TARGET: {self.target} | SESSION: {self.session_number} | FINDINGS: {e_str}",
            f"SUBDOMAINS: {stats['subdomains']} | ENDPOINTS: {stats['endpoints_total']} ({stats['endpoints_tested']} tested)",
            f"ELIMINATED: {stats['vectors_eliminated']} vectors | LEADS: {stats['untested_leads']} untested / {stats['promising_leads']} total",
        ]

        # Top leads sorted by priority
        untested = self.get_untested_vectors()
        top_leads = sorted(untested, key=lambda x: x.get("priority", 5))[:5]
        if top_leads:
            lead_strs = [
                f"{i+1}. {l['description']} (P{l['priority']})"
                for i, l in enumerate(top_leads)
            ]
            lines.append("TOP LEADS: " + " | ".join(lead_strs))

        # Recent findings
        recent = self.findings[-3:] if self.findings else []
        if recent:
            finding_strs = [
                f"[{f['exploitation_level']}] {f['title']} ({f['severity']})"
                for f in reversed(recent)
            ]
            lines.append("RECENT FINDINGS: " + " | ".join(finding_strs))

        return "\n".join(lines)

    def export_for_gemini(self) -> str:
        """Full structured JSON dump with analysis instructions for Gemini."""
        payload = {
            "instructions": (
                "You are analyzing attack state for a security research engagement. "
                "Review the findings, eliminated vectors, and promising leads. "
                "Suggest: (1) highest-priority untested vectors, (2) potential vulnerability chains, "
                "(3) any patterns in eliminated vectors that suggest alternative approaches. "
                "Rate suggestions by likely impact (critical/high/medium/low)."
            ),
            "state": {
                "target": self.target,
                "session_number": self.session_number,
                "created_at": self.created_at,
                "last_updated": self.last_updated,
                "stats": self.get_stats(),
                "findings": self.findings,
                "eliminated_vectors": self.eliminated_vectors,
                "promising_leads": self.promising_leads,
                "discovered_endpoints": dict(list(self.discovered_endpoints.items())[:100]),
                "tested_vectors": self.tested_vectors,
                "session_log": self.session_log,
            },
        }
        return json.dumps(payload, cls=StateEncoder, indent=2)


# --- CLI Interface ---


def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Attack State Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 C_attack_state.py --load superhuman\n"
            "  python3 C_attack_state.py --untested superhuman\n"
            "  python3 C_attack_state.py --findings superhuman\n"
            "  python3 C_attack_state.py --stats superhuman\n"
            "  python3 C_attack_state.py --export-claude superhuman\n"
            "  python3 C_attack_state.py --export-gemini superhuman\n"
        ),
    )
    parser.add_argument("--load", metavar="TARGET", help="Load and print state summary")
    parser.add_argument("--untested", metavar="TARGET", help="List untested vectors")
    parser.add_argument("--findings", metavar="TARGET", help="List all findings")
    parser.add_argument("--stats", metavar="TARGET", help="Show statistics")
    parser.add_argument("--export-claude", metavar="TARGET", help="Export compact summary for Claude")
    parser.add_argument("--export-gemini", metavar="TARGET", help="Export full state for Gemini")

    args = parser.parse_args()

    if args.load:
        state = AttackState.load(args.load)
        print(f"=== Attack State: {state.target} ===")
        print(f"Session: {state.session_number}")
        print(f"Created: {state.created_at}")
        print(f"Updated: {state.last_updated}")
        print(f"Subdomains: {len(state.discovered_subdomains)}")
        print(f"Endpoints: {len(state.discovered_endpoints)}")
        print(f"Findings: {len(state.findings)}")
        print(f"Eliminated: {len(state.eliminated_vectors)}")
        print(f"Leads: {len(state.promising_leads)}")
        print(f"Tokens: {len(state.auth_tokens)}")
        print(f"Sessions: {len(state.session_log)}")

    elif args.untested:
        state = AttackState.load(args.untested)
        untested = state.get_untested_vectors()
        if not untested:
            print("No untested vectors.")
            return
        print(f"=== Untested Vectors ({len(untested)}) ===")
        for i, lead in enumerate(sorted(untested, key=lambda x: x.get("priority", 5)), 1):
            print(f"  {i}. [P{lead['priority']}] {lead['description']}")
            if lead.get("notes"):
                print(f"     Notes: {lead['notes']}")

    elif args.findings:
        state = AttackState.load(args.findings)
        if not state.findings:
            print("No findings recorded.")
            return
        print(f"=== Findings ({len(state.findings)}) ===")
        for f in state.findings:
            print(f"  [{f['exploitation_level']}] {f['title']} — {f['severity']}")
            print(f"    {f['description'][:120]}")
            if f.get("evidence"):
                print(f"    Evidence: {f['evidence'][:80]}")
            print()

    elif args.stats:
        state = AttackState.load(args.stats)
        stats = state.get_stats()
        print(f"=== Stats: {stats['target']} ===")
        for k, v in stats.items():
            if k == "findings_by_level":
                print(f"  {k}:")
                for lvl, ct in sorted(v.items()):
                    print(f"    {lvl}: {ct}")
            else:
                print(f"  {k}: {v}")

    elif args.export_claude:
        state = AttackState.load(args.export_claude)
        print(state.export_for_claude())

    elif args.export_gemini:
        state = AttackState.load(args.export_gemini)
        print(state.export_for_gemini())

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

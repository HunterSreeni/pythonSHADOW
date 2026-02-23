"""
C_gemini_bridge.py — Generate copy-pasteable Gemini prompts and parse Gemini JSON responses.

Wraps JS bundles, API specs, browser extension source, and source repos into
structured analysis prompts. Parses Gemini's JSON output and merges findings
into AttackState with E3 exploitation level (source-code-only, unverified).
"""

import json
import re
import sys
import os
import argparse
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from C_attack_state import AttackState

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

GEMINI_ANALYSIS_PROMPT = """You are a senior security researcher analyzing {file_type} for a bug bounty target.

Analyze the following {file_type} and return a JSON object with EXACTLY this schema:
{{
  "endpoints": [
    {{"url": "string", "method": "GET|POST|PUT|DELETE", "params": ["string"], "auth": "none|cookie|bearer|api_key", "interesting": true, "reason": "string"}}
  ],
  "secrets": [
    {{"type": "api_key|token|password|credential", "value": "string", "context": "where found", "confidence": "high|medium|low"}}
  ],
  "attack_vectors": [
    {{"type": "xss|ssrf|idor|sqli|auth_bypass|etc", "target": "endpoint or component", "evidence": "what you found", "confidence": "high|medium|low"}}
  ]
}}

Rules:
- Only include endpoints you can see in the code
- Only flag secrets that look like real credentials (not public keys or placeholders)
- Rate confidence honestly — "high" means you're sure, "low" means it's a guess
- Do NOT inflate severity — your findings will be verified live

{file_type_specific_instructions}

--- BEGIN {file_type} ---
{content}
--- END {file_type} ---
"""

JS_INSTRUCTIONS = (
    "Focus on: API endpoints (fetch/axios/XHR calls), hardcoded secrets, "
    "authentication logic, CORS configurations, postMessage handlers, eval() usage, "
    "innerHTML assignments, URL parameters, WebSocket connections."
)

API_SPEC_INSTRUCTIONS = (
    "Focus on: endpoints lacking authentication, admin-only endpoints, file upload "
    "endpoints, endpoints accepting user IDs (IDOR), endpoints with query parameters "
    "(injection), rate-limiting gaps, deprecated but still accessible endpoints."
)

EXTENSION_INSTRUCTIONS = (
    "Focus on: manifest permissions, externally_connectable origins, "
    "web_accessible_resources, content script injection patterns, message passing "
    "(chrome.runtime.sendMessage / postMessage), storage of secrets in chrome.storage, "
    "CSP weaknesses in manifest, eval/Function/innerHTML in background/content scripts."
)

SOURCE_REPO_INSTRUCTIONS = (
    "Focus on: authentication and authorization logic, hardcoded credentials, "
    "database queries (SQL injection), file handling (path traversal), "
    "deserialization of untrusted data, command execution, API route definitions, "
    "middleware configurations, secrets in config files, .env files, Dockerfiles."
)

MAX_CONTENT_BYTES = 500_000  # 500 KB Gemini context limit


# ---------------------------------------------------------------------------
# GeminiBridge class
# ---------------------------------------------------------------------------

class GeminiBridge:
    """Generate Gemini analysis prompts and merge Gemini findings into AttackState."""

    def __init__(self, target: str):
        self.target = target
        self.state = AttackState.load(target)

    # --- Prompt Formatters ---

    @staticmethod
    def _read_and_truncate(path: str, label: str = "file") -> str:
        """Read file content, truncate if over MAX_CONTENT_BYTES."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"{label} not found: {path}")
        content = p.read_text(encoding="utf-8", errors="replace")
        if len(content) > MAX_CONTENT_BYTES:
            content = content[:MAX_CONTENT_BYTES] + "\n... [TRUNCATED at 500KB] ..."
        return content

    def format_js_bundle(self, path: str) -> str:
        """Read JS file and wrap in analysis prompt."""
        content = self._read_and_truncate(path, "JS bundle")
        return GEMINI_ANALYSIS_PROMPT.format(
            file_type="JavaScript bundle",
            content=content,
            file_type_specific_instructions=JS_INSTRUCTIONS,
        )

    def format_api_spec(self, path: str) -> str:
        """Read OpenAPI/Swagger spec and wrap in analysis prompt."""
        content = self._read_and_truncate(path, "API spec")
        return GEMINI_ANALYSIS_PROMPT.format(
            file_type="OpenAPI/Swagger specification",
            content=content,
            file_type_specific_instructions=API_SPEC_INSTRUCTIONS,
        )

    def format_extension_source(self, path: str) -> str:
        """Read browser extension source directory and wrap in analysis prompt.

        Walks the directory, reads manifest.json first, then key source files
        (JS/HTML/JSON), concatenates them with file markers.
        """
        ext_dir = Path(path)
        if not ext_dir.is_dir():
            raise NotADirectoryError(f"Extension dir not found: {path}")

        parts = []
        total_size = 0

        # Always include manifest first
        manifest = ext_dir / "manifest.json"
        if manifest.exists():
            mf_text = manifest.read_text(encoding="utf-8", errors="replace")
            parts.append(f"=== manifest.json ===\n{mf_text}")
            total_size += len(mf_text)

        # Walk and collect relevant files
        extensions = {".js", ".ts", ".jsx", ".tsx", ".json", ".html", ".htm"}
        skip_dirs = {"node_modules", ".git", "__pycache__", "vendor", "_metadata"}

        for root, dirs, files in os.walk(ext_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in sorted(files):
                fpath = Path(root) / fname
                if fpath.suffix.lower() not in extensions:
                    continue
                if fpath == manifest:
                    continue  # already included
                try:
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                if total_size + len(text) > MAX_CONTENT_BYTES:
                    parts.append(
                        f"\n=== {fpath.relative_to(ext_dir)} === [SKIPPED — size limit reached]"
                    )
                    continue
                rel = fpath.relative_to(ext_dir)
                parts.append(f"=== {rel} ===\n{text}")
                total_size += len(text)

        content = "\n\n".join(parts)
        return GEMINI_ANALYSIS_PROMPT.format(
            file_type="browser extension source",
            content=content,
            file_type_specific_instructions=EXTENSION_INSTRUCTIONS,
        )

    def format_source_repo(self, path: str) -> str:
        """Read source repository and wrap key files in analysis prompt.

        Walks the directory, prioritises config/auth/route files, and
        concatenates with file markers.
        """
        repo_dir = Path(path)
        if not repo_dir.is_dir():
            raise NotADirectoryError(f"Repo dir not found: {path}")

        # Priority files to include first
        priority_patterns = [
            "*.env*", "*.config.*", "Dockerfile*", "docker-compose*",
            "*auth*", "*login*", "*session*", "*middleware*", "*route*",
            "*api*", "*secret*", "*credential*", "*token*",
        ]

        parts = []
        total_size = 0
        included = set()

        source_exts = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java",
            ".php", ".rs", ".clj", ".cljs", ".yml", ".yaml", ".json",
            ".toml", ".env", ".cfg", ".ini", ".conf", ".xml",
        }
        skip_dirs = {
            "node_modules", ".git", "__pycache__", "vendor", "dist",
            "build", ".next", ".cache", "coverage", "venv", ".venv",
        }

        # Collect all candidate files
        candidates = []
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in sorted(files):
                fpath = Path(root) / fname
                if fpath.suffix.lower() in source_exts or fname.startswith(".env"):
                    candidates.append(fpath)

        # Sort: priority-matching files first, then alphabetically
        def is_priority(fp: Path) -> bool:
            name_lower = fp.name.lower()
            stem_lower = fp.stem.lower()
            keywords = [
                "auth", "login", "session", "middleware", "route", "api",
                "secret", "credential", "token", "config", "env",
                "docker", "compose",
            ]
            return any(kw in name_lower or kw in stem_lower for kw in keywords)

        candidates.sort(key=lambda fp: (0 if is_priority(fp) else 1, str(fp)))

        for fpath in candidates:
            if fpath in included:
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            if total_size + len(text) > MAX_CONTENT_BYTES:
                parts.append(
                    f"\n=== {fpath.relative_to(repo_dir)} === [SKIPPED — size limit reached]"
                )
                continue
            rel = fpath.relative_to(repo_dir)
            parts.append(f"=== {rel} ===\n{text}")
            total_size += len(text)
            included.add(fpath)

        content = "\n\n".join(parts)
        return GEMINI_ANALYSIS_PROMPT.format(
            file_type="source code repository",
            content=content,
            file_type_specific_instructions=SOURCE_REPO_INSTRUCTIONS,
        )

    # --- Response Parsing ---

    @staticmethod
    def parse_gemini_output(json_str: str) -> dict:
        """Validate Gemini's JSON response.

        Handles markdown code fences, extracts the JSON object,
        validates the expected schema keys.

        Returns:
            Parsed dict with keys: endpoints, secrets, attack_vectors.

        Raises:
            ValueError: If JSON is invalid or schema doesn't match.
        """
        text = json_str.strip()

        # Strip markdown code fences (```json ... ``` or ``` ... ```)
        fence_pattern = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?\s*```$", re.DOTALL)
        m = fence_pattern.search(text)
        if m:
            text = m.group(1).strip()

        # Try to extract JSON object if there's surrounding text
        if not text.startswith("{"):
            start = text.find("{")
            if start == -1:
                raise ValueError("No JSON object found in Gemini output")
            # Find matching closing brace
            depth = 0
            end = -1
            for i in range(start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            if end == -1:
                raise ValueError("Unmatched braces in Gemini output")
            text = text[start:end]

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON from Gemini: {e}") from e

        if not isinstance(data, dict):
            raise ValueError(f"Expected JSON object, got {type(data).__name__}")

        # Validate top-level keys
        expected_keys = {"endpoints", "secrets", "attack_vectors"}
        for key in expected_keys:
            if key not in data:
                data[key] = []  # tolerate missing keys, default to empty
            if not isinstance(data[key], list):
                raise ValueError(f"Expected list for key '{key}', got {type(data[key]).__name__}")

        # Validate endpoint entries
        for i, ep in enumerate(data["endpoints"]):
            if not isinstance(ep, dict):
                raise ValueError(f"endpoints[{i}]: expected object, got {type(ep).__name__}")
            if "url" not in ep:
                raise ValueError(f"endpoints[{i}]: missing required field 'url'")

        # Validate secret entries
        for i, sec in enumerate(data["secrets"]):
            if not isinstance(sec, dict):
                raise ValueError(f"secrets[{i}]: expected object, got {type(sec).__name__}")
            if "type" not in sec:
                raise ValueError(f"secrets[{i}]: missing required field 'type'")

        # Validate attack_vector entries
        for i, vec in enumerate(data["attack_vectors"]):
            if not isinstance(vec, dict):
                raise ValueError(f"attack_vectors[{i}]: expected object, got {type(vec).__name__}")
            if "type" not in vec:
                raise ValueError(f"attack_vectors[{i}]: missing required field 'type'")

        return data

    # --- State Merging ---

    def merge_into_state(self, gemini_findings: dict) -> dict:
        """Merge Gemini findings into attack state.

        All entries are tagged E3 (source-code-only, unverified).

        Returns:
            Dict with merge statistics.
        """
        stats = {
            "endpoints_added": 0,
            "secrets_added": 0,
            "vectors_added": 0,
            "duplicates_skipped": 0,
        }

        # Merge endpoints
        for ep in gemini_findings.get("endpoints", []):
            url = ep.get("url", "").strip()
            if not url:
                stats["duplicates_skipped"] += 1
                continue
            if url in self.state.discovered_endpoints:
                stats["duplicates_skipped"] += 1
                continue
            params = ep.get("params")
            if isinstance(params, list):
                # AttackState.add_endpoint expects dict for params; convert list to dict
                params = {p: "" for p in params if isinstance(p, str)}
            self.state.add_endpoint(
                url=url,
                method=ep.get("method", "GET"),
                params=params,
                notes=f"[Gemini] auth={ep.get('auth', '?')} | {ep.get('reason', '')}",
            )
            stats["endpoints_added"] += 1

        # Merge secrets as E3 findings
        for secret in gemini_findings.get("secrets", []):
            sec_type = secret.get("type", "unknown")
            context = secret.get("context", "unknown")
            value = secret.get("value", "???")
            confidence = secret.get("confidence", "low")

            self.state.add_finding(
                title=f"Potential {sec_type}: {context}",
                severity="medium" if confidence == "high" else "low",
                exploitation_level="E3",
                description=f"Gemini found potential {sec_type} in {context} (confidence: {confidence})",
                evidence=f"Value: {value[:20]}..." if len(value) > 20 else f"Value: {value}",
            )
            stats["secrets_added"] += 1

        # Merge attack vectors as leads (check for duplicates against eliminated)
        eliminated_keys = {v["vector"] for v in self.state.eliminated_vectors}
        for vector in gemini_findings.get("attack_vectors", []):
            vec_type = vector.get("type", "unknown")
            vec_target = vector.get("target", "unknown")
            desc = f"{vec_type}: {vec_target}"

            if desc in eliminated_keys:
                stats["duplicates_skipped"] += 1
                continue

            # Also check existing promising_leads to avoid duplicates
            existing_leads = {l["description"] for l in self.state.promising_leads}
            if desc in existing_leads:
                stats["duplicates_skipped"] += 1
                continue

            confidence = vector.get("confidence", "low")
            priority = 2 if confidence == "high" else (3 if confidence == "medium" else 4)
            evidence = vector.get("evidence", "")

            self.state.add_lead(
                description=desc,
                priority=priority,
                notes=f"Gemini ({confidence}): {evidence}",
            )
            stats["vectors_added"] += 1

        self.state.save()
        return stats

    # --- Export ---

    def export_state_prompt(self) -> str:
        """Export current attack state as a Gemini analysis prompt."""
        return self.state.export_for_gemini()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SHADOW Gemini Bridge — prompt generator and response parser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Export attack state for Gemini review\n"
            "  python3 C_gemini_bridge.py --export superhuman\n\n"
            "  # Generate JS bundle analysis prompt\n"
            "  python3 C_gemini_bridge.py --export superhuman --js-bundle /tmp/entry.js\n\n"
            "  # Generate API spec analysis prompt\n"
            "  python3 C_gemini_bridge.py --export superhuman --api-spec openapi.json\n\n"
            "  # Generate browser extension analysis prompt\n"
            "  python3 C_gemini_bridge.py --export superhuman --extension-dir /tmp/ext/\n\n"
            "  # Generate source repo analysis prompt\n"
            "  python3 C_gemini_bridge.py --export superhuman --source-repo /tmp/repo/\n\n"
            "  # Import Gemini JSON response into attack state\n"
            "  python3 C_gemini_bridge.py --import-findings superhuman --gemini-output response.json\n"
        ),
    )

    # Mode: export or import
    parser.add_argument(
        "--export", metavar="TARGET",
        help="Export prompt for Gemini (target name)",
    )
    parser.add_argument(
        "--import-findings", metavar="TARGET",
        help="Import Gemini JSON output into attack state (target name)",
    )

    # Export sub-options
    parser.add_argument("--js-bundle", metavar="PATH", help="Path to JS bundle file")
    parser.add_argument("--api-spec", metavar="PATH", help="Path to OpenAPI/Swagger spec")
    parser.add_argument("--extension-dir", metavar="PATH", help="Path to browser extension directory")
    parser.add_argument("--source-repo", metavar="PATH", help="Path to source code repository")

    # Import sub-options
    parser.add_argument(
        "--gemini-output", metavar="PATH",
        help="Path to file containing Gemini's JSON response",
    )

    args = parser.parse_args()

    # ---- Export mode ----
    if args.export:
        bridge = GeminiBridge(args.export)

        if args.js_bundle:
            prompt = bridge.format_js_bundle(args.js_bundle)
        elif args.api_spec:
            prompt = bridge.format_api_spec(args.api_spec)
        elif args.extension_dir:
            prompt = bridge.format_extension_source(args.extension_dir)
        elif args.source_repo:
            prompt = bridge.format_source_repo(args.source_repo)
        else:
            # Default: export attack state for Gemini review
            prompt = bridge.export_state_prompt()

        print(prompt)
        # Also report size for convenience
        print(
            f"\n--- Prompt size: {len(prompt):,} chars (~{len(prompt) // 4:,} tokens) ---",
            file=sys.stderr,
        )

    # ---- Import mode ----
    elif args.import_findings:
        if not args.gemini_output:
            print("[!] --gemini-output is required with --import-findings", file=sys.stderr)
            sys.exit(1)

        output_path = Path(args.gemini_output)
        if not output_path.exists():
            print(f"[!] File not found: {args.gemini_output}", file=sys.stderr)
            sys.exit(1)

        raw = output_path.read_text(encoding="utf-8", errors="replace")
        bridge = GeminiBridge(args.import_findings)

        try:
            findings = bridge.parse_gemini_output(raw)
        except ValueError as e:
            print(f"[!] Failed to parse Gemini output: {e}", file=sys.stderr)
            sys.exit(1)

        stats = bridge.merge_into_state(findings)

        print(f"=== Gemini Import Results ({args.import_findings}) ===")
        print(f"  Endpoints added:    {stats['endpoints_added']}")
        print(f"  Secrets added (E3): {stats['secrets_added']}")
        print(f"  Vectors added:      {stats['vectors_added']}")
        print(f"  Duplicates skipped: {stats['duplicates_skipped']}")
        print(f"  State saved to: {bridge.state.save()}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

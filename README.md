# SHADOW Bug Bounty Framework

A modular, automated security testing framework that orchestrates Kali Linux tools with custom Python modules across a five-phase methodology — from reconnaissance through exploitation and reporting.

> **For authorized security testing only.** Always obtain explicit written permission before testing any target.

---

## Features

- **Single entry point** — one command replaces 15+ bash tool chains
- **Kali-first routing** — prefers native Kali tools (nmap, subfinder, nuclei, sqlmap, ffuf, etc.) with automatic Python fallback
- **Persistent state** — tracks subdomains, endpoints, findings, and tested vectors across sessions
- **Exploitation level rating** — every finding rated E1–E4 based on proof quality, not guesswork
- **Gemini integration** — bulk analysis of large JS bundles, API specs, and source code
- **Unified output** — all tools normalize to the same JSON schema regardless of source

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Full scan (recon + discovery + testing)
python3 C_quickstart.py --target example.com --mode full

# Recon only
python3 C_quickstart.py --target example.com --mode recon

# Targeted testing with specific vectors
python3 C_quickstart.py --target example.com --mode hunt --vector xss,ssrf,idor,sqli

# Resume a previous session (CTF/iterative mode)
python3 C_quickstart.py --target example.com --mode ctf --resume

# With proxy (Burp/Caido)
python3 C_quickstart.py --target example.com --mode full --proxy http://127.0.0.1:8080

# With authentication
python3 C_quickstart.py --target example.com --mode test --auth-cookie "session=abc123"
```

---

## Modes

| Mode | Description |
|------|-------------|
| `full` | All phases: recon + discovery + testing |
| `recon` | Phase 1 only — subdomain enum, port scan, tech fingerprinting |
| `discover` | Phase 2 only — JS analysis, directory brute force, parameter discovery |
| `test` | Phase 3 only — vulnerability testing with all vectors |
| `hunt` | Targeted testing with specific vectors (`--vector` flag) |
| `ctf` | Iterative mode with persistent state, loads/resumes previous sessions |

**Available vectors:** `xss`, `ssrf`, `idor`, `sqli`, `jwt`, `csrf`, `file_upload`, `business_logic`, `ssti`, `xxe`, `cmdi`

---

## Architecture

```
shadow-bounty/
├── C_quickstart.py              # Primary entry point
├── cli.py                       # Alternative CLI (shadow scan/recon/test/module)
├── orchestrator.py              # Pipeline engine
├── C_attack_state.py            # Persistent state tracker
├── C_gemini_bridge.py           # Gemini bulk analysis integration
│
├── core/                        # Shared utilities
│   ├── http_client.py           # Async HTTP with retry, proxy, UA rotation
│   ├── payload_manager.py       # Payload templates for injection tests
│   ├── response_analyzer.py     # Vulnerability indicator detection
│   ├── result_manager.py        # Finding aggregation and severity classification
│   └── session_manager.py       # Session and auth management
│
├── C_wrappers/                  # Kali tool wrappers (unified JSON output)
│   ├── C_tool_router.py         # Central routing engine with fallback chains
│   ├── C_scan_subdomains.py     # subfinder / amass / crt.sh
│   ├── C_scan_ports.py          # nmap / naabu / Python sockets
│   ├── C_bruteforce_dirs.py     # ffuf / gobuster / dirb
│   ├── C_test_sqli.py           # sqlmap / Python
│   ├── C_test_xss.py            # nuclei / Python
│   ├── C_scan_vulns.py          # nuclei / nikto
│   ├── C_discover_params.py     # ffuf param mode / Python
│   └── C_fingerprint.py         # whatweb / wafw00f / Python
│
├── C_unified-exploits/          # Coordinated exploit suites
│   ├── C_injection_suite.py     # SQLi + XSS + SSTI + XXE + CMDi
│   ├── C_auth_suite.py          # JWT + login bypass + session + pw reset
│   ├── C_access_suite.py        # IDOR + access control + privilege escalation
│   └── C_api_suite.py           # GraphQL + OAuth + OpenAPI + REST
│
├── phase1_recon/                # Subdomain enum, port scan, tech fingerprint, DNS, certs, wayback
├── phase2_discovery/            # JS analysis, dir brute, params, API/GraphQL/OpenAPI, admin panels
├── phase3_testing/              # Injection, access control, auth, SSRF, CSRF, file upload, race conditions
├── phase4_exploitation/         # Vulnerability chaining, evidence collection, PoC generation
├── phase5_reporting/            # Finding aggregation, markdown/JSON reports
│
└── config/
    ├── default_config.yaml      # All tunable settings (proxy, rate limits, wordlists, payloads)
    ├── payloads/                # sqli / xss / ssrf / ssti / xxe payload lists
    └── wordlists/               # directories / parameters / subdomains
```

---

## Persistent State (CTF/Iterative Mode)

`C_attack_state.py` maintains attack context across sessions:

```bash
# Load state for a target
python3 C_attack_state.py --load example.com

# View stats and top untested leads
python3 C_attack_state.py --stats example.com
```

Tracks:
- Discovered subdomains and endpoints
- Tested vectors with outcomes (`eliminated` / `promising` / `exploited`)
- Findings with exploitation level ratings (E1–E4)
- Authentication tokens and session data
- Session history and notes

---

## Exploitation Level Ratings

Every finding is rated before reporting:

| Level | Label | Evidence Required |
|-------|-------|------------------|
| **E1** | Proven Exploitation | Actual data accessed, code executed, auth bypassed |
| **E2** | Confirmed Behavior | Server responds as expected, behavior is the vulnerability |
| **E3** | Source Code Only | Visible in frontend/source, backend not yet tested |
| **E4** | Theoretical | Inferred from indirect signals |

Only E1 and E2 are submittable to bug bounty programs.

---

## Gemini Integration

For large files that would exhaust Claude's context window:

```bash
# Package target files and generate analysis prompt
python3 C_gemini_bridge.py --export example.com

# Import Gemini findings back into attack state
python3 C_gemini_bridge.py --import example.com --gemini-output findings.json
```

Useful for: JS bundles >100KB, API specs with 50+ endpoints, decompiled APKs, browser extensions.

All Gemini findings are imported as **E3** (unverified) and require live testing.

---

## Alternative CLI

```bash
# Granular control via cli.py
python3 cli.py scan -t example.com
python3 cli.py recon -t example.com
python3 cli.py module sqli -t example.com
python3 cli.py list                         # list all available modules
```

Available modules: `subdomain`, `ports`, `tech`, `certs`, `wayback`, `dns`, `js`, `dirs`, `params`, `api`, `graphql`, `openapi`, `sqli`, `xss`, `xxe`, `ssti`, `cmdi`, `ssrf`, `csrf`, `idor`, `privesc`, `jwt`, `login`, `session`, `pwreset`, `race`, `upload`, `bizlogic`

---

## Requirements

- Python 3.10+
- Kali Linux (recommended) with standard bug bounty toolkit
- `pip install -r requirements.txt`

Key Kali tools used (framework falls back to Python if not present): `nmap`, `subfinder`, `amass`, `nuclei`, `ffuf`, `gobuster`, `sqlmap`, `whatweb`, `wafw00f`, `naabu`, `nikto`

---

## Output

Results are written to:
```
targets/<target-name>/
├── C_findings/          # Vulnerability findings (JSON)
├── C_recon/             # Reconnaissance data
└── C_session_state.json # Persistent attack state
```

Reports generated by Phase 5:
- `shadow_report_<domain>.md` — human-readable markdown
- `shadow_summary_<domain>.json` — machine-readable summary

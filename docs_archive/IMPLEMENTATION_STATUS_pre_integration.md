# SHADOW Bug Bounty Framework - Implementation Status

**Last Updated:** 2026-02-05
**Location:** `/home/huntersreeni/Documents/personal/Red_Teamer/SHADOW/shadow-bounty/`

---

## ✅ COMPLETED PHASES

### Phase A: Core Foundation
| File | Purpose | Status |
|------|---------|--------|
| `core/__init__.py` | Module exports | ✅ Done |
| `core/http_client.py` | Async HTTP (rate limiting, proxy, retries, batch) | ✅ Done |
| `core/result_manager.py` | JSON/Markdown output (Finding, ScanResult, Severity) | ✅ Done |
| `core/payload_manager.py` | Payload loading, 15+ encodings, built-in payloads | ✅ Done |
| `core/response_analyzer.py` | SQL/XSS/SSTI/path traversal detection, diff analysis | ✅ Done |
| `core/session_manager.py` | Cookie/auth handling (Bearer, Basic, API Key) | ✅ Done |
| `core/utils.py` | 25+ utility functions | ✅ Done |
| `config/default_config.yaml` | Full configuration template | ✅ Done |
| `requirements.txt` | All Python dependencies | ✅ Done |

**Payload Files Created:**
- `config/payloads/sqli/payloads.txt` (70+ payloads)
- `config/payloads/xss/payloads.txt` (60+ payloads)
- `config/payloads/ssrf/payloads.txt` (60+ payloads)
- `config/payloads/xxe/payloads.txt` (20+ payloads)
- `config/payloads/ssti/payloads.txt` (50+ payloads)

**Wordlists Created:**
- `config/wordlists/directories.txt`
- `config/wordlists/parameters.txt`
- `config/wordlists/subdomains.txt`

---

### Phase B: Recon Suite
| File | Purpose | Status |
|------|---------|--------|
| `phase1_recon/__init__.py` | Module exports | ✅ Done |
| `phase1_recon/subdomain_enum.py` | Subdomain discovery (crt.sh, APIs, tools) | ✅ Done |
| `phase1_recon/port_scanner.py` | Port scanning (async TCP, nmap wrapper) | ✅ Done |
| `phase1_recon/tech_fingerprint.py` | Technology detection (40+ signatures) | ✅ Done |
| `phase1_recon/cert_transparency.py` | CT log parsing (crt.sh, certspotter) | ✅ Done |
| `phase1_recon/wayback_extractor.py` | Historical URLs (Wayback, Common Crawl) | ✅ Done |
| `phase1_recon/dns_enum.py` | DNS records, zone transfer, SPF/DMARC analysis | ✅ Done |
| `phase1_recon/subdomain_prober.py` | **NEW** Async subdomain probing with SSRF header testing | ✅ Done |

**New Features (subdomain_prober.py):**
- 100+ common subdomain prefixes (api, dev, staging, admin, etc.)
- Async parallel probing for speed (configurable threads)
- Response fingerprinting (status, title, server, technologies)
- SSRF header testing on discovered subdomains (X-Forwarded-For, etc.)
- Technology detection from response headers and body
- JSON output with all discovered subdomains and characteristics

---

### Phase C: Discovery Suite
| File | Purpose | Status |
|------|---------|--------|
| `phase2_discovery/__init__.py` | Module exports | ✅ Done |
| `phase2_discovery/js_analyzer.py` | JS bundle analysis (endpoints, secrets, API keys) - **ENHANCED** | ✅ Done |
| `phase2_discovery/directory_bruteforce.py` | Dir/file discovery (ffuf wrapper + native) | ✅ Done |
| `phase2_discovery/parameter_discovery.py` | Hidden param mining (Arjun wrapper + native) | ✅ Done |
| `phase2_discovery/api_endpoint_extractor.py` | API enumeration from JS/HTML/robots/sitemap | ✅ Done |
| `phase2_discovery/graphql_introspect.py` | GraphQL schema introspection & security analysis | ✅ Done |
| `phase2_discovery/openapi_discovery.py` | Swagger/OpenAPI finder & security analysis | ✅ Done |
| `phase2_discovery/oauth_discovery.py` | **NEW** OAuth endpoint discovery and testing | ✅ Done |
| `phase2_discovery/framework_fingerprinter.py` | **NEW** Web framework detection and path testing | ✅ Done |
| `phase2_discovery/admin_panel_detector.py` | **NEW** Admin panel detection and analysis | ✅ Done |

**Features Implemented:**
- **JS Analyzer** (ENHANCED): 30+ endpoint patterns, admin route detection, auth pattern detection, hardcoded URL extraction, fetch/axios/jQuery patterns
- **Directory Bruteforce**: ffuf integration, smart filtering, recursive scanning
- **Parameter Discovery**: Response comparison, header fuzzing, JSON body testing
- **API Extractor**: Multi-source discovery (JS, HTML, robots, sitemap, probing)
- **GraphQL**: Full introspection, security checks, SDL generation
- **OpenAPI**: Swagger 2.0 & OpenAPI 3.x, security scheme analysis
- **OAuth Discovery** (NEW): .well-known config, token/authorize/revoke endpoints, grant type testing, client enumeration, Basic Auth testing
- **Framework Fingerprinter** (NEW): Rails/Django/Express/Laravel/Spring Boot/ASP.NET detection, framework-specific path testing, sensitive endpoint discovery
- **Admin Panel Detector** (NEW): 60+ admin paths, panel type detection, CSRF token extraction, registration endpoint discovery, optional credential testing

---

### Phase D: Vulnerability Testing
| File | Purpose | Status |
|------|---------|--------|
| `phase3_testing/__init__.py` | Module exports | ✅ Done |
| `phase3_testing/injection/__init__.py` | Injection module exports | ✅ Done |
| `phase3_testing/access/__init__.py` | Access control module exports | ✅ Done |
| `phase3_testing/auth/__init__.py` | Auth module exports | ✅ Done |
| `phase3_testing/injection/sqli_tester.py` | SQL injection (error, time, boolean, union, DB fingerprint) | ✅ Done |
| `phase3_testing/injection/xss_tester.py` | XSS (reflected, DOM, context-aware, filter bypass) | ✅ Done |
| `phase3_testing/injection/xxe_tester.py` | XXE (file disclosure, SSRF, blind XXE) | ✅ Done |
| `phase3_testing/injection/ssti_tester.py` | SSTI (Jinja2, Twig, Freemarker, etc.) | ✅ Done |
| `phase3_testing/injection/command_injection.py` | Command injection (Linux/Windows) | ✅ Done |
| `phase3_testing/access/idor_tester.py` | IDOR (numeric, UUID, response comparison) | ✅ Done |
| `phase3_testing/access/privilege_escalation.py` | Vertical/horizontal privilege escalation | ✅ Done |
| `phase3_testing/access/access_control.py` | Forced browsing, method override, unauth access | ✅ Done |
| `phase3_testing/auth/jwt_tester.py` | JWT (none algo, weak secrets, algo confusion) | ✅ Done |
| `phase3_testing/auth/login_bypass.py` | SQL bypass, default creds, header bypass | ✅ Done |
| `phase3_testing/auth/session_tester.py` | Session fixation, entropy, cookie flags | ✅ Done |
| `phase3_testing/auth/password_reset.py` | Host injection, token exposure, enumeration | ✅ Done |
| `phase3_testing/ssrf_tester.py` | SSRF (internal, cloud metadata, protocols, **header-based**) - **ENHANCED** | ✅ Done |
| `phase3_testing/csrf_tester.py` | CSRF (missing token, bypass, header validation) | ✅ Done |
| `phase3_testing/race_condition.py` | Race conditions (parallel requests, TOCTOU) | ✅ Done |
| `phase3_testing/file_upload.py` | File upload (ext bypass, polyglot, path traversal) | ✅ Done |
| `phase3_testing/business_logic.py` | Business logic (price/qty manipulation, workflow) | ✅ Done |

**Features Implemented:**
- **SQLi Tester**: Error-based, time-based, boolean-based, union-based; DB fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **XSS Tester**: Context-aware payloads, DOM XSS detection, filter bypass techniques
- **XXE Tester**: File disclosure, SSRF via XXE, blind XXE with OOB
- **SSTI Tester**: Multi-engine detection (Jinja2, Twig, Freemarker, Velocity, Smarty, Mako)
- **Command Injection**: Linux/Windows payloads, time-based detection
- **IDOR Tester**: Numeric/UUID manipulation, response comparison
- **JWT Tester**: None algorithm, weak secret bruteforce, algorithm confusion (RS256→HS256)
- **Login Bypass**: SQL injection, default credentials, header-based bypass
- **Session Tester**: Cookie security flags, entropy analysis, fixation testing
- **Password Reset**: Host header injection, email manipulation, token exposure
- **SSRF Tester** (ENHANCED): Internal networks, cloud metadata (AWS/GCP/Azure), protocol handlers, **header-based SSRF testing** (X-Forwarded-For, X-Forwarded-Host, X-Real-IP, etc.), response behavior analysis, OOB callback testing
- **CSRF Tester**: Token validation bypass, header-based protection testing
- **Race Condition**: Parallel request synchronization, double-spending detection
- **File Upload**: Extension bypass, content-type bypass, polyglot files, SVG XSS
- **Business Logic**: Price manipulation, quantity tampering, workflow bypass, status manipulation

---

### Phase F: Orchestration
| File | Purpose | Status |
|------|---------|--------|
| `orchestrator.py` | Pipeline runner (all phases coordinated) | ✅ Done |
| `cli.py` | Main CLI entry point with subcommands | ✅ Done |

**Features Implemented:**
- **Orchestrator**: Full pipeline coordination, phase control, module toggling, result aggregation
- **CLI**: `scan`, `recon`, `discover`, `test`, `module`, `list` subcommands
- **Report Generation**: JSON summary + Markdown report with findings by severity
- **Module System**: 27 modules available via CLI

---

## ❌ REMAINING PHASES

### Phase E: Exploitation & Reporting (Optional Enhancement)
| File | Purpose | Priority |
|------|---------|----------|
| `phase4_exploitation/__init__.py` | Module exports | P0 |
| `phase4_exploitation/poc_generator.py` | Generate curl/Python PoCs | P0 |
| `phase4_exploitation/evidence_collector.py` | Request/response storage | P0 |
| `phase4_exploitation/screenshot_capture.py` | Automated screenshots | P1 |
| `phase4_exploitation/chain_builder.py` | Document vuln chains | P2 |
| `phase5_reporting/__init__.py` | Module exports | P0 |
| `phase5_reporting/report_generator.py` | Advanced Markdown reports | P0 |
| `phase5_reporting/cvss_calculator.py` | CVSS 3.1 scoring | P0 |
| `phase5_reporting/deduplicator.py` | Finding deduplication | P1 |
| `phase5_reporting/templates/hackerone.md.j2` | HackerOne template | P0 |
| `phase5_reporting/templates/bugcrowd.md.j2` | Bugcrowd template | P1 |
| `phase5_reporting/templates/generic.md.j2` | Generic template | P0 |

*Note: Basic reporting is included in orchestrator.py. Phase E provides advanced features.*

---

## Directory Structure (Current)

```
shadow-bounty/
├── config/
│   ├── default_config.yaml       ✅
│   ├── payloads/
│   │   ├── sqli/payloads.txt     ✅
│   │   ├── xss/payloads.txt      ✅
│   │   ├── ssrf/payloads.txt     ✅
│   │   ├── xxe/payloads.txt      ✅
│   │   └── ssti/payloads.txt     ✅
│   └── wordlists/
│       ├── directories.txt       ✅
│       ├── parameters.txt        ✅
│       └── subdomains.txt        ✅
├── core/
│   ├── __init__.py               ✅
│   ├── http_client.py            ✅
│   ├── payload_manager.py        ✅
│   ├── response_analyzer.py      ✅
│   ├── result_manager.py         ✅
│   ├── session_manager.py        ✅
│   └── utils.py                  ✅
├── phase1_recon/
│   ├── __init__.py               ✅
│   ├── cert_transparency.py      ✅
│   ├── dns_enum.py               ✅
│   ├── port_scanner.py           ✅
│   ├── subdomain_enum.py         ✅
│   ├── subdomain_prober.py       ✅ NEW
│   ├── tech_fingerprint.py       ✅
│   └── wayback_extractor.py      ✅
├── phase2_discovery/
│   ├── __init__.py               ✅
│   ├── js_analyzer.py            ✅ ENHANCED
│   ├── directory_bruteforce.py   ✅
│   ├── parameter_discovery.py    ✅
│   ├── api_endpoint_extractor.py ✅
│   ├── graphql_introspect.py     ✅
│   ├── openapi_discovery.py      ✅
│   ├── oauth_discovery.py        ✅ NEW
│   ├── framework_fingerprinter.py ✅ NEW
│   └── admin_panel_detector.py   ✅ NEW
├── phase3_testing/
│   ├── __init__.py               ✅
│   ├── ssrf_tester.py            ✅ ENHANCED
│   ├── csrf_tester.py            ✅
│   ├── race_condition.py         ✅
│   ├── file_upload.py            ✅
│   ├── business_logic.py         ✅
│   ├── injection/
│   │   ├── __init__.py           ✅
│   │   ├── sqli_tester.py        ✅
│   │   ├── xss_tester.py         ✅
│   │   ├── xxe_tester.py         ✅
│   │   ├── ssti_tester.py        ✅
│   │   └── command_injection.py  ✅
│   ├── access/
│   │   ├── __init__.py           ✅
│   │   ├── idor_tester.py        ✅
│   │   ├── privilege_escalation.py ✅
│   │   └── access_control.py     ✅
│   └── auth/
│       ├── __init__.py           ✅
│       ├── jwt_tester.py         ✅
│       ├── login_bypass.py       ✅
│       ├── session_tester.py     ✅
│       └── password_reset.py     ✅
├── phase4_exploitation/          ❌ (empty - optional)
├── phase5_reporting/
│   └── templates/                ❌ (empty - optional)
├── orchestrator.py               ✅
├── cli.py                        ✅
├── requirements.txt              ✅
└── IMPLEMENTATION_STATUS.md      ✅ (this file)
```

---

## CLI Usage Examples (Completed Modules)

### Phase 1: Recon Suite

```bash
# Subdomain Enumeration
python phase1_recon/subdomain_enum.py --target example.com --output results/

# Subdomain Probing (NEW)
python phase1_recon/subdomain_prober.py -d example.com -o results/
python phase1_recon/subdomain_prober.py -d example.com -o results/ --threads 100
python phase1_recon/subdomain_prober.py -d example.com -o results/ --no-ssrf  # Skip SSRF header testing
python phase1_recon/subdomain_prober.py -d example.com -o results/ --prefixes "custom,extra,test"

# Port Scanning
python phase1_recon/port_scanner.py --target example.com --output results/ --ports top-1000

# Technology Fingerprinting
python phase1_recon/tech_fingerprint.py --target https://example.com --output results/

# Certificate Transparency
python phase1_recon/cert_transparency.py --target example.com --output results/

# Wayback Extraction
python phase1_recon/wayback_extractor.py --target example.com --output results/ --limit 5000

# DNS Enumeration
python phase1_recon/dns_enum.py --target example.com --output results/
```

### Phase 2: Discovery Suite

```bash
# JavaScript Analysis (ENHANCED - deep extraction)
python phase2_discovery/js_analyzer.py --target https://example.com --output results/
python phase2_discovery/js_analyzer.py --target https://example.com --output results/ --deep-extract

# OAuth Discovery (NEW)
python phase2_discovery/oauth_discovery.py -t https://api.example.com -o results/
python phase2_discovery/oauth_discovery.py -t https://example.com -o results/ --threads 20

# Framework Fingerprinting (NEW)
python phase2_discovery/framework_fingerprinter.py -t https://example.com -o results/
python phase2_discovery/framework_fingerprinter.py -t https://example.com -o results/ --threads 30

# Admin Panel Detection (NEW)
python phase2_discovery/admin_panel_detector.py -t https://example.com -o results/
python phase2_discovery/admin_panel_detector.py -t https://example.com -o results/ --test-creds

# Directory Brute Force
python phase2_discovery/directory_bruteforce.py --target https://example.com --output results/ \
  --wordlist config/wordlists/directories.txt --extensions ".php,.asp" --recursive

# Parameter Discovery
python phase2_discovery/parameter_discovery.py --target https://example.com/page --output results/

# API Endpoint Extraction
python phase2_discovery/api_endpoint_extractor.py --target https://example.com --output results/

# GraphQL Introspection
python phase2_discovery/graphql_introspect.py --target https://example.com/graphql --output results/

# OpenAPI Discovery
python phase2_discovery/openapi_discovery.py --target https://example.com --output results/
```

### Phase 3: Vulnerability Testing

```bash
# SQL Injection
python phase3_testing/injection/sqli_tester.py --target https://example.com/search?q=test --output results/

# XSS Testing
python phase3_testing/injection/xss_tester.py --target https://example.com/search --output results/

# XXE Testing
python phase3_testing/injection/xxe_tester.py --target https://example.com/api/xml --output results/

# SSTI Testing
python phase3_testing/injection/ssti_tester.py --target https://example.com/template --output results/

# Command Injection
python phase3_testing/injection/command_injection.py --target https://example.com/ping --output results/

# IDOR Testing
python phase3_testing/access/idor_tester.py --target https://example.com/api/user/123 --output results/

# Privilege Escalation
python phase3_testing/access/privilege_escalation.py --target https://example.com/api --output results/ \
  --user-token "eyJ..."

# Access Control
python phase3_testing/access/access_control.py --target https://example.com/api --output results/

# JWT Testing
python phase3_testing/auth/jwt_tester.py --target https://example.com/api --token "eyJ..." --output results/

# Login Bypass
python phase3_testing/auth/login_bypass.py --target https://example.com/login --output results/

# Session Testing
python phase3_testing/auth/session_tester.py --target https://example.com --output results/

# Password Reset Testing
python phase3_testing/auth/password_reset.py --target https://example.com/forgot-password --output results/

# SSRF Testing (ENHANCED - with header-based SSRF)
python phase3_testing/ssrf_tester.py --target https://example.com/fetch?url= --output results/
python phase3_testing/ssrf_tester.py --target https://example.com/api --output results/ --header-ssrf
python phase3_testing/ssrf_tester.py --target https://example.com/api --output results/ --header-ssrf --oob-server http://your-oob-server.com

# CSRF Testing
python phase3_testing/csrf_tester.py --target https://example.com --output results/ --auth-cookie "session=abc"

# Race Condition Testing
python phase3_testing/race_condition.py --target https://example.com/api/transfer --output results/ \
  --method POST --data '{"amount": 100}' --concurrent 20

# File Upload Testing
python phase3_testing/file_upload.py --target https://example.com/upload --output results/

# Business Logic Testing
python phase3_testing/business_logic.py --target https://example.com/api/checkout --output results/
```

---

## CLI Usage - Main Entry Point

```bash
# Show help
python cli.py --help

# Full scan
python cli.py scan -t example.com -o results/

# Recon only
python cli.py recon -t example.com -o results/

# Discovery only
python cli.py discover -t https://example.com -o results/

# Vulnerability testing only
python cli.py test -t https://example.com/api -o results/ --auth-cookie "session=abc"

# Run specific module
python cli.py module sqli -t "https://example.com/search?q=test" -o results/
python cli.py module xss -t https://example.com/search -o results/
python cli.py module subdomain -t example.com -o results/

# List all available modules
python cli.py list
```

---

## Next Session: Optional Phase E Enhancement

The framework is now **fully functional**. Phase E is optional for advanced features:
```
Continue implementing SHADOW Phase E for advanced PoC generation and report templates.
Read IMPLEMENTATION_STATUS.md for current progress.
```

---

## Progress Summary

| Phase | Status | Files |
|-------|--------|-------|
| A: Core Foundation | ✅ Complete | 17 files |
| B: Recon Suite | ✅ Complete | 8 files (+1 NEW) |
| C: Discovery Suite | ✅ Complete | 10 files (+3 NEW) |
| D: Vulnerability Testing | ✅ Complete | 21 files (1 ENHANCED) |
| E: Exploitation & Reporting | ⏸️ Optional | 0/12 files |
| F: Orchestration | ✅ Complete | 2 files |

**Core Framework: 100% complete (58 files)**
**With Optional Phase E: ~85% (58/70 files)**

### Recent Updates (2026-02-05)

| Module | Type | Description |
|--------|------|-------------|
| `subdomain_prober.py` | NEW | Async subdomain probing with SSRF header testing |
| `oauth_discovery.py` | NEW | OAuth endpoint discovery and grant type testing |
| `framework_fingerprinter.py` | NEW | Rails/Django/Express/Laravel/Spring detection |
| `admin_panel_detector.py` | NEW | Admin panel detection with CSRF/login analysis |
| `ssrf_tester.py` | ENHANCED | Header-based SSRF testing (X-Forwarded-*, Host, etc.) |
| `js_analyzer.py` | ENHANCED | Admin routes, auth patterns, hardcoded URL extraction |

## Quick Start

```bash
cd shadow-bounty/

# Install dependencies
pip install -r requirements.txt

# Run full scan
python cli.py scan -t example.com -o results/

# Or use orchestrator directly
python orchestrator.py -t example.com -o results/
```

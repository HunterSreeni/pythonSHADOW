# SHADOW Bug Bounty Framework - Usage Context

> **Purpose**: This document provides AI agents and humans with clear context on how to use each module in the SHADOW bug bounty framework.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
3. [Phase 2: Discovery](#phase-2-discovery)
4. [Phase 3: Vulnerability Testing](#phase-3-vulnerability-testing)
5. [Core Utilities](#core-utilities)
6. [Full Pipeline](#full-pipeline)

---

## Quick Start

```bash
# Navigate to framework directory
cd /home/huntersreeni/Documents/personal/Red_Teamer/SHADOW/shadow-bounty

# Activate virtual environment (if exists)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run full scan
python cli.py scan -t example.com -o results/
```

---

## Phase 1: Reconnaissance

### 1.1 Subdomain Prober

**File**: `phase1_recon/subdomain_prober.py`

**Purpose**: Probe common subdomains with async parallel requests, fingerprint responses, and test for SSRF-prone headers.

```bash
# Basic usage
python phase1_recon/subdomain_prober.py -d <domain> -o <output_dir>

# Full options
python phase1_recon/subdomain_prober.py \
  -d example.com \
  -o results/ \
  --threads 50 \
  --timeout 10 \
  --prefixes "custom,extra,internal" \
  --no-ssrf \
  -p http://127.0.0.1:8080 \
  -v
```

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --domain` | Target domain (required) | - |
| `-o, --output` | Output directory | `results` |
| `--threads` | Concurrent threads | `50` |
| `--timeout` | Request timeout (seconds) | `10` |
| `--prefixes` | Additional subdomain prefixes (comma-separated) | - |
| `--no-ssrf` | Skip SSRF header testing | `False` |
| `-p, --proxy` | Proxy URL | - |
| `-c, --config` | Config file path | - |
| `-v, --verbose` | Verbose output | `False` |

**Output Files**:
- `subdomain_probe_<domain>.json` - Full results
- `subdomains_<domain>.json` - Detailed subdomain data
- `subdomains_<domain>.txt` - Simple subdomain list

---

### 1.2 Subdomain Enumeration

**File**: `phase1_recon/subdomain_enum.py`

**Purpose**: Enumerate subdomains using multiple sources (crt.sh, APIs, DNS).

```bash
python phase1_recon/subdomain_enum.py --target example.com --output results/
```

| Flag | Description | Default |
|------|-------------|---------|
| `--target` | Target domain (required) | - |
| `--output` | Output directory | `results` |
| `--timeout` | Request timeout | `30` |
| `-v, --verbose` | Verbose output | `False` |

---

### 1.3 Port Scanner

**File**: `phase1_recon/port_scanner.py`

**Purpose**: Scan ports using async TCP or nmap wrapper.

```bash
# Basic scan
python phase1_recon/port_scanner.py --target example.com --output results/

# Full options
python phase1_recon/port_scanner.py \
  --target example.com \
  --output results/ \
  --ports top-1000 \
  --threads 100 \
  --timeout 5
```

| Flag | Description | Default |
|------|-------------|---------|
| `--target` | Target host (required) | - |
| `--output` | Output directory | `results` |
| `--ports` | Port range (`top-100`, `top-1000`, `1-65535`, or custom) | `top-1000` |
| `--threads` | Concurrent threads | `100` |
| `--timeout` | Connection timeout | `5` |

---

### 1.4 Technology Fingerprinter

**File**: `phase1_recon/tech_fingerprint.py`

**Purpose**: Detect technologies (40+ signatures) from headers, cookies, and response body.

```bash
python phase1_recon/tech_fingerprint.py --target https://example.com --output results/
```

---

### 1.5 Certificate Transparency

**File**: `phase1_recon/cert_transparency.py`

**Purpose**: Query CT logs (crt.sh, certspotter) for subdomains.

```bash
python phase1_recon/cert_transparency.py --target example.com --output results/
```

---

### 1.6 Wayback Extractor

**File**: `phase1_recon/wayback_extractor.py`

**Purpose**: Extract historical URLs from Wayback Machine and Common Crawl.

```bash
python phase1_recon/wayback_extractor.py \
  --target example.com \
  --output results/ \
  --limit 5000
```

---

### 1.7 DNS Enumeration

**File**: `phase1_recon/dns_enum.py`

**Purpose**: Enumerate DNS records, attempt zone transfer, analyze SPF/DMARC.

```bash
python phase1_recon/dns_enum.py --target example.com --output results/
```

---

## Phase 2: Discovery

### 2.1 OAuth Discovery

**File**: `phase2_discovery/oauth_discovery.py`

**Purpose**: Discover OAuth endpoints, test grant types, check .well-known configs, enumerate clients.

```bash
# Basic usage
python phase2_discovery/oauth_discovery.py -t <target_url> -o <output_dir>

# Full options
python phase2_discovery/oauth_discovery.py \
  -t https://api.example.com \
  -o results/ \
  --threads 10 \
  --timeout 30 \
  -p http://127.0.0.1:8080 \
  -v
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target URL (required) | - |
| `-o, --output` | Output directory | `results` |
| `--threads` | Concurrent threads | `10` |
| `--timeout` | Request timeout | `30` |
| `-p, --proxy` | Proxy URL | - |
| `-c, --config` | Config file path | - |
| `-v, --verbose` | Verbose output | `False` |

**Endpoints Tested**:
- `/oauth/token`, `/oauth/authorize`, `/oauth/revoke`
- `/.well-known/openid-configuration`
- `/.well-known/oauth-authorization-server`
- Token introspection, JWKS endpoints

**Grant Types Tested**:
- `client_credentials`, `password`, `authorization_code`
- `refresh_token`, `implicit`, `jwt-bearer`, `device_code`

---

### 2.2 Framework Fingerprinter

**File**: `phase2_discovery/framework_fingerprinter.py`

**Purpose**: Detect web frameworks (Rails, Django, Express, Laravel, Spring Boot, ASP.NET) and test framework-specific paths.

```bash
# Basic usage
python phase2_discovery/framework_fingerprinter.py -t <target_url> -o <output_dir>

# Full options
python phase2_discovery/framework_fingerprinter.py \
  -t https://example.com \
  -o results/ \
  --threads 20 \
  --timeout 30 \
  -v
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target URL (required) | - |
| `-o, --output` | Output directory | `results` |
| `--threads` | Concurrent threads | `20` |
| `--timeout` | Request timeout | `30` |
| `-p, --proxy` | Proxy URL | - |
| `-v, --verbose` | Verbose output | `False` |

**Frameworks Detected**:
- Ruby on Rails (`/rails/info`, `/sidekiq`, X-Runtime header)
- Django (`/admin/`, csrfmiddlewaretoken, `/__debug__/`)
- Express.js (X-Powered-By, `/api`, `/graphql`)
- Laravel (`/telescope`, `/horizon`, `/nova`)
- Spring Boot (`/actuator/*`, `/h2-console`)
- ASP.NET (ViewState, `/elmah.axd`, `/trace.axd`)
- WordPress (`/wp-admin`, `/wp-json`)
- Next.js (`/_next/static`, `__NEXT_DATA__`)

---

### 2.3 Admin Panel Detector

**File**: `phase2_discovery/admin_panel_detector.py`

**Purpose**: Detect admin panels, analyze login forms, extract CSRF tokens, find registration endpoints.

```bash
# Basic usage
python phase2_discovery/admin_panel_detector.py -t <target_url> -o <output_dir>

# With credential testing (use responsibly)
python phase2_discovery/admin_panel_detector.py \
  -t https://example.com \
  -o results/ \
  --test-creds \
  --threads 20
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target URL (required) | - |
| `-o, --output` | Output directory | `results` |
| `--threads` | Concurrent threads | `20` |
| `--timeout` | Request timeout | `30` |
| `--test-creds` | Test default credentials | `False` |
| `-p, --proxy` | Proxy URL | - |
| `-v, --verbose` | Verbose output | `False` |

**Paths Tested** (60+):
- `/admin`, `/administrator`, `/panel`, `/console`
- `/dashboard`, `/manage`, `/backend`, `/ops`
- `/wp-admin`, `/user/login`, CMS-specific paths

**Detection Features**:
- Panel type (Active Admin, Django Admin, WordPress, custom)
- Login form field extraction
- CSRF token detection
- Registration endpoint discovery

---

### 2.4 JavaScript Analyzer

**File**: `phase2_discovery/js_analyzer.py`

**Purpose**: Analyze JS bundles for endpoints, secrets, domains, admin routes, and auth patterns.

```bash
# Basic usage
python phase2_discovery/js_analyzer.py -t <target_url> -o <output_dir>

# Deep extraction mode
python phase2_discovery/js_analyzer.py \
  -t https://example.com \
  -o results/ \
  --deep-extract \
  --threads 20 \
  --depth 2
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target URL (required) | - |
| `-o, --output` | Output directory | `results` |
| `--threads` | Concurrent threads | `20` |
| `--timeout` | Request timeout | `30` |
| `--depth` | Crawl depth for JS discovery | `2` |
| `--deep-extract` | Enable admin/auth pattern extraction | `False` |
| `-p, --proxy` | Proxy URL | - |
| `-v, --verbose` | Verbose output | `False` |

**Extracts**:
- API endpoints (fetch, axios, jQuery patterns)
- Secrets (AWS keys, API keys, JWTs, database URLs)
- Admin/internal routes (`/admin/*`, `/internal/*`, `/_*`)
- Authentication patterns (Bearer tokens, localStorage)
- Hardcoded URLs and domains
- Source maps

**Output Files**:
- `js_analysis_<domain>.json` - Summary
- `js_analysis_<domain>_detailed.json` - Full data
- `endpoints_<domain>.txt` - Endpoint list
- `admin_routes_<domain>.txt` - Admin routes
- `api_endpoints_<domain>.txt` - API endpoints

---

### 2.5 Directory Bruteforce

**File**: `phase2_discovery/directory_bruteforce.py`

**Purpose**: Discover directories/files using wordlists (ffuf wrapper + native).

```bash
python phase2_discovery/directory_bruteforce.py \
  --target https://example.com \
  --output results/ \
  --wordlist config/wordlists/directories.txt \
  --extensions ".php,.asp,.aspx" \
  --recursive \
  --threads 50
```

---

### 2.6 Parameter Discovery

**File**: `phase2_discovery/parameter_discovery.py`

**Purpose**: Discover hidden parameters using response comparison.

```bash
python phase2_discovery/parameter_discovery.py \
  --target https://example.com/page \
  --output results/ \
  --wordlist config/wordlists/parameters.txt
```

---

### 2.7 API Endpoint Extractor

**File**: `phase2_discovery/api_endpoint_extractor.py`

**Purpose**: Extract API endpoints from JS, HTML, robots.txt, sitemap.xml.

```bash
python phase2_discovery/api_endpoint_extractor.py \
  --target https://example.com \
  --output results/
```

---

### 2.8 GraphQL Introspection

**File**: `phase2_discovery/graphql_introspect.py`

**Purpose**: Introspect GraphQL schemas and analyze for security issues.

```bash
python phase2_discovery/graphql_introspect.py \
  --target https://example.com/graphql \
  --output results/
```

---

### 2.9 OpenAPI Discovery

**File**: `phase2_discovery/openapi_discovery.py`

**Purpose**: Find and analyze Swagger/OpenAPI specifications.

```bash
python phase2_discovery/openapi_discovery.py \
  --target https://example.com \
  --output results/
```

---

## Phase 3: Vulnerability Testing

### 3.1 SSRF Tester

**File**: `phase3_testing/ssrf_tester.py`

**Purpose**: Test for SSRF via URL parameters and HTTP headers.

```bash
# URL parameter SSRF
python phase3_testing/ssrf_tester.py \
  -t "https://example.com/fetch?url=test" \
  -o results/

# Header-based SSRF
python phase3_testing/ssrf_tester.py \
  -t https://example.com/api \
  -o results/ \
  --header-ssrf

# With OOB server
python phase3_testing/ssrf_tester.py \
  -t https://example.com/api \
  -o results/ \
  --header-ssrf \
  --oob-server http://your-callback-server.com

# Specify parameters
python phase3_testing/ssrf_tester.py \
  -t "https://example.com/proxy?url=test&callback=test" \
  -o results/ \
  --params url,callback
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target URL (required) | - |
| `-o, --output` | Output directory | `results` |
| `--threads` | Concurrent threads | `10` |
| `--timeout` | Request timeout | `30` |
| `--params` | Parameters to test (comma-separated) | Auto-detect |
| `--header-ssrf` | Enable header-based SSRF testing | `False` |
| `--oob-server` | OOB callback server for blind SSRF | - |
| `-p, --proxy` | Proxy URL | - |
| `-v, --verbose` | Verbose output | `False` |

**SSRF Headers Tested**:
- `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`
- `X-Client-IP`, `True-Client-IP`, `Client-IP`
- `X-Originating-IP`, `CF-Connecting-IP`, `Forwarded`
- `X-Host`, `Host`, `X-Original-URL`, `X-Rewrite-URL`

**Payloads**:
- Localhost variants (127.0.0.1, localhost, [::1])
- Internal networks (10.x, 172.16.x, 192.168.x)
- Cloud metadata (169.254.169.254, metadata.google.internal)
- Bypass techniques (decimal IP, hex IP, URL encoding)
- Protocol handlers (file://, gopher://, dict://)

---

### 3.2 SQL Injection Tester

**File**: `phase3_testing/injection/sqli_tester.py`

**Purpose**: Test for SQL injection (error-based, time-based, boolean-based, union-based).

```bash
python phase3_testing/injection/sqli_tester.py \
  --target "https://example.com/search?q=test" \
  --output results/ \
  --techniques all \
  --db-fingerprint
```

| Flag | Description | Default |
|------|-------------|---------|
| `--target` | Target URL with parameter (required) | - |
| `--output` | Output directory | `results` |
| `--techniques` | Testing techniques (`error`, `time`, `boolean`, `union`, `all`) | `all` |
| `--db-fingerprint` | Fingerprint database type | `False` |
| `--params` | Parameters to test | Auto-detect |

---

### 3.3 XSS Tester

**File**: `phase3_testing/injection/xss_tester.py`

**Purpose**: Test for XSS (reflected, DOM-based, context-aware).

```bash
python phase3_testing/injection/xss_tester.py \
  --target https://example.com/search \
  --output results/ \
  --params q,name
```

---

### 3.4 XXE Tester

**File**: `phase3_testing/injection/xxe_tester.py`

**Purpose**: Test for XML External Entity injection.

```bash
python phase3_testing/injection/xxe_tester.py \
  --target https://example.com/api/xml \
  --output results/ \
  --oob-server http://your-callback.com
```

---

### 3.5 SSTI Tester

**File**: `phase3_testing/injection/ssti_tester.py`

**Purpose**: Test for Server-Side Template Injection (Jinja2, Twig, Freemarker, etc.).

```bash
python phase3_testing/injection/ssti_tester.py \
  --target https://example.com/render \
  --output results/
```

---

### 3.6 Command Injection Tester

**File**: `phase3_testing/injection/command_injection.py`

**Purpose**: Test for OS command injection (Linux/Windows).

```bash
python phase3_testing/injection/command_injection.py \
  --target https://example.com/ping \
  --output results/ \
  --params host
```

---

### 3.7 IDOR Tester

**File**: `phase3_testing/access/idor_tester.py`

**Purpose**: Test for Insecure Direct Object Reference.

```bash
python phase3_testing/access/idor_tester.py \
  --target "https://example.com/api/user/123" \
  --output results/ \
  --id-range 1-1000
```

---

### 3.8 Privilege Escalation Tester

**File**: `phase3_testing/access/privilege_escalation.py`

**Purpose**: Test for vertical/horizontal privilege escalation.

```bash
python phase3_testing/access/privilege_escalation.py \
  --target https://example.com/api \
  --output results/ \
  --user-token "eyJ..." \
  --admin-endpoints /admin,/users
```

---

### 3.9 Access Control Tester

**File**: `phase3_testing/access/access_control.py`

**Purpose**: Test for forced browsing, method override, unauthenticated access.

```bash
python phase3_testing/access/access_control.py \
  --target https://example.com/api \
  --output results/
```

---

### 3.10 JWT Tester

**File**: `phase3_testing/auth/jwt_tester.py`

**Purpose**: Test JWT vulnerabilities (none algorithm, weak secrets, algorithm confusion).

```bash
python phase3_testing/auth/jwt_tester.py \
  --target https://example.com/api \
  --token "eyJ..." \
  --output results/ \
  --wordlist /path/to/secrets.txt
```

---

### 3.11 Login Bypass Tester

**File**: `phase3_testing/auth/login_bypass.py`

**Purpose**: Test for login bypass (SQL injection, default credentials, header bypass).

```bash
python phase3_testing/auth/login_bypass.py \
  --target https://example.com/login \
  --output results/
```

---

### 3.12 Session Tester

**File**: `phase3_testing/auth/session_tester.py`

**Purpose**: Test session security (fixation, entropy, cookie flags).

```bash
python phase3_testing/auth/session_tester.py \
  --target https://example.com \
  --output results/
```

---

### 3.13 Password Reset Tester

**File**: `phase3_testing/auth/password_reset.py`

**Purpose**: Test password reset (host injection, token exposure, enumeration).

```bash
python phase3_testing/auth/password_reset.py \
  --target https://example.com/forgot-password \
  --output results/
```

---

### 3.14 CSRF Tester

**File**: `phase3_testing/csrf_tester.py`

**Purpose**: Test for CSRF vulnerabilities.

```bash
python phase3_testing/csrf_tester.py \
  --target https://example.com \
  --output results/ \
  --auth-cookie "session=abc123"
```

---

### 3.15 Race Condition Tester

**File**: `phase3_testing/race_condition.py`

**Purpose**: Test for race conditions (TOCTOU, double-spending).

```bash
python phase3_testing/race_condition.py \
  --target https://example.com/api/transfer \
  --output results/ \
  --method POST \
  --data '{"amount": 100}' \
  --concurrent 20
```

---

### 3.16 File Upload Tester

**File**: `phase3_testing/file_upload.py`

**Purpose**: Test file upload vulnerabilities.

```bash
python phase3_testing/file_upload.py \
  --target https://example.com/upload \
  --output results/
```

---

### 3.17 Business Logic Tester

**File**: `phase3_testing/business_logic.py`

**Purpose**: Test business logic flaws (price manipulation, workflow bypass).

```bash
python phase3_testing/business_logic.py \
  --target https://example.com/api/checkout \
  --output results/
```

---

## Core Utilities

### HTTP Client

**File**: `core/http_client.py`

```python
from core.http_client import AsyncHTTPClient

async with AsyncHTTPClient(
    proxy="http://127.0.0.1:8080",
    timeout=30,
    rate_limit=10.0,
    max_retries=3,
) as client:
    response = await client.get("https://example.com")
    response = await client.post(url, data={"key": "value"})
```

### Result Manager

**File**: `core/result_manager.py`

```python
from core.result_manager import ResultManager, ScanResult, Finding, Severity

result = ScanResult(tool="my_scanner", target="https://example.com")
result.add_finding(Finding(
    title="SQL Injection",
    severity=Severity.HIGH,
    description="Found SQL injection in search parameter",
    url="https://example.com/search",
    parameter="q",
    payload="' OR 1=1--",
))
result.finalize()

manager = ResultManager("results/")
manager.save(result)
```

### Payload Manager

**File**: `core/payload_manager.py`

```python
from core.payload_manager import PayloadManager

pm = PayloadManager()
payloads = pm.get_payloads("sqli")  # or xss, ssrf, xxe, ssti
encoded = pm.encode("payload", encoding="url")  # or base64, double_url, etc.
```

---

## Full Pipeline

### CLI Entry Point

**File**: `cli.py`

```bash
# Full scan (all phases)
python cli.py scan -t example.com -o results/

# Recon only
python cli.py recon -t example.com -o results/

# Discovery only
python cli.py discover -t https://example.com -o results/

# Testing only
python cli.py test -t https://example.com/api -o results/ --auth-cookie "session=abc"

# Run specific module
python cli.py module sqli -t "https://example.com/search?q=test" -o results/
python cli.py module xss -t https://example.com/search -o results/
python cli.py module subdomain -t example.com -o results/

# List all modules
python cli.py list
```

### Orchestrator

**File**: `orchestrator.py`

```bash
# Full orchestrated scan
python orchestrator.py -t example.com -o results/

# With specific phases
python orchestrator.py -t example.com -o results/ --phases recon,discover

# With proxy
python orchestrator.py -t example.com -o results/ -p http://127.0.0.1:8080
```

---

## Output Format

All modules output:
- **JSON file**: Machine-readable results with all findings
- **Markdown file**: Human-readable report with severity breakdown
- **Text files**: Simple lists (endpoints, subdomains, etc.)

### Finding Severity Levels

| Severity | Description |
|----------|-------------|
| `CRITICAL` | Immediate exploitation risk (RCE, auth bypass, data breach) |
| `HIGH` | Significant security impact (SQLi, SSRF, privilege escalation) |
| `MEDIUM` | Moderate risk (XSS, CSRF, information disclosure) |
| `LOW` | Minor security concerns (verbose errors, missing headers) |
| `INFO` | Informational (discovered endpoints, technologies) |

---

## Proxy Configuration

All modules support proxy for Burp/Caido integration:

```bash
# HTTP proxy
-p http://127.0.0.1:8080

# SOCKS proxy
-p socks5://127.0.0.1:1080
```

---

## Common Workflows

### Bug Bounty Recon Workflow

```bash
# 1. Subdomain discovery
python phase1_recon/subdomain_prober.py -d target.com -o results/

# 2. Technology fingerprinting
python phase1_recon/tech_fingerprint.py -t https://target.com -o results/

# 3. Framework detection
python phase2_discovery/framework_fingerprinter.py -t https://target.com -o results/

# 4. Admin panel detection
python phase2_discovery/admin_panel_detector.py -t https://target.com -o results/

# 5. JavaScript analysis
python phase2_discovery/js_analyzer.py -t https://target.com -o results/ --deep-extract

# 6. OAuth discovery (if API)
python phase2_discovery/oauth_discovery.py -t https://api.target.com -o results/
```

### API Security Testing Workflow

```bash
# 1. OAuth/Auth discovery
python phase2_discovery/oauth_discovery.py -t https://api.target.com -o results/

# 2. SSRF testing with headers
python phase3_testing/ssrf_tester.py -t https://api.target.com -o results/ --header-ssrf

# 3. IDOR testing
python phase3_testing/access/idor_tester.py -t "https://api.target.com/user/123" -o results/

# 4. JWT testing (if applicable)
python phase3_testing/auth/jwt_tester.py -t https://api.target.com --token "eyJ..." -o results/
```

---

## Environment Variables

```bash
# Optional: Set default proxy
export SHADOW_PROXY="http://127.0.0.1:8080"

# Optional: Set default output directory
export SHADOW_OUTPUT="./results"
```

---

## Dependencies

See `requirements.txt` for full list. Key dependencies:
- `aiohttp` - Async HTTP client
- `pyyaml` - Configuration parsing
- `beautifulsoup4` - HTML parsing (optional)

---

## Notes for AI Agents

1. **Always specify output directory** with `-o` flag
2. **Use proxy** when testing to capture traffic: `-p http://127.0.0.1:8080`
3. **Start with recon** before active testing
4. **Check rate limits** - use `--threads` to control concurrency
5. **Review results** in JSON format for programmatic processing
6. **Chain modules** - use output from one module as input to another

---

*Last Updated: 2026-02-05*

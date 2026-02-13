# SHADOW Tool Routing Rules

Generated: 2026-02-12 | Platform: Kali Linux 6.18.5

---

## Executive Summary

This document defines routing rules for 33 installed Kali tools and 28 custom Python modules in the SHADOW framework. The goal is to maximize effectiveness by using each tool where it excels while maintaining pipeline integration through the Python framework.

**Key principle:** Kali tools are PRIMARY for raw scanning power. Python scripts are PRIMARY for pipeline orchestration, unified output, and specialized testing that Kali tools do not cover.

---

## Conflict Resolution Table

| # | Capability | Kali Tool(s) | Python Script | Winner | Rationale |
|---|-----------|-------------|---------------|--------|-----------|
| C001 | Subdomain Enum | subfinder, amass, theHarvester | subdomain_enum.py | **Python (orchestrator)** | Python wraps Kali tools + adds API sources |
| C002 | Port Scanning | nmap, naabu | port_scanner.py | **nmap** | SYN scan, NSE scripts, OS detection |
| C003 | Tech Fingerprint | whatweb, wafw00f | tech_fingerprint.py | **whatweb** | 1800+ plugins vs 40 signatures |
| C004 | DNS Enum | dnsrecon, dnsx, fierce | dns_enum.py | **dnsrecon** | More techniques; Python adds SPF/DMARC analysis |
| C005 | Dir Bruteforce | ffuf, gobuster, dirb | directory_bruteforce.py | **ffuf** | 10x faster (Go), advanced filtering |
| C006 | SQL Injection | sqlmap | sqli_tester.py | **sqlmap** | Tamper scripts, DB takeover, OS shell |
| C007 | Command Inj | commix | command_injection.py | **commix** | Purpose-built, more bypass techniques |
| C008 | Vuln Scanning | nuclei, nikto | phase3 scripts | **nuclei** | Thousands of templates; Python for deep dives |
| C009 | URL Discovery | katana, urlfinder | wayback_extractor.py | **Both** | Different data sources (live vs historical) |
| C010 | Subdomain Probe | httpx | subdomain_prober.py | **httpx** | Faster; Python adds SSRF header testing |
| C011 | Param Discovery | ffuf, wfuzz | parameter_discovery.py | **ffuf** | Faster fuzzing; Python for analysis |
| C012 | CMS Scanning | wpscan, droopescan | framework_fingerprinter.py | **wpscan** | CMS-specific vuln database |

---

## Routing Flowcharts by Category

### 1. Reconnaissance Phase

```
TARGET RECEIVED
    |
    v
[Subdomain Enumeration]
    |
    +--> Python subdomain_enum.py (ORCHESTRATOR)
    |       |-- Calls subfinder (if installed) ---- YES --> runs subfinder
    |       |-- Calls amass (if installed) -------- YES --> runs amass
    |       |-- Queries crt.sh, HackerTarget, ThreatCrowd, urlscan.io
    |       |-- DNS bruteforce (if wordlist provided)
    |       +-- Merges all results, resolves, probes HTTP
    |
    +--> SUPPLEMENT: theHarvester (email + subdomain OSINT)
    +--> SUPPLEMENT: shodan (internet-wide scan data)
    |
    v
[DNS Enumeration]
    |
    +--> PRIMARY: dnsrecon (full DNS enum, zone transfer, cache snoop)
    +--> SUPPLEMENT: Python dns_enum.py (SPF/DMARC/CAA security analysis)
    +--> SUPPLEMENT: dnsx (fast bulk DNS resolution)
    |
    v
[Port Scanning]
    |
    +--> PRIMARY: nmap -sV -sC (service detection + default scripts)
    |       |-- For speed: naabu (fast SYN scan for port discovery)
    |       +-- Then nmap -sV on open ports only
    +--> FALLBACK: Python port_scanner.py (when nmap unavailable)
    |
    v
[Technology Fingerprinting]
    |
    +--> PRIMARY: whatweb (deep fingerprinting with 1800+ plugins)
    +--> PRIMARY: wafw00f (WAF detection)
    +--> SUPPLEMENT: Python tech_fingerprint.py (pipeline integration)
    |
    v
[SSL/TLS Analysis]
    |
    +--> PRIMARY: sslscan (cipher enum, protocol detection)
    +--> SUPPLEMENT: sslyze (detailed TLS analysis)
    +--> SUPPLEMENT: tlsx (Go-based, pipeline-friendly)
    |
    v
[Historical URL Discovery]
    |
    +--> PRIMARY: Python wayback_extractor.py (Wayback + CommonCrawl)
    +--> SUPPLEMENT: katana (live web crawling with JS rendering)
    +--> SUPPLEMENT: urlfinder (URL extraction from responses)
```

### 2. Discovery Phase

```
RECON DATA RECEIVED
    |
    v
[Directory/File Discovery]
    |
    +--> PRIMARY: ffuf -w /usr/share/wordlists/dirb/common.txt
    |       |-- Use -mc for status filter
    |       |-- Use -fs for size filter
    |       +-- JSON output for pipeline: -o output.json -of json
    +--> ALTERNATIVE: gobuster dir (simpler syntax)
    +--> FALLBACK: Python directory_bruteforce.py (wraps ffuf or native)
    |
    v
[Parameter Discovery]
    |
    +--> PRIMARY: ffuf with parameter wordlist
    |       ffuf -u URL?FUZZ=value -w params.txt
    +--> SUPPLEMENT: Python parameter_discovery.py (response diff analysis)
    |
    v
[JavaScript Analysis]
    |
    +--> PRIMARY: Python js_analyzer.py (custom endpoint/secret extraction)
    +--> SUPPLEMENT: katana (JS rendering + link extraction)
    |
    v
[API Discovery]
    |
    +--> PRIMARY: Python api_endpoint_extractor.py (no Kali equivalent)
    +--> PRIMARY: Python graphql_introspect.py (no Kali equivalent)
    +--> PRIMARY: Python openapi_discovery.py (no Kali equivalent)
    +--> PRIMARY: Python oauth_discovery.py (no Kali equivalent)
    |
    v
[CMS-Specific Scanning]
    |
    +--> IF WordPress: wpscan --url TARGET
    +--> IF Drupal/Joomla: droopescan scan TARGET
    +--> GENERAL: Python admin_panel_detector.py + framework_fingerprinter.py
    |
    v
[Broad Vulnerability Scanning]
    |
    +--> PRIMARY: nuclei -u TARGET -t cves/ -t misconfigurations/
    +--> SUPPLEMENT: nikto -h TARGET (server misconfiguration focus)
```

### 3. Vulnerability Testing Phase

```
DISCOVERY DATA RECEIVED
    |
    v
[SQL Injection]
    |
    +--> SCREEN: Python sqli_tester.py (fast detection across endpoints)
    |       |-- Tests error-based, time-based, boolean-based, union
    |       +-- Identifies injectable parameters
    +--> EXPLOIT: sqlmap -u "URL?param=value" --batch
    |       |-- Confirmed SQLi: sqlmap --dbs --dump
    |       +-- Advanced: sqlmap --tamper=... --level=5 --risk=3
    |
    v
[XSS Testing]
    |
    +--> PRIMARY: Python xss_tester.py (context-aware, filter bypass)
    |       |-- Tests reflected, DOM-based, multiple contexts
    |       +-- Applies encoding mutations
    +--> SUPPLEMENT: nuclei -t xss/ (template-based XSS checks)
    |
    v
[SSTI Testing]
    |
    +--> PRIMARY: Python ssti_tester.py (multi-engine detection)
    |       |-- Jinja2, Twig, Freemarker, Mako, ERB
    |       +-- RCE verification
    +--> NO KALI EQUIVALENT (tplmap not installed)
    |
    v
[Command Injection]
    |
    +--> SCREEN: Python command_injection.py (quick detection)
    +--> EXPLOIT: commix --url="URL?param=value"
    |       |-- Confirmed: commix --os-cmd="id"
    |       +-- Advanced: commix --technique=...
    |
    v
[XXE Testing]
    |
    +--> PRIMARY: Python xxe_tester.py (file disclosure, SSRF, blind)
    +--> SUPPLEMENT: interactsh-client (for OOB XXE verification)
    |
    v
[SSRF Testing]
    |
    +--> PRIMARY: Python ssrf_tester.py (internal, cloud metadata, protocol)
    +--> SUPPLEMENT: interactsh-client (for blind SSRF verification)
    |
    v
[Authentication Testing]
    |
    +--> PRIMARY: Python jwt_tester.py (NO KALI EQUIVALENT)
    +--> PRIMARY: Python login_bypass.py
    +--> PRIMARY: Python session_tester.py
    +--> PRIMARY: Python password_reset.py
    +--> SUPPLEMENT: hydra (credential bruteforce if needed)
    |
    v
[Access Control Testing]
    |
    +--> PRIMARY: Python idor_tester.py (NO KALI EQUIVALENT)
    +--> PRIMARY: Python privilege_escalation.py (NO KALI EQUIVALENT)
    +--> PRIMARY: Python access_control.py (NO KALI EQUIVALENT)
    |
    v
[Business Logic & Race Conditions]
    |
    +--> PRIMARY: Python business_logic.py (NO KALI EQUIVALENT)
    +--> PRIMARY: Python race_condition.py (NO KALI EQUIVALENT)
    |
    v
[CSRF Testing]
    |
    +--> PRIMARY: Python csrf_tester.py (NO KALI EQUIVALENT for automation)
    |
    v
[File Upload Testing]
    |
    +--> PRIMARY: Python file_upload.py (NO KALI EQUIVALENT for automation)
```

---

## Environment Setup Requirements

### Required Python Dependencies

```bash
pip install -r /home/huntersreeni/Documents/Red_Teamer/SHADOW/shadow-bounty/requirements.txt
```

Key dependencies:
- `aiohttp>=3.9.0` - Async HTTP client (core)
- `dnspython>=2.4.0` - DNS resolution
- `pyjwt>=2.8.0` - JWT testing
- `cryptography>=41.0.0` - JWT crypto operations
- `beautifulsoup4>=4.12.0` - HTML parsing
- `pyyaml>=6.0` - Configuration

### Required Kali Packages (verify installed)

```bash
# Core tools (all confirmed installed)
apt install -y nmap sqlmap nikto gobuster ffuf wfuzz hydra john hashcat \
  whatweb wafw00f wpscan sslscan sslyze commix burpsuite metasploit-framework \
  amass dnsrecon

# Go tools via pdtm (all confirmed installed at ~/.pdtm/go/bin/)
# subfinder, nuclei, httpx, katana, dnsx, naabu, interactsh-client
```

### Missing but Recommended

```bash
# Install SecLists for comprehensive wordlists
apt install -y seclists
# OR
git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# Install additional Go tools
go install github.com/tomnomnom/gau@latest          # Wayback URL fetcher
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest       # Web crawler
go install github.com/hahwul/dalfox/v2@latest        # XSS scanner
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest  # CRLF fuzzer

# Install feroxbuster (fast recursive content discovery)
apt install -y feroxbuster

# Install arjun (parameter discovery)
pip install arjun
```

---

## Dependency Checklist

### Pre-Scan Verification

| Check | Command | Required |
|-------|---------|----------|
| Python 3.12+ | `python3 --version` | Yes |
| aiohttp installed | `python3 -c "import aiohttp"` | Yes |
| dnspython installed | `python3 -c "import dns.resolver"` | Yes |
| pyjwt installed | `python3 -c "import jwt"` | For JWT testing |
| nmap available | `nmap --version` | Recommended |
| subfinder available | `subfinder -version` | Recommended |
| nuclei available | `nuclei -version` | Recommended |
| sqlmap available | `sqlmap --version` | For SQLi exploitation |
| ffuf available | `ffuf -V` | For directory bruteforce |
| httpx available | `httpx -version` | For subdomain probing |
| interactsh-client | `interactsh-client -version` | For OOB testing |

### Network Requirements

- Outbound HTTP/HTTPS access to target
- Outbound DNS (port 53) for resolution
- Access to crt.sh, HackerTarget, urlscan.io for passive recon
- Access to web.archive.org for Wayback queries
- Optional: Proxy (Burp/Caido) on localhost:8080

---

## Integration Points Between Toolsets

### Data Flow: Kali --> Python

1. **subfinder/amass output --> subdomain_enum.py**: Python calls these tools as subprocesses, parses stdout line-by-line
2. **nmap XML output --> port_scanner.py**: Python parses nmap `-oX -` XML output for port/service data
3. **ffuf JSON output --> directory_bruteforce.py**: Python can wrap ffuf and parse `-o output.json -of json`
4. **nuclei JSON output --> result_manager.py**: Parse nuclei `-json` output into ScanResult/Finding objects

### Data Flow: Python --> Kali

1. **subdomain_enum.py results --> httpx**: Pipe subdomain list to httpx for probing: `cat subdomains.txt | httpx`
2. **parameter_discovery.py --> sqlmap**: Feed discovered parameterized URLs to sqlmap
3. **js_analyzer.py endpoints --> ffuf**: Use extracted endpoints as custom wordlists for ffuf
4. **sqli_tester.py findings --> sqlmap**: Route confirmed injectable endpoints to sqlmap for exploitation

### Shared Data Formats

- **Subdomain lists**: Plain text, one per line (interoperable with all tools)
- **URL lists**: Plain text with full URLs (for httpx, nuclei, ffuf input)
- **Findings**: JSON with severity/description/evidence (Python ResultManager format)
- **Scan results**: JSON + Markdown (Python ResultManager dual output)

---

## Routing Decision Matrix

For each scan type, use this decision matrix:

### Quick Scan (Speed Priority)

| Phase | Tool | Time |
|-------|------|------|
| Subdomain | subfinder -silent | 30s |
| DNS resolve | dnsx | 10s |
| Port scan | naabu -top-ports 100 | 60s |
| HTTP probe | httpx -silent | 30s |
| Vuln scan | nuclei -severity critical,high | 5min |
| **Total** | | **~7min** |

### Standard Scan (Balanced)

| Phase | Tool | Time |
|-------|------|------|
| Subdomain | Python subdomain_enum.py (all sources) | 5min |
| DNS | Python dns_enum.py + dnsrecon | 3min |
| Port scan | nmap -sV top-1000 | 10min |
| Tech | whatweb + wafw00f | 2min |
| Dirs | ffuf with common.txt | 5min |
| Vuln scan | nuclei (all templates) | 15min |
| Testing | Python phase3 (all modules) | 20min |
| **Total** | | **~60min** |

### Deep Scan (Thoroughness Priority)

| Phase | Tool | Time |
|-------|------|------|
| Subdomain | Python + subfinder + amass + theHarvester | 15min |
| DNS | dnsrecon + Python dns_enum.py | 10min |
| Port scan | nmap -sV -sC -p- (all ports) | 30min+ |
| Wayback | Python wayback_extractor.py | 5min |
| Crawl | katana --depth 5 | 10min |
| Tech | whatweb + wafw00f + Python | 5min |
| Dirs | ffuf + gobuster (multiple wordlists) | 20min |
| JS analysis | Python js_analyzer.py --deep-extract | 10min |
| API discovery | Python (graphql, openapi, oauth) | 10min |
| SQLi screen | Python sqli_tester.py | 15min |
| SQLi exploit | sqlmap (on confirmed) | 30min+ |
| XSS | Python xss_tester.py | 15min |
| All phase3 | Python full testing suite | 60min |
| Nuclei | nuclei -severity all -rate-limit 50 | 30min |
| **Total** | | **~4-5 hours** |

---

## Unique Value: Python-Only Capabilities

These capabilities have NO Kali tool equivalent and represent the unique value of the SHADOW Python framework:

1. **JWT Testing** (`jwt_tester.py`) - Algorithm confusion, none algorithm, weak secret bruteforce
2. **Business Logic Testing** (`business_logic.py`) - Price manipulation, workflow bypass
3. **Race Condition Testing** (`race_condition.py`) - TOCTOU, parallel request testing
4. **IDOR Testing** (`idor_tester.py`) - Automated ID enumeration and access comparison
5. **Privilege Escalation Testing** (`privilege_escalation.py`) - Role manipulation, vertical privesc
6. **Access Control Testing** (`access_control.py`) - HTTP verb tampering, forced browsing
7. **GraphQL Introspection** (`graphql_introspect.py`) - Schema extraction, query generation
8. **OAuth Discovery** (`oauth_discovery.py`) - OAuth/OIDC endpoint and misconfiguration detection
9. **OpenAPI Discovery** (`openapi_discovery.py`) - Swagger/OpenAPI spec parsing
10. **CSRF Testing** (`csrf_tester.py`) - Automated token analysis, PoC generation
11. **File Upload Testing** (`file_upload.py`) - Extension/MIME bypass automation
12. **Password Reset Testing** (`password_reset.py`) - Token analysis, host header injection
13. **Pipeline Orchestration** (`orchestrator.py`) - Unified multi-phase scanning with aggregated results
14. **Response Analysis Engine** (`response_analyzer.py`) - Cross-vulnerability anomaly detection
15. **Payload Encoding Engine** (`payload_manager.py`) - 26 encoding schemes with mutation support

---

## Recommendations

### High Priority

1. **Install SecLists**: Custom wordlists are very small (176-209 lines). SecLists provides millions of entries.
2. **Install dalfox**: Specialized XSS scanner to complement Python xss_tester.py.
3. **Install gau**: Fast Wayback URL fetcher to supplement wayback_extractor.py.

### Medium Priority

4. **Install feroxbuster**: Recursive content discovery, complements ffuf.
5. **Install arjun**: Specialized parameter discovery tool.
6. **Add interactsh integration**: Python scripts should integrate interactsh-client for OOB verification (blind SSRF, blind XXE, blind XSS).

### Low Priority

7. **Add SSL/TLS Python module**: Wrap sslscan/sslyze output into pipeline.
8. **Add OSINT module**: Integrate Shodan/theHarvester into Python pipeline.
9. **Add nuclei result parser**: Import nuclei JSON findings into ResultManager format.

# 🔒 Penetration Testing Toolkit v3.0

<div align="center">

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        🛡️  PROFESSIONAL RED TEAM TOOLKIT  🛡️                ║
║                                                              ║
║   Engagement Management • OSINT • Scanning • Fuzzing         ║
║   Password Cracking • Encryption • Professional Reports      ║
║   CLI Interface  •  Browser-based Web GUI                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational-green.svg)](LICENSE)
[![Modules](https://img.shields.io/badge/Modules-10-orange.svg)](#modules)
[![Web GUI](https://img.shields.io/badge/Web_GUI-Flask-lightblue.svg)](#-web-gui)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success.svg)](#)

**A professional, modular toolkit for authorized penetration testing — available as both a CLI and browser-based Web GUI**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Web GUI](#-web-gui) • [Modules](#-modules) • [Workflow](#-professional-workflow)

</div>

---

## 🎯 What's New in v3.0

v3.0 transforms this from a collection of scanning wrappers into a **professional red team platform**:

| Feature | Description |
|---|---|
| 🌐 **Web GUI** | Browser-based interface (`python3 server.py`) — run tools, view live output, manage engagements |
| 🗂 **Engagement System** | Client info, scope definition, exclusion lists, findings tracker, full audit trail |
| 🔍 **OSINT Module** | theHarvester, Subfinder, Amass, DNSRecon, Shodan API, crt.sh, whois |
| 🌍 **IP Trace (GUI)** | traceroute, mtr, ping, whois — full network path analysis in the browser |
| 💥 **Web Fuzzer** | gobuster, ffuf, feroxbuster integration + built-in Python fuzzer fallback |
| 📊 **Report Generator** | Professional HTML/PDF/JSON/CSV reports from engagement findings |
| 🧱 **BaseModule Architecture** | Shared base class — scope validation, finding logging, audit trail in every module |
| 🛡 **Scope Enforcement** | Every module checks targets against engagement scope before executing |

---

## ✨ Features

```
┌─────────────────────────────────────────────────────────────┐
│  Engagement Management     │  OSINT & Recon                  │
│  • Client & scope tracking │  • theHarvester (emails/hosts)  │
│  • Findings database       │  • Subfinder (subdomains)       │
│  • Severity classification │  • Amass (deep enumeration)     │
│  • Audit trail (every cmd) │  • DNSRecon (DNS records)       │
│  • Evidence directory      │  • Shodan API integration       │
│  • Scope enforcement       │  • crt.sh (cert transparency)   │
│                            │                                  │
│  Web Fuzzing               │  Reporting                      │
│  • gobuster (dir/dns/vhost)│  • Professional HTML reports    │
│  • ffuf (param/dir fuzzing)│  • PDF export (weasyprint)      │
│  • feroxbuster (recursive) │  • JSON findings export         │
│  • Built-in Python fuzzer  │  • CSV spreadsheet export       │
│  • vhost enumeration       │  • Executive summary            │
│                            │                                  │
│  Network Scanning          │  Password & Crypto              │
│  • Nmap (15+ scan types)   │  • Dictionary attacks           │
│  • Vuln assessment (Nikto) │  • Brute force + hybrid         │
│  • IP geolocation/OSINT    │  • AES-256 / Fernet encryption  │
│  • Scan profiles           │  • 12+ hash algorithms          │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites

```bash
# System dependencies
sudo apt-get update
sudo apt-get install -y \
    nmap nikto traceroute whois dnsutils \
    gobuster ffuf feroxbuster seclists \
    theharvester amass dnsrecon \
    python3-pip

# PDF report generation (optional but recommended)
sudo apt-get install -y libpango-1.0-0 libcairo2 libpangoft2-1.0-0
```

### Python Dependencies

```bash
git clone https://github.com/leadrelic/Pentesters-ToolKit.git
cd Pentesters-ToolKit

# Automated installation
chmod +x install.sh && ./install.sh

# Or manually
pip3 install --break-system-packages -r requirements.txt
```

### Go-based tools (optional, better performance)

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest
```

---

## 🚀 Quick Start

### CLI
```bash
python3 toolkit.py
```

### Web GUI
```bash
python3 server.py
# Opens http://127.0.0.1:5000 automatically
```

Optional flags:
```bash
python3 server.py --port 8080          # custom port
python3 server.py --host 0.0.0.0       # expose on LAN (trusted networks only)
python3 server.py --no-browser         # don't auto-open browser
python3 server.py --debug              # Flask debug mode
```

### Professional Red Team Workflow

```
1. Create an engagement
   (pentest) engagement
   (engagement) new acme-q1-2026

2. Define scope
   (engagement) scope add 10.10.10.0/24
   (engagement) scope add *.acme.example.com
   (engagement) exclude 10.10.10.1          ← out-of-scope gateway

3. Run recon — scope is enforced automatically
   (pentest) osint
   (osint) dns acme.example.com
   (osint) crtsh acme.example.com
   (osint) subfinder acme.example.com

4. Scan
   (pentest) nmap
   (nmap) scan 10.10.10.0/24

5. Fuzz web apps
   (pentest) fuzzer
   (fuzzer) gobuster dir http://10.10.10.5/

6. Log findings as you work
   (pentest) engagement
   (engagement) finding           ← interactive prompt

7. Generate report
   (pentest) report
   (reporter) html                ← opens in browser
   (reporter) pdf                 ← professional PDF
```

---

## 🌐 Web GUI

Launch a full browser-based interface alongside the CLI:

```bash
python3 server.py
```

The Web GUI provides live streaming terminal output (via SSE), engagement management, and one-click report generation — all without leaving the browser.

| Page | What it does |
|---|---|
| **Dashboard** | Finding counts, recent jobs, installed tool status |
| **Engagement → Manage** | Create/load engagements, define scope, scope checker |
| **Engagement → Findings** | View all findings, add new findings manually |
| **Engagement → Reports** | Generate HTML/PDF/JSON/CSV reports, download links |
| **Recon → OSINT** | DNS, crt.sh, whois, Subfinder, theHarvester, Amass, DNSRecon, dig |
| **Recon → IP Trace** | traceroute, mtr, ping, whois — live network path output |
| **Scanning → Nmap** | 9 scan profiles including quick, full, stealth, vuln, OS, custom |
| **Scanning → Vuln Scan** | Nikto, Nmap vuln scripts, SSL/TLS analysis, security headers |
| **Scanning → Fuzzer** | gobuster (dir/dns/vhost), ffuf, feroxbuster |
| **Credentials → Password** | Command builder for hashcat + John the Ripper |
| **Tools** | See which tools are installed, install commands |

**GUI features:**
- Live streaming output — see results as they arrive
- Scope enforcement — out-of-scope targets are blocked at the API layer
- Copy button on every terminal panel
- Enter key triggers scans (no need to click Run)
- Running job indicator in the header
- "Add Finding" shortcut banner appears when a scan finishes
- All engagements, findings, and reports are shared with the CLI

---

## 🧩 Modules

### 🗂 Engagement Module (`engagement.py`) — NEW

**The core of every professional engagement.**

```bash
Commands:
  new <name>              Create a new engagement
  load <name>             Load a saved engagement
  list                    List all engagements
  info                    Show engagement summary
  scope add <target>      Add IP/CIDR/domain to scope
  scope list              List in-scope targets
  exclude <target>        Add an exclusion
  check <target>          Check if target is in scope
  finding                 Add a finding interactively
  findings [severity]     List findings (filter optional)
  audit [n]               Show last n audit entries
  close                   Save and close
```

Scope items accept: IP addresses, CIDR ranges (`192.168.1.0/24`), exact domains, wildcard domains (`*.example.com`).

---

### 📊 Report Generator (`reporter.py`) — NEW

**One command from engagement → professional PDF.**

```bash
Commands:
  html [path]     Generate HTML report (dark theme, always available)
  pdf  [path]     Generate PDF report (requires weasyprint)
  json [path]     Export findings as JSON
  csv  [path]     Export findings as CSV
  open            Open latest report in browser
  list            List generated reports
```

Reports include: executive summary, risk matrix, per-finding detail cards with CVE references, scope documentation, and audit statistics.

---

### 🔍 OSINT Module (`osint.py`) — NEW

**Passive and semi-passive reconnaissance.**

```bash
Commands:
  theharvester <domain>   Email/subdomain/host enumeration
  subfinder <domain>      Passive subdomain discovery
  amass <domain>          Deep subdomain enumeration [passive|active]
  dnsrecon <domain>       Full DNS reconnaissance
  dns <domain>            Quick A/MX/NS/TXT/SOA lookup (built-in)
  crtsh <domain>          Certificate transparency (no API key)
  shodan <query>          Shodan search (requires API key)
  whois <target>          WHOIS information
  emails <domain>         Harvest public email addresses
  batch <file>            Full recon on each target in file
  tools                   Check which tools are installed
```

Shodan integration: `config shodan_api_key <your-key>`

---

### 💥 Web Fuzzer (`fuzzer.py`) — NEW

**Directory, subdomain, vhost, and parameter fuzzing.**

```bash
Commands:
  gobuster dir <url>       Directory brute-force
  gobuster dns <domain>    Subdomain enumeration
  gobuster vhost <url>     Virtual host discovery
  ffuf <url/FUZZ>          Fast fuzzing with FUZZ placeholder
  ferox <url>              Recursive content discovery
  fuzz <url>               Built-in Python fuzzer (no tools needed)
  vhost <domain> <ip>      Virtual host enumeration
  wordlists                Show available/configured wordlists
  tools                    Check installed fuzzing tools
```

Wordlist auto-detection: automatically finds SecLists, dirb, dirbuster lists.

---

### 🗺 Nmap Module (`nmap.py`)

15+ scan types, NSE scripts, OS fingerprinting, XML parsing, scan profiles.

```bash
scan <target>                   Quick comprehensive scan
tcp_syn_scan <target>           SYN stealth (requires root)
aggressive_scan <target>        -A scan (OS/version/scripts)
profile comprehensive <target>  Full assessment profile
vulnerability_scan <target>     NSE vuln scripts
```

---

### 🛡 Vulnerability Scanner (`vuln_scan.py`)

Nikto, Nmap NSE, SSL/TLS testing, CMS detection, security headers.

```bash
web <url>                       Nikto web scan
ssl <target>                    SSL/TLS analysis
headers <url>                   Security headers check
cms_scan <url>                  CMS detection
nmap_vuln <target>              Nmap vuln scripts
```

---

### 🌐 IP Trace (`trace.py`)

Multi-source geolocation, traceroute, reverse DNS, WHOIS, reputation.

---

### 🔓 Password Cracking (`pass_crack.py`)

Dictionary, brute force, hybrid, rule-based attacks. 10+ hash algorithms.

---

### 🔐 Encryption/Hashing (`hashing.py`)

Fernet, AES-256-CBC, 12+ hash algorithms, Base64/hex encoding.

---

### 📚 Dictionary Creator (`dictionary.py`)

Leetspeak mutations, case variations, year/number patterns, custom wordlists.

---

## 🏗 Architecture

### BaseModule (`base_module.py`)

Every module extends `BaseModule`, which provides:
- `_print_success/error/warning/info` — consistent coloured output
- `do_config` — persistent per-module configuration
- `_require_scope(target)` — scope validation before any operation
- `_log_finding(...)` — emit findings directly to the active engagement
- `_audit(command, detail)` — automatic audit trail via `precmd` hook
- `_save_output(content)` — timestamped result persistence
- `do_back/exit/quit/emptyline/default` — consistent CLI behaviour

### Engagement-aware modules

When a module is launched from the main toolkit, the active `Engagement` object is passed in. Every `_require_scope()` and `_log_finding()` call automatically operates against the current engagement — no manual wiring needed.

---

## 📁 File Layout

```
~/.pentest_toolkit/
├── config/
│   └── <module>.json           Per-module configuration
├── engagements/
│   └── <engagement-name>/
│       ├── engagement.json     Full engagement data (scope, findings, audit)
│       ├── audit.log           Plain-text timestamped audit trail
│       └── evidence/           Evidence files
├── reports/
│   ├── report_<name>_<ts>.html HTML report
│   └── report_<name>_<ts>.pdf  PDF report
├── logs/
│   ├── pentest_toolkit.log     Rolling log
│   └── session_<ts>.log        Per-session log
├── osint/                      OSINT results
├── fuzzer/                     Fuzzer results
└── nmap/                       Nmap scan outputs
```

---

## 🛡 Security & Legal

```
┌─────────────────────────────────────────────────────────────┐
│  ⚠️  FOR AUTHORIZED TESTING ONLY  ⚠️                         │
├─────────────────────────────────────────────────────────────┤
│  • Always obtain written authorization before testing       │
│  • Define scope in the Engagement module before scanning    │
│  • The audit trail provides legal documentation of actions  │
│  • Unauthorized access is illegal in most jurisdictions     │
└─────────────────────────────────────────────────────────────┘
```

The Engagement module's scope enforcement and audit trail are specifically designed to help you stay within authorized boundaries and document your activities for reporting.

---

## 🗺 Roadmap

### v3.1
- [ ] Metasploit RPC integration
- [ ] Burp Suite findings import
- [ ] CVE lookup via NVD/CIRCL API
- [ ] Automated recon pipeline (run all OSINT → scan → fuzz in one command)
- [ ] Web GUI: stop running job from the browser
- [ ] Web GUI: hashcat/john execution directly in the browser

### v3.2
- [ ] Shodan Monitor integration
- [ ] AWS/Azure/GCP asset discovery
- [ ] Container/Kubernetes security scanning
- [ ] Active Directory enumeration module

### v4.0
- [ ] Web GUI authentication (local password protect)
- [ ] Team collaboration (shared engagements)
- [ ] Compliance mapping (PCI-DSS, HIPAA, ISO 27001)

---

## 📜 License

MIT License — Copyright (c) 2026  (@leadrelic)

For educational and authorized security testing purposes only.

---

<div align="center">

**Built by a security professional, for security professionals**

[⬆ Back to Top](#-penetration-testing-toolkit-v30)

</div>

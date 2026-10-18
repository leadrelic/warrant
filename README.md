# warrant

A pentest toolkit built around one rule: **nothing runs against a target until the engagement's scope authorizes it.** Every tool run is scope-checked, audited, saved as evidence and parsed into findings, from the CLI or the web GUI.

Python 3.9+. No dependencies for the CLI; `flask` for the GUI, `weasyprint` for PDF reports.

```bash
pip install -e ".[web]"          # or just: python -m warrant ...

warrant new acme --client "Acme Corp" --tester me --scope 10.10.10.0/24 --scope example.com --exclude 10.10.10.1
warrant scope check 10.10.10.5 8.8.8.8
warrant run nmap 10.10.10.0/24 profile=quick
warrant run nuclei https://app.example.com severity=high,critical
warrant finding list
warrant report --format html,md
warrant serve                     # web GUI
```

## How it works

| Piece | Behavior |
|---|---|
| **Scope** | IPs, CIDRs, `a.b.c.d-e` ranges, domains (`example.com` covers subdomains). Hostnames are resolved and every address must be in scope and outside the exclusions. Networks must be fully inside scope. No scope defined means everything is blocked. Domains that resolve outside your listed networks (CDNs) raise a warning. |
| **Validation** | Typed parameters only. Targets can't start with `-` or contain shell metacharacters; "extra flags" fields accept an allow-list of flags with validated values (no `-oN`, `-iL`, script paths...). Tools run as argv lists, never through a shell. |
| **Audit log** | Hash-chained JSONL per engagement: every run (argv, resolved IPs, output hashes), blocked attempt, scope change and finding. `warrant audit --verify` detects edits, deletions and reordering. |
| **Evidence** | Raw output and tool artifacts (nmap XML, nuclei JSONL...) are stored under the engagement and linked from findings. |
| **Findings** | Parsed from tool output (open and risky ports, NSE vulnerable results, vulners CVEs, nuclei matches, sensitive paths, TLS and header issues). Deduplicated across runs; track status (`open`, `confirmed`, `remediated`, `accepted`, `false_positive`). |
| **Reports** | HTML (self-contained, fully escaped), Markdown, JSON, CSV (formula-safe), PDF. Includes scope, findings, tools used and audit-chain status. |

Data lives in `~/.warrant/` (override with `WARRANT_HOME`), files `0600`.

## Tools

`warrant tools` lists everything with install status; `warrant tools nmap` shows parameters.

| | |
|---|---|
| **Recon** | crt.sh (marks which names are in scope), subfinder, amass, gobuster dns, dnsrecon, theHarvester, whois, dig |
| **Scanning** | nmap (profiles, ports, timing), testssl.sh, ssh-audit, enum4linux-ng, built-in TLS audit (expiry, trust, TLS 1.0/1.1, weak ciphers) |
| **Web** | nuclei, nikto, gobuster dir/vhost, ffuf, feroxbuster, httpx, whatweb; built-in security-header/cookie/CORS audit and exposed-file check (`.git`, `.env`, phpinfo...) |
| **Network** | traceroute, mtr, ping |
| **Passwords** | hashid (hashcat modes and john formats), wordlist generator, hashcat and john wrappers |

Built-in tools never follow redirects, so a request can't leave the host that passed the scope check.

## Web GUI

`warrant serve` prints a URL containing a one-time token. It binds to loopback, requires the token (HttpOnly, SameSite=Strict cookie), validates the Host header (DNS rebinding) and Origin on writes, and sends a strict CSP; tool output is always rendered as text. Remote binding needs `--allow-remote` and has no TLS, so prefer an SSH tunnel.

## Tests

```bash
pip install flask
python -m unittest discover -s tests
```

## Disclaimer

For authorized security testing only. Scope enforcement is a safety net, not a substitute for a signed rules-of-engagement document.

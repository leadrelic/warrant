"""Wrappers around external tools. All argv construction happens here, from validated parameters only."""

import os
import re

from ..runner import ToolSpec
from ..validate import Param
from . import parsers as P

DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
]


def default_wordlist():
    return next((w for w in DEFAULT_WORDLISTS if os.path.exists(w)), None)


# ---------- nmap ----------
NMAP_PROFILES = {
    "default": ["-sV"],
    "quick": ["-sV", "-sC", "-T4", "--top-ports", "1000"],
    "full": ["-sV", "-sC", "-p-", "-T4"],
    "stealth": ["-sS", "-T2"],
    "aggressive": ["-A", "-T4"],
    "vuln": ["--script", "vuln", "-sV"],
    "udp": ["-sU", "--top-ports", "100"],
    "os": ["-O", "-sV"],
    "ping": ["-sn"],
}
NMAP_ALLOWED = {
    "-sS": None, "-sT": None, "-sU": None, "-sV": None, "-sC": None, "-sn": None, "-sA": None, "-sF": None,
    "-sX": None, "-sN": None, "-A": None, "-O": None, "-Pn": None, "-n": None, "-F": None, "-v": None, "-vv": None,
    "-6": None, "--open": None, "--reason": None, "--osscan-guess": None, "-T": None,
    "-p": r"[0-9,\-TU:]{1,200}", "--top-ports": r"\d{1,5}", "--max-rate": r"\d{1,6}", "--min-rate": r"\d{1,6}",
    "--host-timeout": r"\d{1,5}[smh]", "--max-retries": r"\d{1,2}", "--version-intensity": r"[0-9]",
    "--script": r"[A-Za-z0-9_,.*\-]{1,200}",       # script names/categories only; no paths or expressions
}


def build_nmap(p, ctx):
    args = list(NMAP_PROFILES[p.get("profile", "default")])
    if p.get("ports"):
        cleaned, skip = [], False
        for a in args:
            if skip:
                skip = False
            elif a == "-p-":
                continue
            elif a == "--top-ports":
                skip = True
            else:
                cleaned.append(a)
        args = cleaned + ["-p", p["ports"]]
    if p.get("timing") is not None:
        args = [a for a in args if not re.fullmatch(r"-T[0-5]", a)] + [f"-T{p['timing']}"]
    if p.get("skip_ping"):
        args.append("-Pn")
    args += p.get("extra", [])
    return [ctx.binary, *args, "-oX", str(ctx.paths["xml"]), p["target"]]


nmap = ToolSpec(
    "nmap", "Nmap", "Scanning", "Port, service and OS scanning. Open ports and risky services become findings.",
    [Param("target", "target", "Target (IP, CIDR, range, host)"),
     Param("profile", "choice", "Profile", required=False, default="default", choices=list(NMAP_PROFILES)),
     Param("ports", "ports", "Ports (overrides profile)", required=False),
     Param("timing", "int", "Timing -T0..5", required=False, min=0, max=5),
     Param("skip_ping", "bool", "Skip host discovery (-Pn)", required=False, default=False),
     Param("extra", "flags", "Extra flags (allow-listed)", required=False, allowed=NMAP_ALLOWED)],
    binary="nmap", build=build_nmap, parse=P.parse_nmap_xml, outputs={"xml": ".xml"},
    install="apt install nmap", needs_root=False,
)


# ---------- web ----------
def _wl(p):
    return Param("wordlist", "file", "Wordlist", required=default_wordlist() is None, default=default_wordlist())


def build_gobuster_dir(p, ctx):
    a = [ctx.binary, "dir", "-u", p["url"], "-w", p["wordlist"], "-t", p.get("threads", 30), "--no-error"]
    if p.get("extensions"):
        a += ["-x", p["extensions"]]
    if p.get("status_codes"):
        a += ["-s", p["status_codes"], "-b", ""]
    return a


gobuster_dir = ToolSpec(
    "gobuster_dir", "Gobuster (dir)", "Web", "Directory and file brute-forcing.",
    [Param("url", "url", "Base URL"), _wl(None),
     Param("extensions", "text", "Extensions (php,txt)", required=False, pattern=r"^[A-Za-z0-9,]{1,100}$"),
     Param("status_codes", "text", "Status codes", required=False, pattern=r"^\d{3}(,\d{3})*$"),
     Param("threads", "int", "Threads", required=False, default=30, min=1, max=200)],
    binary="gobuster", build=build_gobuster_dir, parse=P.parse_dirlines, install="apt install gobuster",
)

gobuster_dns = ToolSpec(
    "gobuster_dns", "Gobuster (dns)", "Recon", "Subdomain brute-forcing.",
    [Param("domain", "target", "Domain"), _wl(None), Param("threads", "int", "Threads", required=False, default=30, min=1, max=200)],
    binary="gobuster", build=lambda p, c: [c.binary, "dns", "-d", p["domain"], "-w", p["wordlist"], "-t", p.get("threads", 30)],
    install="apt install gobuster",
)

gobuster_vhost = ToolSpec(
    "gobuster_vhost", "Gobuster (vhost)", "Web", "Virtual host discovery.",
    [Param("url", "url", "Base URL"), _wl(None), Param("threads", "int", "Threads", required=False, default=30, min=1, max=200)],
    binary="gobuster",
    build=lambda p, c: [c.binary, "vhost", "-u", p["url"], "-w", p["wordlist"], "-t", p.get("threads", 30), "--append-domain"],
    install="apt install gobuster",
)


def build_ffuf(p, ctx):
    url = p["url"] if "FUZZ" in p["url"] else p["url"].rstrip("/") + "/FUZZ"
    a = [ctx.binary, "-u", url, "-w", p["wordlist"], "-t", p.get("threads", 40), "-of", "json", "-o", str(ctx.paths["json"])]
    if p.get("status_codes"):
        a += ["-mc", p["status_codes"]]
    return a


ffuf = ToolSpec(
    "ffuf", "ffuf", "Web", "Fast web fuzzer (FUZZ is appended if absent).",
    [Param("url", "url", "URL (FUZZ marks the position)"), _wl(None),
     Param("status_codes", "text", "Match status codes", required=False, default="200,204,301,302,307,401,403",
           pattern=r"^(\d{3}|all)(,\d{3})*$"),
     Param("threads", "int", "Threads", required=False, default=40, min=1, max=200)],
    binary="ffuf", build=build_ffuf, parse=P.parse_ffuf, outputs={"json": ".json"}, install="apt install ffuf",
)

feroxbuster = ToolSpec(
    "feroxbuster", "feroxbuster", "Web", "Recursive content discovery.",
    [Param("url", "url", "Base URL"), _wl(None), Param("threads", "int", "Threads", required=False, default=50, min=1, max=200)],
    binary="feroxbuster",
    build=lambda p, c: [c.binary, "-u", p["url"], "-w", p["wordlist"], "-t", p.get("threads", 50), "--no-state"],
    parse=P.parse_dirlines, install="apt install feroxbuster",
)

nikto = ToolSpec(
    "nikto", "Nikto", "Web", "Web server misconfiguration scanner.",
    [Param("url", "url", "URL"),
     Param("tuning", "text", "Tuning (e.g. 123b)", required=False, pattern=r"^[0-9a-cx]{1,12}$")],
    binary="nikto",
    build=lambda p, c: [c.binary, "-h", p["url"], "-Format", "json", "-output", str(c.paths["json"]), "-nointeractive"]
    + (["-Tuning", p["tuning"]] if p.get("tuning") else []),
    parse=P.parse_nikto, outputs={"json": ".json"}, install="apt install nikto",
)

nuclei = ToolSpec(
    "nuclei", "Nuclei", "Web", "Template-based vulnerability scanner. Matches become findings.",
    [Param("url", "url", "URL"),
     Param("severity", "text", "Severities", required=False, default="medium,high,critical",
           pattern=r"^(info|low|medium|high|critical)(,(info|low|medium|high|critical))*$"),
     Param("tags", "text", "Tags (cve,exposure)", required=False, pattern=r"^[A-Za-z0-9,_-]{1,100}$"),
     Param("rate_limit", "int", "Requests/second", required=False, default=50, min=1, max=1000)],
    binary="nuclei",
    build=lambda p, c: [c.binary, "-u", p["url"], "-jsonl", "-o", str(c.paths["jsonl"]), "-severity", p["severity"],
                        "-rl", p.get("rate_limit", 50), "-nc"] + (["-tags", p["tags"]] if p.get("tags") else []),
    parse=P.parse_nuclei, outputs={"jsonl": ".jsonl"}, install="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
)

whatweb = ToolSpec(
    "whatweb", "WhatWeb", "Web", "Web technology fingerprinting.",
    [Param("url", "url", "URL")], binary="whatweb", build=lambda p, c: [c.binary, "-a", "3", "--color=never", p["url"]],
    install="apt install whatweb",
)

httpx = ToolSpec(
    "httpx", "httpx", "Web", "HTTP probing: status, title, technologies.",
    [Param("url", "url", "URL")], binary="httpx",
    build=lambda p, c: [c.binary, "-u", p["url"], "-title", "-tech-detect", "-status-code", "-nc"],
    install="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
)

# ---------- TLS / SSH / SMB ----------
testssl = ToolSpec(
    "testssl", "testssl.sh", "Scanning", "Comprehensive TLS configuration test.",
    [Param("target", "target", "host[:port]")], binary="testssl.sh", alt_binaries=("testssl",),
    build=lambda p, c: [c.binary, "--color", "0", "--warnings", "batch", p["target"]], install="apt install testssl.sh",
)

ssh_audit = ToolSpec(
    "ssh_audit", "ssh-audit", "Scanning", "SSH server configuration audit.",
    [Param("target", "target", "host[:port]")], binary="ssh-audit",
    build=lambda p, c: [c.binary, p["target"]], install="pip install ssh-audit",
)

enum4linux = ToolSpec(
    "enum4linux", "enum4linux-ng", "Scanning", "SMB/Windows enumeration.",
    [Param("target", "target", "Target host")], binary="enum4linux-ng",
    build=lambda p, c: [c.binary, "-A", p["target"]], install="apt install enum4linux-ng",
)

# ---------- recon ----------
subfinder = ToolSpec(
    "subfinder", "Subfinder", "Recon", "Passive subdomain discovery.",
    [Param("domain", "target", "Domain")], binary="subfinder",
    build=lambda p, c: [c.binary, "-d", p["domain"], "-silent"],
    install="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
)
amass = ToolSpec(
    "amass", "Amass (passive)", "Recon", "Passive attack-surface enumeration.",
    [Param("domain", "target", "Domain")], binary="amass",
    build=lambda p, c: [c.binary, "enum", "-passive", "-d", p["domain"]], install="apt install amass",
)
dnsrecon = ToolSpec(
    "dnsrecon", "DNSRecon", "Recon", "DNS enumeration.",
    [Param("domain", "target", "Domain"), Param("type", "choice", "Type", required=False, default="std", choices=["std", "axfr", "srv"])],
    binary="dnsrecon", build=lambda p, c: [c.binary, "-d", p["domain"], "-t", p.get("type", "std")], install="apt install dnsrecon",
)
theharvester = ToolSpec(
    "theharvester", "theHarvester", "Recon", "Emails, hosts and names from public sources.",
    [Param("domain", "target", "Domain"),
     Param("sources", "text", "Sources", required=False, default="crtsh,duckduckgo", pattern=r"^[a-z0-9,]{1,100}$"),
     Param("limit", "int", "Limit", required=False, default=200, min=10, max=2000)],
    binary="theHarvester", alt_binaries=("theharvester",),
    build=lambda p, c: [c.binary, "-d", p["domain"], "-b", p.get("sources", "crtsh,duckduckgo"), "-l", p.get("limit", 200)],
    install="apt install theharvester",
)
whois = ToolSpec(
    "whois", "whois", "Recon", "Registration data for a domain or IP.",
    [Param("target", "target", "Domain or IP")], binary="whois", build=lambda p, c: [c.binary, p["target"]], install="apt install whois",
)
dig = ToolSpec(
    "dig", "dig", "Recon", "DNS query.",
    [Param("name", "target", "Name"),
     Param("record_type", "choice", "Type", required=False, default="A",
           choices=["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "ANY"])],
    binary="dig", build=lambda p, c: [c.binary, "+noall", "+answer", p["name"], p.get("record_type", "A")], install="apt install dnsutils",
)
traceroute = ToolSpec(
    "traceroute", "traceroute", "Network", "Network path to a target.",
    [Param("target", "target", "Target")], binary="traceroute" if os.name == "posix" else "tracert",
    build=lambda p, c: [c.binary, p["target"]], install="apt install traceroute",
)
mtr = ToolSpec(
    "mtr", "mtr", "Network", "Combined traceroute and ping report.",
    [Param("target", "target", "Target")], binary="mtr",
    build=lambda p, c: [c.binary, "--report", "--report-cycles", "3", p["target"]], install="apt install mtr-tiny",
)
ping = ToolSpec(
    "ping", "ping", "Network", "ICMP reachability.",
    [Param("target", "target", "Target"), Param("count", "int", "Count", required=False, default=4, min=1, max=20)],
    binary="ping",
    build=lambda p, c: [c.binary, "-n" if os.name == "nt" else "-c", p.get("count", 4), p["target"]],
)

# ---------- cracking (offline, no targets) ----------
hashcat = ToolSpec(
    "hashcat", "hashcat", "Passwords", "Dictionary attack with hashcat. Use hashid to find the mode.",
    [Param("hash_file", "file", "File with hashes"), Param("mode", "int", "Hash mode (-m)", min=0, max=99999),
     Param("wordlist", "file", "Wordlist"), Param("rules", "file", "Rules file", required=False)],
    binary="hashcat",
    build=lambda p, c: [c.binary, "-m", p["mode"], "-a", "0", p["hash_file"], p["wordlist"]]
    + (["-r", p["rules"]] if p.get("rules") else []) + ["--quiet"],
    install="apt install hashcat", timeout=6 * 3600,
)
john = ToolSpec(
    "john", "John the Ripper", "Passwords", "Dictionary attack with john.",
    [Param("hash_file", "file", "File with hashes"), Param("wordlist", "file", "Wordlist"),
     Param("format", "text", "Format (e.g. raw-md5)", required=False, pattern=r"^[A-Za-z0-9_-]{1,40}$")],
    binary="john",
    build=lambda p, c: [c.binary, f"--wordlist={p['wordlist']}"] + ([f"--format={p['format']}"] if p.get("format") else []) + [p["hash_file"]],
    install="apt install john", timeout=6 * 3600,
)

EXTERNAL = [nmap, nuclei, nikto, testssl, ssh_audit, enum4linux, gobuster_dir, gobuster_vhost, ffuf, feroxbuster,
            whatweb, httpx, subfinder, amass, gobuster_dns, dnsrecon, theharvester, whois, dig, traceroute, mtr,
            ping, hashcat, john]

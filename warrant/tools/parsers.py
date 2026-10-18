"""Turn raw tool output into finding drafts (dicts accepted by Engagement.add_finding)."""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def safe_xml_root(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if "<!ENTITY" in text:
        raise ValueError("refusing XML with entity declarations")
    return ET.fromstring(text)


# ---------- nmap ----------
# port -> (title, severity, recommendation)
RISKY_PORTS = {
    23: ("Telnet exposed", "medium", "Disable Telnet; use SSH."),
    21: ("FTP exposed (cleartext protocol)", "low", "Replace FTP with SFTP/FTPS or restrict access."),
    69: ("TFTP exposed", "medium", "Disable TFTP or restrict it to management networks."),
    512: ("rexec/rsh service exposed", "high", "Disable r-services."),
    513: ("rlogin service exposed", "high", "Disable r-services."),
    514: ("rsh service exposed", "high", "Disable r-services."),
    445: ("SMB exposed", "low", "Restrict SMB to required hosts; ensure SMBv1 is disabled and signing required."),
    3389: ("RDP exposed", "low", "Restrict RDP behind VPN/gateway; require NLA and MFA."),
    5900: ("VNC exposed", "medium", "Restrict VNC access and require strong authentication/encryption."),
    1433: ("Microsoft SQL Server exposed", "medium", "Restrict database listeners to application hosts."),
    3306: ("MySQL exposed", "medium", "Restrict database listeners to application hosts."),
    5432: ("PostgreSQL exposed", "medium", "Restrict database listeners to application hosts."),
    27017: ("MongoDB exposed", "medium", "Restrict access and enforce authentication."),
    6379: ("Redis exposed", "medium", "Bind to localhost/internal networks and require authentication."),
    11211: ("Memcached exposed", "medium", "Restrict access; disable UDP."),
    9200: ("Elasticsearch exposed", "medium", "Restrict access and enable authentication."),
    2375: ("Docker API exposed (unencrypted)", "high", "Do not expose the Docker socket over TCP without TLS and authentication."),
    161: ("SNMP exposed", "low", "Restrict SNMP; use SNMPv3 and non-default community strings."),
}


def parse_nmap_xml(ctx):
    path = ctx.paths.get("xml")
    if not path or not Path(path).exists():
        return []
    root = safe_xml_root(path)
    drafts = []
    for host in root.findall("host"):
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype", "").startswith("ipv")), "")
        names = [h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")]
        label = addr + (f" ({names[0]})" if names else "")
        rows = []
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            num, proto = int(port.get("portid")), port.get("protocol")
            svc = port.find("service")
            desc = " ".join(x for x in [svc.get("name") if svc is not None else "", svc.get("product") if svc is not None else "",
                                        svc.get("version") if svc is not None else ""] if x)
            rows.append(f"{num}/{proto}  {desc}".rstrip())
            if num in RISKY_PORTS and proto == "tcp" or (num == 161 and proto == "udp"):
                title, sev, rec = RISKY_PORTS[num]
                drafts.append(dict(title=f"{title} on {label}", severity=sev, affected=f"{addr}:{num}/{proto}",
                                   description=f"Port {num}/{proto} is open ({desc or 'unknown service'}). "
                                               "Identified by port scan; validate whether exposure is intended.",
                                   recommendation=rec))
            for sc in port.findall("script"):
                out = sc.get("output", "")
                sid = sc.get("id", "script")
                if "VULNERABLE" in out.upper() and "NOT VULNERABLE" not in out.upper():
                    cves = sorted(set(m.upper() for m in CVE_RE.findall(out)))
                    drafts.append(dict(title=f"NSE {sid}: reported vulnerable ({label} port {num})", severity="high",
                                       affected=f"{addr}:{num}/{proto}", cve=", ".join(cves),
                                       description=out.strip()[:3000],
                                       recommendation="Validate manually, then patch or mitigate."))
                elif sid == "vulners":
                    scored = [(float(m.group(2)), m.group(1)) for m in re.finditer(r"(CVE-\d{4}-\d+)\s+(\d+\.\d)", out)]
                    if scored:
                        top = max(scored)[0]
                        drafts.append(dict(title=f"Known CVEs for {desc or 'service'} on {label}:{num}",
                                           severity=severity_from_cvss(top), affected=f"{addr}:{num}/{proto}",
                                           cve=", ".join(sorted({c for _, c in scored})[:10]),
                                           description="vulners matched version-based CVEs (unverified):\n" + out.strip()[:3000],
                                           recommendation="Confirm the installed version and patch level."))
        if rows:
            drafts.append(dict(title=f"Open ports on {label}", severity="info", affected=addr,
                               description="\n".join(rows)))
    return drafts


# ---------- content discovery ----------
SENSITIVE_PATH = re.compile(
    r"(/\.git(/|$)|/\.env|/\.svn|/\.DS_Store|/id_rsa|\.sql(\.gz)?$|/backup|\.bak$|\.old$|/phpinfo|/server-status|"
    r"/\.htpasswd|/wp-config|/config\.(php|json|yml|yaml)|/actuator|/admin|/console|/\.aws|/\.ssh)", re.I)


def sensitive_paths_finding(source, base, hits):
    """hits: list of (url, status). One finding for the interesting ones."""
    interesting = [(u, s) for u, s in hits if SENSITIVE_PATH.search(u) and str(s) in ("200", "301", "302", "401", "403")]
    if not interesting:
        return []
    uniq = sorted(set(interesting))[:60]
    return [dict(title=f"Potentially sensitive paths discovered ({source})", severity="medium", affected=base,
                 description="Content discovery found paths that commonly expose sensitive data or admin functionality. "
                             "Validate each manually.\n" + "\n".join(f"{s}  {u}" for u, s in uniq),
                 recommendation="Remove unneeded files/endpoints and restrict access to administrative interfaces.")]


def parse_ffuf(ctx):
    path = ctx.paths.get("json")
    if not path or not Path(path).exists():
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace") or "{}")
    hits = [(r.get("url", ""), r.get("status", "")) for r in data.get("results", [])]
    return sensitive_paths_finding("ffuf", data.get("config", {}).get("url", ""), hits)


def parse_dirlines(ctx):
    """gobuster dir lines '/path (Status: 200)' and feroxbuster '200 GET ... http://x/y'."""
    hits = []
    for line in ctx.output.splitlines():
        m = re.search(r"(\S+)\s+\(Status:\s*(\d{3})", line)
        if m:
            hits.append((m.group(1), m.group(2)))
            continue
        m = re.match(r"\s*(\d{3})\s+\w+\s+.*?(https?://\S+)", line)
        if m:
            hits.append((m.group(2), m.group(1)))
    return sensitive_paths_finding(ctx.spec.id, "", hits)


# ---------- nuclei / nikto ----------
def parse_nuclei(ctx):
    path = ctx.paths.get("jsonl")
    if not path or not Path(path).exists():
        return []
    drafts = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        info = r.get("info", {})
        cls = info.get("classification") or {}
        cve = cls.get("cve-id") or []
        cvss = cls.get("cvss-score")
        refs = info.get("reference") or []
        sev = (info.get("severity") or "info").lower()
        drafts.append(dict(
            title=f"{info.get('name', r.get('template-id', 'nuclei finding'))}",
            severity=sev if sev in ("critical", "high", "medium", "low", "info") else "info",
            affected=r.get("matched-at") or r.get("host", ""),
            description=(info.get("description") or "") + f"\nTemplate: {r.get('template-id', '')}",
            recommendation="See references: " + ", ".join(refs[:3]) if refs else "",
            cve=", ".join(cve) if isinstance(cve, list) else str(cve or ""),
            cvss=str(cvss) if cvss else "",
        ))
    return drafts


def parse_nikto(ctx):
    path = ctx.paths.get("json")
    if not path or not Path(path).exists():
        return []
    text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    data = json.loads(text)
    items = []

    def walk(o):
        if isinstance(o, dict):
            if isinstance(o.get("vulnerabilities"), list):
                items.extend(v for v in o["vulnerabilities"] if isinstance(v, dict))
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(data)
    if not items:
        return []
    lines = [f"{v.get('method', 'GET')} {v.get('url', '')}: {v.get('msg', '')}" for v in items[:80]]
    return [dict(title="Nikto web server observations", severity="low", affected="",
                 description="Nikto reported the following; many entries are informational and need manual validation.\n"
                             + "\n".join(lines),
                 recommendation="Review each observation; remove default files, update the server and harden configuration.")]

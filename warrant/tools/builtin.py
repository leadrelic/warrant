"""Built-in tools: pure-Python checks that need no external binaries. All scope-checked via their target params."""

import json
import os
import re
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.request
import warnings
from contextlib import closing
from datetime import datetime
from urllib.parse import urlsplit

from .. import __version__
from ..runner import ToolSpec
from ..scope import parse_target
from ..validate import Param

UA = f"warrant/{__version__}"


# ---------- HTTP helper (no redirects, no proxies, certificate errors tolerated) ----------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def http_get(url, timeout=10, max_bytes=65536):
    """Returns (status, headers, body). Never follows redirects, so requests cannot leave the checked host."""
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect, urllib.request.HTTPSHandler(context=tls))
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    except (urllib.error.URLError, OSError) as e:
        raise ConnectionError(f"{url}: {getattr(e, 'reason', e)}") from None
    with closing(resp):
        body = resp.read(max_bytes)
        return getattr(resp, "status", None) or resp.code, resp.headers, body


# ---------- security headers ----------
def run_headers(p, ctx):
    url = p["url"]
    host = urlsplit(url).hostname
    yield f"GET {url}"
    status, headers, _ = http_get(url)
    yield f"HTTP {status}"
    for k, v in headers.items():
        yield f"  {k}: {v}"
    low = {k.lower(): v for k, v in headers.items()}
    https = url.lower().startswith("https")
    missing = []
    if https and "strict-transport-security" not in low:
        missing.append("Strict-Transport-Security")
    csp = low.get("content-security-policy", "")
    if not csp:
        missing.append("Content-Security-Policy")
    if "x-frame-options" not in low and "frame-ancestors" not in csp:
        missing.append("X-Frame-Options or CSP frame-ancestors")
    if low.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff")
    if "referrer-policy" not in low:
        missing.append("Referrer-Policy")
    if missing:
        ctx.draft(title=f"Missing HTTP security headers on {host}", severity="low", affected=url,
                  description="The response did not include: " + ", ".join(missing) + ".",
                  recommendation="Add the missing headers at the web server or application layer.")
    bad = []
    for c in headers.get_all("Set-Cookie") or []:
        parts = [x.strip() for x in c.split(";")]
        name, attrs = parts[0].split("=", 1)[0], [a.lower() for a in parts[1:]]
        issues = []
        if https and "secure" not in attrs:
            issues.append("Secure")
        if "httponly" not in attrs:
            issues.append("HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            issues.append("SameSite")
        if issues:
            bad.append(f"{name}: missing {', '.join(issues)}")
    if bad:
        ctx.draft(title=f"Cookies missing security attributes on {host}", severity="low", affected=url,
                  description="\n".join(bad), recommendation="Set Secure, HttpOnly and SameSite on session cookies.")
    leaks = [f"{h}: {low[h]}" for h in ("server", "x-powered-by", "x-aspnet-version") if h in low and re.search(r"\d", low[h])]
    if leaks:
        ctx.draft(title=f"Software version disclosure on {host}", severity="info", affected=url,
                  description="\n".join(leaks), recommendation="Suppress version details in response headers.")
    acao, acac = low.get("access-control-allow-origin", ""), low.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        ctx.draft(title=f"Permissive CORS with credentials on {host}", severity="medium", affected=url,
                  description="Access-Control-Allow-Origin: * together with Allow-Credentials: true.",
                  recommendation="Return a specific allowed origin and never combine wildcard origins with credentials.")
    if 300 <= status < 400 and "location" in low:
        yield f"[i] redirect to {low['location']} (not followed)"


headers_audit = ToolSpec(
    "headers_audit", "HTTP security headers", "Web", "Checks security headers, cookies, CORS and version disclosure. Does not follow redirects.",
    [Param("url", "url", "URL")], run=run_headers,
)


# ---------- TLS ----------
def _decode_cert(der):
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        name = f.name
    try:
        return ssl._ssl._test_decode_cert(name)
    except Exception:
        return {}
    finally:
        os.unlink(name)


def _open_tls(host, port, context, timeout=8):
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        return context.wrap_socket(sock, server_hostname=None if re.fullmatch(r"[\d.:a-fA-F]+", host) else host)
    except BaseException:
        sock.close()
        raise


def _loose_context(version=None):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        try:
            c.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        if version is not None:
            c.minimum_version = c.maximum_version = version
    return c


def run_tls(p, ctx):
    host, port = parse_target(p["target"]).host, p.get("port", 443)
    affected = f"{host}:{port}"
    with _open_tls(host, port, _loose_context()) as s:
        version, cipher, der = s.version(), s.cipher(), s.getpeercert(True)
    yield f"Negotiated: {version}  {cipher[0] if cipher else '?'}"
    if cipher and re.search(r"RC4|3DES|DES-CBC|NULL|EXPORT|MD5|anon", cipher[0], re.I):
        ctx.draft(title=f"Weak TLS cipher negotiated on {affected}", severity="medium", affected=affected,
                  description=f"Server negotiated {cipher[0]}.", recommendation="Disable weak ciphers (RC4, 3DES, NULL, EXPORT, anonymous).")

    verify_error = None
    try:
        with _open_tls(host, port, ssl.create_default_context()):
            pass
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message
    except (ssl.SSLError, OSError) as e:
        verify_error = str(e)
    if verify_error:
        yield f"Certificate validation: FAILED ({verify_error})"
        ctx.draft(title=f"TLS certificate validation fails on {affected}", severity="medium", affected=affected,
                  description=f"Default trust store validation failed: {verify_error}.",
                  recommendation="Install a certificate from a trusted CA that matches the hostname.")
    else:
        yield "Certificate validation: ok"

    cert = _decode_cert(der) if der else {}
    if cert.get("notAfter"):
        days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
        yield f"Certificate expires: {cert['notAfter']} ({days} days)"
        if days < 0:
            ctx.draft(title=f"Expired TLS certificate on {affected}", severity="medium", affected=affected,
                      description=f"Certificate expired {-days} days ago ({cert['notAfter']}).", recommendation="Renew the certificate.")
        elif days < 30:
            ctx.draft(title=f"TLS certificate expires soon on {affected}", severity="low", affected=affected,
                      description=f"Certificate expires in {days} days.", recommendation="Renew the certificate.")
    if cert.get("subject") and cert.get("issuer"):
        yield f"Subject: {_dn(cert['subject'])}   Issuer: {_dn(cert['issuer'])}"

    accepted = []
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                      ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
        try:
            c = _loose_context(ver)
        except (ValueError, ssl.SSLError):
            yield f"  {name}: not testable with this local OpenSSL"
            continue
        try:
            with _open_tls(host, port, c):
                accepted.append(name)
                yield f"  {name}: accepted"
        except (ssl.SSLError, OSError):
            yield f"  {name}: rejected"
    old = [v for v in accepted if v in ("TLSv1.0", "TLSv1.1")]
    if old:
        ctx.draft(title=f"Deprecated TLS versions enabled on {affected}", severity="medium", affected=affected,
                  description="Server accepts " + ", ".join(old) + ".", recommendation="Disable TLS 1.0/1.1; require TLS 1.2 or later.")


def _dn(parts):
    return ", ".join(f"{k}={v}" for rdn in parts for k, v in rdn)


tls_audit = ToolSpec(
    "tls_audit", "TLS audit", "Scanning", "Certificate validity/expiry, accepted protocol versions, negotiated cipher.",
    [Param("target", "target", "Host"), Param("port", "int", "Port", required=False, default=443, min=1, max=65535)], run=run_tls,
)


# ---------- exposed files ----------
EXPOSURE_CHECKS = [
    ("/.git/HEAD", lambda b: b.startswith(b"ref:"), "Exposed .git directory", "high",
     "Source code and history can be downloaded.", "Block access to .git and remove it from the web root."),
    ("/.env", lambda b: re.search(rb"^[A-Z][A-Z0-9_]+=", b, re.M) is not None, "Exposed .env file", "high",
     "Environment file with likely secrets is downloadable.", "Remove the file from the web root and rotate any secrets it contains."),
    ("/.svn/entries", lambda b: len(b) > 0 and b[:1] in b"0123456789", "Exposed .svn directory", "medium",
     "Subversion metadata is downloadable.", "Block access to .svn directories."),
    ("/.DS_Store", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1"), "Exposed .DS_Store file", "low",
     "Directory listing metadata is downloadable.", "Remove .DS_Store files from the web root."),
    ("/phpinfo.php", lambda b: b"phpinfo()" in b or b"PHP Version" in b, "phpinfo() page exposed", "medium",
     "Detailed PHP/server configuration is visible.", "Remove the phpinfo page."),
    ("/server-status", lambda b: b"Apache Server Status" in b, "Apache server-status exposed", "medium",
     "Live request and server information is visible.", "Restrict /server-status to localhost or admin networks."),
    ("/actuator/env", lambda b: b"propertySources" in b, "Spring Boot actuator /env exposed", "high",
     "Configuration properties (possibly credentials) are exposed.", "Disable or authenticate actuator endpoints."),
    ("/.htpasswd", lambda b: re.search(rb"^[^:\s]+:\$?[\w./$]+", b, re.M) is not None, ".htpasswd exposed", "high",
     "Password hashes are downloadable.", "Remove the file from the web root and reset affected passwords."),
]


def run_exposure(p, ctx):
    parts = urlsplit(p["url"])
    base = f"{parts.scheme}://{parts.netloc}"
    yield f"Checking {len(EXPOSURE_CHECKS) + 2} well-known paths on {base}"
    for path in ("/robots.txt", "/.well-known/security.txt"):
        try:
            status, _, body = http_get(base + path, max_bytes=2048)
            yield f"  {path}: HTTP {status}" + (" (present)" if status == 200 else "")
        except ConnectionError as e:
            yield f"  {path}: {e}"
    for path, test, title, sev, desc, rec in EXPOSURE_CHECKS:
        ctx.check_cancel()
        try:
            status, _, body = http_get(base + path, max_bytes=4096)
        except ConnectionError as e:
            yield f"  {path}: {e}"
            continue
        hit = status == 200 and test(body)
        yield f"  {path}: HTTP {status}" + ("  <-- EXPOSED" if hit else "")
        if hit:
            ctx.draft(title=f"{title} on {parts.hostname}", severity=sev, affected=base + path,
                      description=desc, recommendation=rec)


web_exposure = ToolSpec(
    "web_exposure", "Exposed files check", "Web", "Checks a handful of well-known sensitive paths (.git, .env, phpinfo...). No redirects followed.",
    [Param("url", "url", "Base URL")], run=run_exposure,
)


# ---------- certificate transparency ----------
def run_crtsh(p, ctx):
    domain = parse_target(p["domain"]).host
    yield f"Querying crt.sh for %.{domain} ..."
    req = urllib.request.Request(f"https://crt.sh/?q=%25.{domain}&output=json", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            data = json.loads(r.read(20_000_000).decode("utf-8", "replace") or "[]")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise ConnectionError(f"crt.sh lookup failed: {e}") from None
    names = set()
    for entry in data:
        for n in str(entry.get("name_value", "")).splitlines():
            n = n.strip().lstrip("*.").lower()
            if n.endswith(domain) and re.fullmatch(r"[a-z0-9.-]+", n):
                names.add(n)
    scope = ctx.engagement.scope if ctx.engagement else None
    in_scope = []
    yield f"{len(names)} unique names:"
    for n in sorted(names):
        ok = bool(scope and scope.check(n, resolve=False).allowed)
        in_scope.append(n) if ok else None
        yield f"  {'[in scope]    ' if ok else '[not listed] '}{n}"
    if names:
        ctx.draft(title=f"Certificate transparency: {len(names)} hostnames for {domain}", severity="info", affected=domain,
                  description="\n".join(sorted(names)[:300]),
                  recommendation="Review for forgotten or shadow hosts; add confirmed assets to scope.")


crtsh = ToolSpec(
    "crtsh", "crt.sh subdomains", "Recon", "Passive subdomain discovery from certificate transparency; marks which names are in scope.",
    [Param("domain", "target", "Domain")], run=run_crtsh,
)


# ---------- hash identification ----------
HASHES = [
    (r"^[a-fA-F0-9]{32}$", [("MD5", 0, "raw-md5"), ("NTLM", 1000, "nt"), ("MD4", 900, "raw-md4")]),
    (r"^[a-fA-F0-9]{40}$", [("SHA-1", 100, "raw-sha1"), ("RIPEMD-160", 6000, "ripemd-160")]),
    (r"^[a-fA-F0-9]{56}$", [("SHA-224", 1300, "raw-sha224")]),
    (r"^[a-fA-F0-9]{64}$", [("SHA-256", 1400, "raw-sha256"), ("SHA3-256", 17400, "raw-sha3")]),
    (r"^[a-fA-F0-9]{96}$", [("SHA-384", 10800, "raw-sha384")]),
    (r"^[a-fA-F0-9]{128}$", [("SHA-512", 1700, "raw-sha512"), ("Whirlpool", 6100, "whirlpool")]),
    (r"^\*[A-F0-9]{40}$", [("MySQL 4.1+", 300, "mysql-sha1")]),
    (r"^\$2[aby]?\$\d\d\$[./A-Za-z0-9]{53}$", [("bcrypt", 3200, "bcrypt")]),
    (r"^\$1\$", [("md5crypt", 500, "md5crypt")]),
    (r"^\$apr1\$", [("Apache MD5 (apr1)", 1600, "md5crypt-long")]),
    (r"^\$5\$", [("sha256crypt", 7400, "sha256crypt")]),
    (r"^\$6\$", [("sha512crypt", 1800, "sha512crypt")]),
    (r"^\$[PH]\$", [("phpass (WordPress/phpBB)", 400, "phpass")]),
    (r"^\$krb5tgs\$23\$", [("Kerberoast RC4 (TGS-REP)", 13100, "krb5tgs")]),
    (r"^\$krb5asrep\$23\$", [("AS-REP roast", 18200, "krb5asrep")]),
    (r"^[^:\s]+::[^:]*:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$", [("NetNTLMv2", 5600, "netntlmv2")]),
    (r"^[^:\s]+::[^:]*:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$", [("NetNTLMv1", 5500, "netntlm")]),
    (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", [("LM:NT pair (use the NT half with mode 1000)", 1000, "nt")]),
    (r"^pbkdf2_sha256\$", [("Django PBKDF2-SHA256", 10000, "django")]),
]


def run_hashid(p, ctx):
    h = p["hash"].strip()
    found = [(n, m, j) for rx, cands in HASHES if re.match(rx, h) for n, m, j in cands]
    if not found:
        yield "No match. Check for a username/salt prefix or an unusual format."
        return
    yield f"{'type':<44}{'hashcat -m':<12}john --format"
    for n, m, j in found:
        yield f"{n:<44}{m:<12}{j}"


hashid = ToolSpec(
    "hashid", "Hash identifier", "Passwords", "Offline: suggests hash types with hashcat modes and john formats.",
    [Param("hash", "text", "Hash", pattern=r"^[\x21-\x7e]{4,1024}$")], run=run_hashid,
)


# ---------- wordlist generator ----------
LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"})


def run_wordlist(p, ctx):
    words = [w.strip() for w in p["words"].split(",") if w.strip()]
    suffixes = ["", "1", "12", "123", "1234", "!", "!!", "@", "#", "123!", "1!", "2023", "2024", "2025", "2026"]
    if p.get("years", True):
        suffixes += [str(y) for y in range(2015, datetime.now().year + 2)] + [str(y) + "!" for y in range(2020, datetime.now().year + 2)]
    out, limit = {}, p.get("max_entries", 200000)
    for w in words:
        for base in {w, w.lower(), w.capitalize(), w.upper(), w.lower().translate(LEET), w.capitalize().translate(LEET)}:
            for s in suffixes:
                out[base + s] = None
                if len(out) >= limit:
                    break
    path = ctx.paths["list"]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    yield f"Wrote {len(out)} candidates to {path}"


wordlist_gen = ToolSpec(
    "wordlist_gen", "Wordlist generator", "Passwords", "Offline: mutates base words (case, leetspeak, years, common suffixes).",
    [Param("words", "text", "Base words (comma separated)", pattern=r"^[A-Za-z0-9 ,._@!-]{1,200}$"),
     Param("years", "bool", "Append years", required=False, default=True),
     Param("max_entries", "int", "Max entries", required=False, default=200000, min=100, max=2000000)],
    run=run_wordlist, outputs={"list": ".list.txt"},
)

BUILTIN = [headers_audit, tls_audit, web_exposure, crtsh, hashid, wordlist_gen]

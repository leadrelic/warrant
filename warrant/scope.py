"""
Scope enforcement. Every target a tool will touch goes through Scope.check() first.

Rules (deliberately strict):
  * No scope defined -> deny, unless the engagement explicitly allows unscoped use.
  * IP/CIDR/range targets must be entirely inside one include network and must not
    overlap any exclusion.
  * Hostnames are allowed if they match an include domain (example.com covers itself
    and its subdomains), or if every address they resolve to is inside an include
    network. Any resolved address inside an exclusion denies the target.
  * Anything that looks like an option (leading '-'), contains whitespace or shell
    metacharacters is rejected outright.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import urlsplit

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}$")
RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
_FORBIDDEN = set(";|&$`<>\\\"'(){}!*?^~#\n\r\t ")


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str                 # "ip" | "network" | "hostname"
    host: str                 # normalised host / network string
    networks: tuple = ()      # ip_network objects for ip/network kinds


def parse_target(raw: str, allow_wildcard: bool = False) -> Target:
    s = (raw or "").strip()
    if not s:
        raise TargetError("empty target")
    if len(s) > 2048:
        raise TargetError("target too long")
    if s.startswith("-"):
        raise TargetError("target must not start with '-'")
    if allow_wildcard and s.startswith("*."):
        s = s[2:]
    if any(c.isspace() or ord(c) < 32 for c in s):
        raise TargetError(f"whitespace/control characters in target: {raw!r}")

    if "://" in s:
        try:
            host = urlsplit(s).hostname
        except ValueError as e:
            raise TargetError(f"bad URL: {e}") from None
        if not host:
            raise TargetError("URL has no host")
        s = host
    if "://" not in raw and any(c in _FORBIDDEN for c in s):
        raise TargetError(f"illegal characters in target: {raw!r}")

    if s.startswith("["):                      # [v6]:port
        end = s.find("]")
        if end < 0:
            raise TargetError("bad IPv6 literal")
        s = s[1:end]
    elif s.count(":") == 1 and "/" not in s:    # host:port
        head, port = s.rsplit(":", 1)
        if port.isdigit() and 0 < int(port) < 65536:
            s = head

    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as e:
            raise TargetError(f"bad network {raw!r}: {e}") from None
        return Target(raw.strip(), "network", str(net), (net,))

    try:
        ip = ipaddress.ip_address(s)
        return Target(raw.strip(), "ip", str(ip), (ipaddress.ip_network(ip),))
    except ValueError:
        pass

    m = RANGE_RE.match(s)
    if m:
        prefix, a, b = m.group(1), int(m.group(2)), int(m.group(3))
        try:
            lo = ipaddress.ip_address(prefix + str(a))
            hi = ipaddress.ip_address(prefix + str(b))
        except ValueError:
            raise TargetError(f"bad range {raw!r}") from None
        if a > b:
            raise TargetError(f"bad range {raw!r}")
        return Target(raw.strip(), "network", s, tuple(ipaddress.summarize_address_range(lo, hi)))

    if re.fullmatch(r"[\d.]+", s):
        raise TargetError(f"invalid IP address {raw!r}")
    s = s.rstrip(".").lower()
    if len(s) > 253 or not HOSTNAME_RE.match(s):
        raise TargetError(f"invalid hostname {raw!r}")
    return Target(raw.strip(), "hostname", s)


def validate_scope_item(item: str) -> str:
    """Normalise a scope entry or raise TargetError. Wildcards (*.x.com) become x.com."""
    t = parse_target(item, allow_wildcard=True)
    return t.host if t.kind == "hostname" else (t.host if t.kind == "network" else t.host)


def default_resolver(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    seen = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        if addr not in seen:
            seen.append(addr)
    return seen


@dataclass
class Decision:
    allowed: bool
    reason: str
    target: str = ""
    resolved: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _domain_match(host: str, domains) -> Optional[str]:
    for d in domains:
        if host == d or host.endswith("." + d):
            return d
    return None


def _net_contains(nets, ip) -> Optional[object]:
    for n in nets:
        if n.version == ip.version and ip in n:
            return n
    return None


class Scope:
    def __init__(self, includes=(), excludes=(), allow_unscoped=False,
                 resolver: Callable[[str], List[str]] = default_resolver):
        self.includes = list(includes)
        self.excludes = list(excludes)
        self.allow_unscoped = allow_unscoped
        self.resolver = resolver
        self.inc_nets, self.inc_domains = self._split(self.includes)
        self.exc_nets, self.exc_domains = self._split(self.excludes)

    @staticmethod
    def _split(items):
        nets, domains = [], []
        for item in items:
            t = parse_target(item, allow_wildcard=True)
            if t.kind == "hostname":
                domains.append(t.host)
            else:
                nets.extend(t.networks)
        return nets, domains

    def check(self, raw: str, resolve: bool = True) -> Decision:
        try:
            t = parse_target(raw)
        except TargetError as e:
            return Decision(False, str(e), str(raw))

        if t.kind in ("ip", "network"):
            for n in t.networks:
                for e in self.exc_nets:
                    if n.version == e.version and n.overlaps(e):
                        return Decision(False, f"overlaps excluded range {e}", t.raw)
            covered = all(any(n.version == i.version and n.subnet_of(i) for i in self.inc_nets) for n in t.networks)
            if covered and self.inc_nets:
                return Decision(True, "inside scope", t.raw)
            return self._unscoped(t, "outside defined scope" if (self.inc_nets or self.inc_domains) else "no scope defined")

        host = t.host
        hit = _domain_match(host, self.exc_domains)
        if hit:
            return Decision(False, f"excluded domain {hit}", t.raw)
        ips = self.resolver(host) if resolve else []
        parsed = []
        for a in ips:
            try:
                parsed.append(ipaddress.ip_address(a))
            except ValueError:
                continue
        for ip in parsed:
            e = _net_contains(self.exc_nets, ip)
            if e:
                return Decision(False, f"resolves to excluded address {ip} ({e})", t.raw, ips)

        dom = _domain_match(host, self.inc_domains)
        if dom:
            warns = []
            if self.inc_nets:
                outside = [str(ip) for ip in parsed if not _net_contains(self.inc_nets, ip)]
                if outside:
                    warns.append("resolves outside listed networks: " + ", ".join(outside)
                                 + " (possible third-party/CDN hosting)")
            return Decision(True, f"matches domain {dom}", t.raw, ips, warns)
        if parsed and all(_net_contains(self.inc_nets, ip) for ip in parsed):
            return Decision(True, "all resolved addresses inside scope", t.raw, ips)
        reason = "outside defined scope" if (self.inc_nets or self.inc_domains) else "no scope defined"
        if not parsed and (self.inc_nets or self.inc_domains):
            reason = "does not resolve and matches no scope domain"
        return self._unscoped(t, reason, ips)

    def _unscoped(self, t: Target, reason: str, ips=None) -> Decision:
        if self.allow_unscoped:
            return Decision(True, "UNSCOPED mode: " + reason, t.raw, ips or [], ["target not verified against scope"])
        return Decision(False, reason, t.raw, ips or [])

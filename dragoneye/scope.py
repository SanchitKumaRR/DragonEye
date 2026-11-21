"""Scope engine.

Every target DragonEye touches passes through `Scope.check()`. This module is
deliberately boring, dependency-free and heavily tested: it is the difference
between recon and a felony.

Rule syntax (one per line, `#` comments allowed):

    example.com        apex + all subdomains
    *.example.com      subdomains only (no apex)
    .example.com       subdomains only (same as *.example.com)
    re:^api[0-9]+\\.    regular expression against the hostname
    10.10.0.0/16       CIDR block (matches IPs and resolving hosts)
    203.0.113.7        single IP
    AS15169            ASN (only matches when the asset carries an ASN)
    https://x.tld/...  URL -> reduced to its hostname

Precedence: out-of-scope (deny) always wins, then in-scope (allow), then deny.
Anything unmatched is out of scope. Unparseable rules raise ScopeError at load
time, so a broken program config fails closed before any traffic is sent.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Sequence
from urllib.parse import urlsplit

LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
ASN_RE = re.compile(r"as(\d{1,10})$", re.I)

# Never touch these, regardless of what the program says.
BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.169.254/32",  # AWS/GCP/Azure metadata
        "fd00:ec2::254/128",  # AWS metadata over IPv6
        "100.100.100.200/32",  # Alibaba metadata
    )
)


class ScopeError(ValueError):
    """Raised for an invalid scope rule or target."""


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    host: str
    reason: str
    rule: str | None = None

    def __bool__(self) -> bool:  # `if scope.check(x):`
        return self.allowed

    def __str__(self) -> str:
        mark = "IN " if self.allowed else "OUT"
        return f"[{mark}] {self.host}: {self.reason}"


@dataclass(frozen=True)
class Rule:
    raw: str
    kind: str  # domain | wildcard | cidr | ip | regex | asn
    value: str
    regex: re.Pattern[str] | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    port: int | None = None
    note: str | None = None

    def matches(self, host: str, asn: int | None = None) -> bool:
        if self.kind == "regex":
            return bool(self.regex and self.regex.search(host))
        if self.kind == "ip":
            return host == self.value
        if self.kind == "cidr":
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                return False
            return self.network is not None and ip in self.network
        if self.kind == "asn":
            return asn is not None and str(asn) == self.value
        if self.kind == "wildcard":
            return host.endswith("." + self.value) and host != self.value
        if self.kind == "domain":
            return host == self.value or host.endswith("." + self.value)
        return False

    def describe(self) -> str:
        label = self.kind
        if self.note:
            label += f", {self.note}"
        return f"{self.raw} ({label})"


def normalize_host(target: str) -> str:
    """Reduce any user/tool input to a bare lowercase hostname or IP."""
    raw = (target or "").strip()
    if not raw:
        raise ScopeError("empty target")

    if "://" in raw:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        port = parts.port
    else:
        value = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in value:  # strip userinfo
            value = value.rsplit("@", 1)[1]
        port = None
        if value.startswith("["):  # [::1]:8443
            host, _, rest = value.partition("]")
            host = host.lstrip("[")
            if rest.startswith(":"):
                port = _as_port(rest[1:])
        elif value.count(":") == 1:  # host:port (but not bare IPv6)
            host, _, maybe_port = value.partition(":")
            port = _as_port(maybe_port)
        else:
            host = value
        if port is None:
            port = None

    host = host.strip().strip(".").lower()
    if not host:
        raise ScopeError(f"cannot extract a host from {target!r}")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeError(f"invalid hostname {host!r}") from exc


def _as_port(value: str) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def parse_rule(raw: str) -> Rule:
    text = (raw or "").strip()
    if not text:
        raise ScopeError("empty rule")

    if text.lower().startswith("re:"):
        pattern = text[3:].strip()
        if not pattern:
            raise ScopeError(f"empty regex in rule {raw!r}")
        try:
            return Rule(text, "regex", pattern, regex=re.compile(pattern, re.I))
        except re.error as exc:
            raise ScopeError(f"bad regex {pattern!r}: {exc}") from exc

    match = ASN_RE.match(text)
    if match:
        return Rule(text, "asn", match.group(1))

    port = None
    host_part = text
    if "://" in text:
        host_part = normalize_host(text)
        port = _as_port(urlsplit(text).port or "")
    else:
        candidate = text.split("/", 1)[0]
        if candidate.count(":") == 1 and not text.startswith("["):
            maybe_host, _, maybe_port = candidate.partition(":")
            if _as_port(maybe_port) is not None:
                host_part, port = maybe_host, _as_port(maybe_port)

    if "/" in text and "://" not in text:  # CIDR
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ScopeError(f"bad CIDR {text!r}: {exc}") from exc
        return Rule(text, "cidr", str(network), network=network)

    try:
        ip = ipaddress.ip_address(host_part)
    except ValueError:
        ip = None
    if ip is not None:
        return Rule(text, "ip", str(ip), port=port)

    value = host_part.strip().lower()
    if "*" in value:
        if not value.startswith("*."):
            raise ScopeError(
                f"unsupported wildcard position in {raw!r} (only leading '*.' is supported)"
            )
        value = value[2:]
        kind = "wildcard"
    elif value.startswith("."):
        value = value.lstrip(".")
        kind = "wildcard"
    else:
        value = value.strip(".")
        kind = "domain"

    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeError(f"invalid hostname in rule {raw!r}") from exc

    label_source = value
    labels = value.split(".")
    if not value or not all(LABEL_RE.match(lbl) for lbl in labels):
        # Allow bare single-label hosts (e.g. "localhost" tests) but reject junk.
        if not all(re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", lbl) for lbl in labels):
            raise ScopeError(f"invalid hostname in rule {raw!r}")
    if len(label_source) > 253:
        raise ScopeError(f"hostname too long in rule {raw!r}")

    note = "port ignored" if port else None
    return Rule(text, kind, value, port=port, note=note)


class Scope:
    """An ordered allow/deny rule set for one program."""

    def __init__(
        self,
        in_scope: Sequence[str],
        out_of_scope: Sequence[str] = (),
        *,
        allow_private: bool = False,
    ) -> None:
        self.allow: list[Rule] = [parse_rule(r) for r in _clean(in_scope)]
        self.deny: list[Rule] = [parse_rule(r) for r in _clean(out_of_scope)]
        self.allow_private = allow_private
        if not self.allow:
            raise ScopeError("program has no in-scope rules; refusing to run")

    # -- checks ------------------------------------------------------------

    def check(self, target: str, asn: int | None = None) -> ScopeDecision:
        host = normalize_host(target)

        try:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = (
                ipaddress.ip_address(host)
            )
        except ValueError:
            ip = None

        if ip is not None:
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    return ScopeDecision(False, host, "cloud metadata endpoint is never allowed")
            if not self.allow_private and (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return ScopeDecision(
                    False,
                    host,
                    "private/loopback/reserved address (use --allow-private to override)",
                )

        for rule in self.deny:
            if rule.matches(host, asn):
                return ScopeDecision(False, host, f"matched out-of-scope rule {rule.raw!r}", rule.raw)

        for rule in self.allow:
            if rule.matches(host, asn):
                return ScopeDecision(True, host, f"matched in-scope rule {rule.raw!r}", rule.raw)

        return ScopeDecision(False, host, "not matched by any in-scope rule")

    def screen_ip(self, target: str) -> ScopeDecision:
        """Screening for IPs *discovered* via DNS for an allowed hostname.

        A domain being in scope does not mean every address it resolves to is.
        Unlike `check()`, an unmatched IP is not rejected (most programs scope by
        domain only), but metadata endpoints, private ranges and explicit deny
        rules still win.
        """
        host = normalize_host(target)
        try:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
        except ValueError:
            return ScopeDecision(True, host, "not an IP")
        if ip is None:
            return ScopeDecision(True, host, "not an IP")

        for network in BLOCKED_NETWORKS:
            if ip in network:
                return ScopeDecision(False, host, "resolved to a cloud metadata endpoint")
        if not self.allow_private and (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return ScopeDecision(
                False,
                host,
                "resolved to a private/loopback/reserved address (use --allow-private)",
            )
        for rule in self.deny:
            if rule.matches(host):
                return ScopeDecision(False, host, f"resolved into out-of-scope rule {rule.raw!r}", rule.raw)
        return ScopeDecision(True, host, "no explicit denial")

    def in_scope(self, target: str, asn: int | None = None) -> bool:
        return self.check(target, asn).allowed

    def filter(self, targets: Iterable[str]) -> tuple[list[str], list[ScopeDecision]]:
        """Split targets into (allowed targets, rejected decisions).

        Allowed targets are returned **as given** (a URL stays a URL), because
        tools like katana and nuclei need the scheme and path. Deduplication is
        on the literal target, not the host.
        """
        allowed: list[str] = []
        rejected: list[ScopeDecision] = []
        seen: set[str] = set()
        for target in targets:
            literal = str(target).strip()
            if not literal or literal.lower() in seen:
                continue
            try:
                decision = self.check(literal)
            except ScopeError as exc:
                rejected.append(ScopeDecision(False, literal, f"invalid target: {exc}"))
                continue
            seen.add(literal.lower())
            if decision.allowed:
                allowed.append(literal)
            else:
                rejected.append(decision)
        return allowed, rejected

    # -- introspection -----------------------------------------------------

    def roots(self) -> list[str]:
        """Seed hosts implied by the in-scope rules (skip regex/asn/CIDR).

        Single IPs are seedable (useful for labs and IP-scoped programs); CIDR
        blocks are not expanded, because nobody wants 65k seeds.
        """
        seeds: list[str] = []
        for rule in self.allow:
            if rule.kind in ("domain", "ip") and rule.value not in seeds:
                seeds.append(rule.value)
        return seeds

    def summary(self) -> dict[str, object]:
        return {
            "in_scope": [r.describe() for r in self.allow],
            "out_of_scope": [r.describe() for r in self.deny],
            "allow_private": self.allow_private,
            "seeds": self.roots(),
        }


def _clean(rules: Iterable[str]) -> list[str]:
    out: list[str] = []
    for line in rules:
        if line is None:
            continue
        for chunk in str(line).splitlines():
            chunk = chunk.strip()
            if chunk and not chunk.startswith("#"):
                out.append(chunk)
    return out

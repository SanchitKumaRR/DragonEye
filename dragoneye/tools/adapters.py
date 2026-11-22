"""Adapters for the v1 tool set (ProjectDiscovery-first, all optional)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .base import ToolAdapter, ToolSpec

OUT = "out.txt"


class Subfinder(ToolAdapter):
    spec = ToolSpec(
        name="subfinder",
        binary="subfinder",
        passive=True,
        description="Passive subdomain enumeration (no packets to the target)",
        install_hint="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        homepage="https://github.com/projectdiscovery/subfinder",
    )

    def build(self, targets: list[str], workdir: Path) -> list[str]:
        domains = workdir / "domains.txt"
        self.write_list(domains, targets)
        return [
            "subfinder", "-dL", str(domains), "-silent", "-duc",
            "-o", str(workdir / OUT),
        ]

    def parse(self, workdir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        assets = []
        for line in self.read_lines(workdir / OUT):
            host = line.split()[0].lower().strip(".")
            if host and "." in host:
                assets.append(
                    {"kind": "domain", "value": host, "meta": {"source": "subfinder", "passive": True}}
                )
        return assets, []


class Dnsx(ToolAdapter):
    spec = ToolSpec(
        name="dnsx",
        binary="dnsx",
        passive=False,
        description="DNS resolution - drops dead hosts before probing",
        install_hint="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        homepage="https://github.com/projectdiscovery/dnsx",
    )

    def build(self, targets: list[str], workdir: Path) -> list[str]:
        self.write_list(workdir / "inputs.txt", targets)
        return [
            "dnsx", "-silent", "-a", "-resp", "-duc", "-l", str(workdir / "inputs.txt"),
            "-o", str(workdir / OUT),
        ]

    def parse(self, workdir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        assets = []
        pattern = re.compile(r"^(?P<host>\S+)\s+\[(?P<ips>[^\]]+)\]$")
        for line in self.read_lines(workdir / OUT):
            match = pattern.match(line)
            if not match:
                continue
            host = match.group("host").lower().strip(".")
            ips = [ip.strip() for ip in match.group("ips").split(",") if ip.strip()]
            assets.append(
                {"kind": "domain", "value": host, "meta": {"ips": ips, "resolved": True}}
            )
        return assets, []


class Httpx(ToolAdapter):
    spec = ToolSpec(
        name="httpx",
        binary="httpx",
        passive=False,
        description="HTTP probing - live hosts, status, title, tech",
        install_hint="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        homepage="https://github.com/projectdiscovery/httpx",
        timeout=1200,
    )

    def build(self, targets: list[str], workdir: Path) -> list[str]:
        self.write_list(workdir / "inputs.txt", targets)
        return [
            "httpx", "-silent", "-json", "-td", "-title", "-status-code", "-server",
            "-duc", "-l", str(workdir / "inputs.txt"), "-o", str(workdir / OUT),
        ]

    def parse(self, workdir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        assets = []
        for item in self.read_jsonl(workdir / OUT):
            url = item.get("url") or ""
            host = (item.get("host") or "").split(":")[0]
            if not url or not host:
                continue
            assets.append(
                {
                    "kind": "url",
                    "value": url,
                    "meta": {
                        "host": host,
                        "status_code": item.get("status_code"),
                        "title": item.get("title"),
                        "webserver": item.get("webserver"),
                        "tech": item.get("tech") or [],
                        "content_length": item.get("content_length"),
                        "source": "httpx",
                    },
                }
            )
        return assets, []


class Katana(ToolAdapter):
    spec = ToolSpec(
        name="katana",
        binary="katana",
        passive=False,
        description="Bounded crawling for URLs and parameters",
        install_hint="go install github.com/projectdiscovery/katana/cmd/katana@latest",
        homepage="https://github.com/projectdiscovery/katana",
        timeout=1200,
    )
    MAX_URLS = 3000

    def build(self, targets: list[str], workdir: Path) -> list[str]:
        self.write_list(workdir / "inputs.txt", targets)
        return [
            "katana", "-silent", "-list", str(workdir / "inputs.txt"), "-d", "2", "-jc",
            # fqdn, not rdn: a crawl must not wander to sibling hosts that the
            # scope engine never approved.
            "-fs", "fqdn", "-duc",
            "-ef", "woff,woff2,css,png,svg,jpg,jpeg,gif,ico,ttf,eot,mp4,webp",
            "-o", str(workdir / OUT),
        ]

    def parse(self, workdir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        assets = []
        seen: set[str] = set()
        for line in self.read_lines(workdir / OUT):
            if len(assets) >= self.MAX_URLS:
                break
            url = line.split()[0]
            if not url.startswith(("http://", "https://")) or url in seen:
                continue
            seen.add(url)
            assets.append({"kind": "url", "value": url, "meta": {"source": "katana"}})
        return assets, []


class Nuclei(ToolAdapter):
    spec = ToolSpec(
        name="nuclei",
        binary="nuclei",
        passive=False,
        description="Template-based vulnerability scanning",
        install_hint="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        homepage="https://github.com/projectdiscovery/nuclei",
        timeout=3600,
    )
    MAX_FINDINGS = 500

    def build(self, targets: list[str], workdir: Path) -> list[str]:
        self.write_list(workdir / "inputs.txt", targets)
        return [
            "nuclei", "-silent", "-jsonl", "-l", str(workdir / "inputs.txt"),
            "-timeout", "10", "-retries", "1",
            # No OOB callbacks and no template/version downloads: the only
            # traffic is the scan itself.
            "-ni", "-duc",
            "-o", str(workdir / OUT),
        ]

    def parse(self, workdir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        findings = []
        for item in self.read_jsonl(workdir / OUT):
            if len(findings) >= self.MAX_FINDINGS:
                break
            info = item.get("info") or {}
            template_id = item.get("template-id") or item.get("templateID") or "unknown"
            matched = item.get("matched-at") or item.get("matched") or item.get("host") or ""
            findings.append(
                {
                    "template_id": template_id,
                    "title": info.get("name") or template_id,
                    "severity": (info.get("severity") or "info").lower(),
                    "matched_at": matched,
                    "host": item.get("host"),
                    "matcher": item.get("matcher-name"),
                    "tags": info.get("tags") or [],
                    "description": info.get("description"),
                    "reference": info.get("reference") or [],
                    "extracted": item.get("extracted-results") or [],
                    "raw": item,
                }
            )
        return [], findings


ADAPTERS: list[ToolAdapter] = [Subfinder(), Dnsx(), Httpx(), Katana(), Nuclei()]

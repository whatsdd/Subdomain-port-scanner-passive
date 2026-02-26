"""
SubRecon v2.0 — Passive Subdomain & Port Scanner Core
Async Python scanner using multiple public data sources.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import aiohttp
import dns.asyncresolver
import dns.exception

logger = logging.getLogger(__name__)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanResult:
    def __init__(self, domain: str):
        self.domain = domain
        self.scan_id = ""
        self.subdomains: List[str] = []
        self.source_counts: Dict[str, int] = {}
        self.resolved: List[Dict] = []   # [{subdomain, ip}]
        self.port_data: List[Dict] = []  # [{subdomain, ip, ports, vulns, tags, cpes, hostnames}]
        self.errors: List[str] = []
        self.started_at: str = _utcnow()
        self.finished_at: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "domain": self.domain,
            "scan_id": self.scan_id,
            "subdomains": self.subdomains,
            "source_counts": self.source_counts,
            "resolved": self.resolved,
            "port_data": self.port_data,
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class PassiveScanner:
    HEADERS = {
        "User-Agent": "SubRecon/2.0 (passive-recon; educational)",
        "Accept": "application/json",
    }

    def __init__(self, domain: str):
        self.domain = domain.lower().strip().rstrip(".")
        self._session: Optional[aiohttp.ClientSession] = None
        self._stopped = False

    def stop(self):
        self._stopped = True

    # ── HTTP helper ─────────────────────────────────────────────────────────

    async def _get(self, url: str, timeout_secs: int = 30) -> Optional[Any]:
        if self._stopped:
            return None
        try:
            timeout = aiohttp.ClientTimeout(total=timeout_secs)
            async with self._session.get(
                url, headers=self.HEADERS, timeout=timeout, ssl=False
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        return {"_raw": text}
                if resp.status == 429:
                    return {"_rate_limited": True}
                return None
        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            logger.debug("HTTP error %s: %s", url, e)
            return None

    # ── Subdomain validation ─────────────────────────────────────────────────

    def _valid(self, name: str) -> bool:
        name = name.lower().strip().lstrip("*.")
        if not name:
            return False
        if not (name.endswith(f".{self.domain}") or name == self.domain):
            return False
        if name == self.domain:
            return False
        return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", name))

    def _clean(self, name: str) -> str:
        return name.lower().strip().lstrip("*.")

    # ── Discovery sources ────────────────────────────────────────────────────

    async def discover_crtsh(self) -> List[str]:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        data = await self._get(url, timeout_secs=45)
        if not isinstance(data, list):
            return []
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                cleaned = self._clean(name)
                if self._valid(cleaned):
                    subs.add(cleaned)
        return list(subs)

    async def discover_anubis(self) -> List[str]:
        url = f"https://anubisdb.com/anubis/subdomains/{self.domain}"
        data = await self._get(url, timeout_secs=20)
        if not isinstance(data, list):
            return []
        return [
            self._clean(s)
            for s in data
            if isinstance(s, str) and self._valid(self._clean(s))
        ]

    async def discover_hackertarget(self) -> List[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        data = await self._get(url, timeout_secs=20)
        if not data or "_raw" not in data:
            return []
        raw: str = data["_raw"]
        if "API count exceeded" in raw or raw.strip().startswith("error"):
            return []
        subs = []
        for line in raw.strip().splitlines():
            if "," in line:
                hostname = line.split(",")[0].strip().lower()
                if self._valid(hostname):
                    subs.append(hostname)
        return subs

    async def discover_alienvault(self) -> List[str]:
        url = (
            f"https://otx.alienvault.com/api/v1/indicators/domain"
            f"/{self.domain}/passive_dns"
        )
        data = await self._get(url, timeout_secs=20)
        if not isinstance(data, dict):
            return []
        subs = []
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "").lower().strip()
            if self._valid(hostname):
                subs.append(hostname)
        return subs

    # ── DNS resolution ───────────────────────────────────────────────────────

    async def resolve_ip(self, subdomain: str) -> Optional[str]:
        if self._stopped:
            return None
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = await resolver.resolve(subdomain, "A")
            if answers:
                return str(answers[0])
        except Exception:
            pass
        return None

    # ── Shodan InternetDB ────────────────────────────────────────────────────

    async def query_internetdb(self, ip: str) -> Dict:
        empty: Dict = {
            "ports": [],
            "hostnames": [],
            "tags": [],
            "vulns": [],
            "cpes": [],
        }
        data = await self._get(f"https://internetdb.shodan.io/{ip}", timeout_secs=15)
        if not isinstance(data, dict) or "_raw" in data or "detail" in data:
            return empty
        return {
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),
            "cpes": data.get("cpes", []),
        }

    # ── Main scan orchestrator ───────────────────────────────────────────────

    async def scan(self, progress: Callable) -> ScanResult:
        result = ScanResult(self.domain)

        async with aiohttp.ClientSession() as session:
            self._session = session

            # ── Phase 1: Subdomain discovery ─────────────────────────────────
            await progress({
                "phase": "discovery_start",
                "message": f"Starting passive discovery for {self.domain}…",
                "pct": 2,
            })

            sources = [
                ("crt.sh",         self.discover_crtsh,        "src_crtsh"),
                ("AnubisDB",        self.discover_anubis,       "src_anubis"),
                ("HackerTarget",    self.discover_hackertarget, "src_hackertarget"),
                ("AlienVault OTX",  self.discover_alienvault,   "src_alienvault"),
            ]

            all_subs: set = set()
            pct_base = 5
            pct_step = 10

            for name, func, src_key in sources:
                if self._stopped:
                    break
                await progress({
                    "phase": "source_query",
                    "source": src_key,
                    "message": f"Querying {name}…",
                    "pct": pct_base,
                    "status": "running",
                })
                try:
                    subs = await func()
                    all_subs.update(subs)
                    result.source_counts[name] = len(subs)
                    await progress({
                        "phase": "source_done",
                        "source": src_key,
                        "message": f"{name}: {len(subs)} subdomains",
                        "pct": pct_base + pct_step // 2,
                        "status": "done",
                        "count": len(subs),
                    })
                except Exception as exc:
                    result.errors.append(f"{name}: {exc}")
                    await progress({
                        "phase": "source_error",
                        "source": src_key,
                        "message": f"{name}: error ({exc})",
                        "pct": pct_base,
                        "status": "error",
                    })
                pct_base += pct_step

            result.subdomains = sorted(all_subs)

            await progress({
                "phase": "discovery_done",
                "message": f"Found {len(result.subdomains)} unique subdomains",
                "pct": 48,
                "subdomains": result.subdomains,
                "source_counts": result.source_counts,
            })

            if not result.subdomains:
                result.finished_at = _utcnow()
                await progress({
                    "phase": "complete",
                    "message": "No subdomains found.",
                    "pct": 100,
                })
                return result

            # ── Phase 2: DNS resolution ───────────────────────────────────────
            await progress({
                "phase": "resolution_start",
                "message": "Resolving IP addresses…",
                "pct": 50,
            })

            sem_dns = asyncio.Semaphore(20)
            resolved_list: List[Dict] = []
            total = len(result.subdomains)

            async def _resolve(sub: str, idx: int):
                if self._stopped:
                    return
                async with sem_dns:
                    ip = await self.resolve_ip(sub)
                pct = 50 + int((idx + 1) / max(total, 1) * 18)
                if ip:
                    resolved_list.append({"subdomain": sub, "ip": ip})
                    await progress({
                        "phase": "resolved",
                        "subdomain": sub,
                        "ip": ip,
                        "pct": pct,
                        "message": f"✓ {sub} → {ip}",
                    })
                else:
                    await progress({
                        "phase": "unresolved",
                        "subdomain": sub,
                        "pct": pct,
                        "message": f"✗ {sub} (no A record)",
                    })

            await asyncio.gather(
                *[_resolve(s, i) for i, s in enumerate(result.subdomains)]
            )
            result.resolved = resolved_list

            await progress({
                "phase": "resolution_done",
                "message": (
                    f"Resolved {len(result.resolved)}/{len(result.subdomains)} subdomains"
                ),
                "pct": 68,
            })

            # ── Phase 3: Port enumeration (Shodan InternetDB) ─────────────────
            ip_to_subs: Dict[str, List[str]] = {}
            for r in result.resolved:
                ip_to_subs.setdefault(r["ip"], []).append(r["subdomain"])

            unique_ips = list(ip_to_subs.keys())

            await progress({
                "phase": "portscan_start",
                "message": (
                    f"Querying {len(unique_ips)} unique IPs via Shodan InternetDB…"
                ),
                "pct": 70,
                "source": "src_internetdb",
                "status": "running",
            })

            ip_data: Dict[str, Dict] = {}
            sem_shodan = asyncio.Semaphore(5)

            async def _query_ip(ip: str, idx: int):
                if self._stopped:
                    return
                async with sem_shodan:
                    await asyncio.sleep(0.3)  # respect rate limits
                    data = await self.query_internetdb(ip)
                ip_data[ip] = data
                pct = 70 + int((idx + 1) / max(len(unique_ips), 1) * 27)
                await progress({
                    "phase": "port_result",
                    "ip": ip,
                    "ports": data["ports"],
                    "vulns": data["vulns"],
                    "pct": pct,
                    "message": (
                        f"IP {ip}: {len(data['ports'])} ports, "
                        f"{len(data['vulns'])} CVEs"
                    ),
                })

            await asyncio.gather(
                *[_query_ip(ip, i) for i, ip in enumerate(unique_ips)]
            )

            # Build final port_data (one row per subdomain)
            empty_port: Dict = {
                "ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": []
            }
            for ip, subs in ip_to_subs.items():
                data = ip_data.get(ip, empty_port)
                for sub in subs:
                    result.port_data.append({
                        "subdomain": sub,
                        "ip": ip,
                        "ports": data["ports"],
                        "hostnames": data["hostnames"],
                        "tags": data["tags"],
                        "vulns": data["vulns"],
                        "cpes": data["cpes"],
                    })

            await progress({
                "phase": "portscan_done",
                "message": "Port enumeration complete",
                "pct": 97,
                "source": "src_internetdb",
                "status": "done",
            })

            result.finished_at = _utcnow()

            await progress({
                "phase": "complete",
                "message": "Scan complete!",
                "pct": 100,
            })

        return result

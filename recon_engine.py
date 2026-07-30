import yaml
import shlex
import asyncio
import os
import json
import ipaddress
import socket
import shutil
import time
from pathlib import Path
from typing import List
from datetime import datetime
from urllib.parse import urlparse

try:
    import dns.exception
    import dns.resolver
except Exception:  # pragma: no cover
    dns = None

class ReconEngine:
    def __init__(self, storage, config_path: str = "config.yaml"):
        self.storage = storage
        self.config_path = config_path
        self._dns_resolver = None
        self._ip_cache_ttl_seconds = 3600
        if dns is not None:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 3.0
            self._dns_resolver = resolver
        self._load_config()

    def _load_config(self):
        try:
            with open(self.config_path, "r") as f:
                self.cfg = yaml.safe_load(f) or {}
        except FileNotFoundError:
            self.cfg = {}
        engine_cfg = self.cfg.get("Engine", {}) if isinstance(self.cfg, dict) else {}
        ttl_raw = engine_cfg.get("ip-cache-ttl-seconds", 3600)
        try:
            ttl = int(ttl_raw)
        except (TypeError, ValueError):
            ttl = 3600
        self._ip_cache_ttl_seconds = max(60, ttl)

    def _commands_for_target(self, scan_type: str) -> List[str]:
        engine_cfg = self.cfg.get("Engine", {})
        profiles = engine_cfg.get("scan-profiles", {})
        if isinstance(profiles, dict):
            chosen = profiles.get(scan_type) or profiles.get("extended")
            if isinstance(chosen, dict):
                cmds = chosen.get("cmd-recon", [])
                if isinstance(cmds, list) and cmds:
                    return cmds

        legacy = engine_cfg.get("cmd-recon", [])
        if scan_type == "domain" and isinstance(legacy, list) and legacy:
            domain_only = [cmd for cmd in legacy if "subfinder" in cmd]
            return domain_only or legacy[:1]
        return legacy

    def _path_for_org(self, orgname: str) -> Path:
        base = Path("data/recon")
        base.mkdir(parents=True, exist_ok=True)
        if hasattr(self.storage, "normalize_orgname"):
            org_key = self.storage.normalize_orgname(orgname)
        else:
            org_key = orgname
        p = base / org_key
        p.mkdir(parents=True, exist_ok=True)
        return p

    def path_for_org(self, orgname: str) -> Path:
        return self._path_for_org(orgname)

    def _engine_paths(self) -> List[str]:
        engine_cfg = self.cfg.get("Engine", {})
        path_cfg = engine_cfg.get("path", "")
        paths: List[str] = []
        if isinstance(path_cfg, str):
            if path_cfg.strip():
                paths.extend([p.strip() for p in path_cfg.split(os.pathsep) if p.strip()])
        elif isinstance(path_cfg, list):
            for item in path_cfg:
                if isinstance(item, str) and item.strip():
                    paths.append(item.strip())

        # keep order, drop duplicates
        seen = set()
        ordered = []
        for p in paths:
            if p not in seen:
                ordered.append(p)
                seen.add(p)
        return ordered

    def _resolve_executable(self, executable: str) -> str:
        # direct path provided in command
        if "/" in executable:
            return executable

        custom_paths = self._engine_paths()
        if custom_paths:
            found = shutil.which(executable, path=os.pathsep.join(custom_paths))
            if found:
                return found

        found = shutil.which(executable)
        if found:
            return found
        raise FileNotFoundError(executable)

    async def _run_cmd(self, cmd: str, cwd: Path):
        # split the command safely
        parts = shlex.split(cmd)
        if not parts:
            return 1
        parts[0] = self._resolve_executable(parts[0])

        env = os.environ.copy()
        custom_paths = self._engine_paths()
        if custom_paths:
            env["PATH"] = os.pathsep.join(custom_paths + [env.get("PATH", "")])

        proc = await asyncio.create_subprocess_exec(*parts, cwd=str(cwd), env=env)
        await proc.wait()
        return proc.returncode

    def missing_tools(self, scan_type: str) -> List[str]:
        missing = []
        for raw in self._commands_for_target(scan_type):
            parts = shlex.split(raw)
            if not parts:
                continue
            executable = parts[0]
            try:
                self._resolve_executable(executable)
            except FileNotFoundError:
                if executable not in missing:
                    missing.append(executable)
        return missing

    def _legacy_path_for_org(self, orgname: str) -> Path:
        base = Path("data/recon")
        base.mkdir(parents=True, exist_ok=True)
        return base / orgname

    def read_output_list(self, orgname: str, fname: str):
        p = self._path_for_org(orgname) / fname
        if not p.exists():
            p = self._legacy_path_for_org(orgname) / fname
        if not p.exists():
            return []
        return [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

    def _resolve_ips(self, hostname: str) -> List[str]:
        normalized_host = str(hostname or "").strip().rstrip(".")
        if not normalized_host:
            return []
        try:
            parsed_ip = ipaddress.ip_address(normalized_host)
            return [str(parsed_ip)]
        except ValueError:
            pass
        ips = []
        if self._dns_resolver is not None:
            for record_type in ("A", "AAAA"):
                try:
                    answers = self._dns_resolver.resolve(normalized_host, record_type, search=False)
                    for answer in answers:
                        ip = str(answer).strip()
                        if ip and ip not in ips:
                            ips.append(ip)
                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers,
                    dns.exception.Timeout,
                ):
                    continue
                except Exception:
                    continue

        try:
            infos = socket.getaddrinfo(normalized_host, None)
            for info in infos:
                sockaddr = info[4]
                if not sockaddr:
                    continue
                ip = sockaddr[0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass

        def _ip_sort_key(value: str):
            try:
                parsed = ipaddress.ip_address(value)
                return (parsed.version, int(parsed))
            except ValueError:
                return (3, value)

        return sorted(ips, key=_ip_sort_key)

    def _extract_hostname(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        token = raw.split()[0]
        parsed = urlparse(token if "://" in token else f"//{token}")
        host = parsed.hostname
        if host:
            return str(host).strip().rstrip(".").lower()

        candidate = token.split("/", 1)[0]
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[-1]
        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1:candidate.index("]")]
        elif candidate.count(":") == 1:
            candidate = candidate.split(":", 1)[0]
        return candidate.strip().rstrip(".").lower()

    def _ip_cache_file(self, orgname: str, cache_name: str) -> Path:
        return self._path_for_org(orgname) / f"{cache_name}_ip_cache.json"

    def _load_ip_cache(self, orgname: str, cache_name: str):
        cache_file = self._ip_cache_file(orgname, cache_name)
        if not cache_file.exists():
            return {}
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError, ValueError):
            return {}

    def _save_ip_cache(self, orgname: str, cache_name: str, cache_data: dict):
        cache_file = self._ip_cache_file(orgname, cache_name)
        cache_file.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")

    def read_subdomains_with_ip(self, orgname: str):
        ip_cache = self._load_ip_cache(orgname, "subdomain")
        now = int(time.time())
        cache_changed = False
        results = []
        for subdomain in self.read_output_list(orgname, "subfinder.txt"):
            rec = ip_cache.get(subdomain)
            cached_ips = []
            valid_cache = False
            if isinstance(rec, dict) and isinstance(rec.get("ips"), list):
                updated_at = int(rec.get("updated_at", 0) or 0)
                if now - updated_at <= self._ip_cache_ttl_seconds:
                    cached_ips = rec["ips"]
                    valid_cache = True
            if not valid_cache:
                cached_ips = self._resolve_ips(subdomain)
                ip_cache[subdomain] = {"ips": cached_ips, "updated_at": now}
                cache_changed = True
            results.append(
                {
                    "subdomain": subdomain,
                    "ips": cached_ips,
                }
            )
        if cache_changed:
            self._save_ip_cache(orgname, "subdomain", ip_cache)
        return results

    def read_live_hosts_with_ip(self, orgname: str):
        ip_cache = self._load_ip_cache(orgname, "live")
        now = int(time.time())
        cache_changed = False
        results = []
        for live_host in self.read_output_list(orgname, "live.txt"):
            hostname = self._extract_hostname(live_host)
            cached_ips = []
            valid_cache = False
            rec = ip_cache.get(hostname)
            if isinstance(rec, dict) and isinstance(rec.get("ips"), list):
                updated_at = int(rec.get("updated_at", 0) or 0)
                if now - updated_at <= self._ip_cache_ttl_seconds:
                    cached_ips = rec["ips"]
                    valid_cache = True
            if hostname and not valid_cache:
                cached_ips = self._resolve_ips(hostname)
                ip_cache[hostname] = {"ips": cached_ips, "updated_at": now}
                cache_changed = True
            results.append(
                {
                    "host": live_host,
                    "hostname": hostname,
                    "ips": cached_ips,
                }
            )
        if cache_changed:
            self._save_ip_cache(orgname, "live", ip_cache)
        return results

    def delete_org_files(self, orgname: str):
        for p in [self._path_for_org(orgname), self._legacy_path_for_org(orgname)]:
            if p.exists():
                shutil.rmtree(p, ignore_errors=True)
 
    async def run_recon(self, orgname: str, domains: List[str], job_id: str, scan_type: str = "extended"):
        target = self._path_for_org(orgname)
        run_target = target / f".run_{job_id}"
        if run_target.exists():
            shutil.rmtree(run_target, ignore_errors=True)
        run_target.mkdir(parents=True, exist_ok=True)
        alltxt = run_target / "all.txt"
        alltxt.write_text("\n".join(domains), encoding="utf-8")

        # update status
        self.storage.append_org(
            orgname,
            {
                "job_id": job_id,
                "status": "running",
                "scan_type": scan_type,
                "started_at": datetime.utcnow().isoformat() + "Z",
            },
        )

        commands = self._commands_for_target(scan_type)
        success = True
        for raw in commands:
            # ensure we insert an absolute path so tools invoked with cwd still find files
            abs_target = str(run_target.resolve())
            cmd = raw.replace("{target}", shlex.quote(abs_target))
            try:
                rc = await self._run_cmd(cmd, run_target)
                if rc != 0:
                    success = False
            except FileNotFoundError:
                success = False
                # missing tool
                self.storage.append_org(
                    orgname,
                    {
                        "job_id": job_id,
                        "status": "failed",
                        "scan_type": scan_type,
                        "reason": f"tool missing for command: {cmd}",
                    },
                )
                break
            except Exception as e:
                success = False
                self.storage.append_org(
                    orgname,
                    {
                        "job_id": job_id,
                        "status": "failed",
                        "scan_type": scan_type,
                        "reason": str(e),
                    },
                )
                break

        if success:
            publish_files = ["all.txt", "subfinder.txt", "naabu.txt", "live.txt"]
            publish_files.extend(["subdomain_ip_cache.json", "live_ip_cache.json"])
            for fname in publish_files:
                src = run_target / fname
                dst = target / fname
                if src.exists():
                    src.replace(dst)
            if scan_type == "domain":
                for stale_name in ["naabu.txt", "live.txt", "live_ip_cache.json"]:
                    stale_file = target / stale_name
                    if stale_file.exists():
                        stale_file.unlink(missing_ok=True)

        final_status = "completed" if success else "failed"
        self.storage.append_org(
            orgname,
            {
                "job_id": job_id,
                "status": final_status,
                "scan_type": scan_type,
                "finished_at": datetime.utcnow().isoformat() + "Z",
            },
        )
        # update global record status
        self.storage.update_global_job(job_id, {"status": final_status, "scan_type": scan_type})
        shutil.rmtree(run_target, ignore_errors=True)

import json
import re
import threading
from pathlib import Path
from typing import List


class Storage:
    def __init__(self):
        self.base = Path("data")
        self.base.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.all_file = self.base / "allrecon.json"
        self.org_dir = self.base / "recon"
        self.org_dir.mkdir(parents=True, exist_ok=True)
        if not self.all_file.exists():
            self.all_file.write_text("[]", encoding="utf-8")
        elif not self.all_file.read_text(encoding="utf-8").strip():
            self.all_file.write_text("[]", encoding="utf-8")

    @staticmethod
    def normalize_orgname(orgname: str) -> str:
        cleaned = " ".join((orgname or "").strip().split())
        key = re.sub(r"[^A-Za-z0-9._-]+", "_", cleaned)
        key = key.strip("._-")
        return key or "org"

    def _org_file_candidates(self, orgname: str) -> List[Path]:
        key_path = self.org_dir / f"{self.normalize_orgname(orgname)}.json"
        legacy_path = self.org_dir / f"{orgname}.json"
        if legacy_path == key_path:
            return [key_path]
        return [key_path, legacy_path]

    def _read_all(self):
        with self.lock:
            try:
                return json.loads(self.all_file.read_text(encoding="utf-8"))
            except Exception:
                return []

    @staticmethod
    def _atomic_write_json(path: Path, data):
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(path)

    def _write_all(self, data):
        with self.lock:
            self._atomic_write_json(self.all_file, data)

    def append_global(self, record: dict):
        with self.lock:
            arr = self._read_all()
            org_key = self.normalize_orgname(record.get("orgname", ""))
            job_id = f"job_{len(arr)+1}_{org_key}"
            record_with_id = dict(record, job_id=job_id, org_key=record.get("org_key", org_key))
            arr.append(record_with_id)
            self._write_all(arr)
            return job_id

    def update_global_job(self, job_id: str, patch: dict):
        with self.lock:
            arr = self._read_all()
            for r in arr:
                if r.get("job_id") == job_id:
                    r.update(patch)
            self._write_all(arr)

    def append_org(self, orgname: str, rec: dict):
        org_key = self.normalize_orgname(orgname)
        p = self.org_dir / f"{org_key}.json"
        with self.lock:
            arr = []
            if p.exists():
                try:
                    arr = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    arr = []
            arr.append(dict(rec, org_key=rec.get("org_key", org_key)))
            self._atomic_write_json(p, arr)

    def load_all(self):
        return self._read_all()

    def load_org(self, orgname: str):
        candidates = self._org_file_candidates(orgname)
        for p in candidates:
            if not p.exists():
                continue
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return []
        return []

    def delete_org(self, orgname: str):
        for p in self._org_file_candidates(orgname):
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

    def delete_org_from_global(self, orgname: str):
        with self.lock:
            org_key = self.normalize_orgname(orgname)
            arr = self._read_all()
            filtered = [
                r
                for r in arr
                if r.get("orgname") != orgname and r.get("org_key") != org_key
            ]
            self._write_all(filtered)

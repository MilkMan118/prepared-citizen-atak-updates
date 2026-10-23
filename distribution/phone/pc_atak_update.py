#!/data/data/com.termux/files/usr/bin/python
"""Verified, manually applied ATAK updates. Standard library + OpenSSL only."""
from __future__ import annotations

import argparse
import ast
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile


PROFILES = {
    "s26": {"model": "SM-S948U", "home": "pcres_viirs_updater_v1", "state": "VIIRS_LIVE_UPDATER"},
    "s24": {"model": "SM-S928U", "home": "pcres_viirs_updater_s24_20261022", "state": "VIIRS_UPDATER_S24_20261022"},
}
NASA = {"PCRES_" + name + ".xml" for name in (
    "GOES_West_GeoColor", "HLS_Landsat_30m", "HLS_Sentinel_30m",
    "MODIS_Terra_Fire_False_Color", "MODIS_Terra_True_Color", "VIIRS_Fire_Live", "VIIRS_True_Live")}
BASEMAPS = {"PCMAP_" + name + ".xml" for name in (
    "Bing_Hybrid", "Bing_Maps", "Bing_Satellite", "Google_Hybrid", "Google_Roadmap", "Google_Satellite", "Google_Terrain")}
USGS = {"pc_usgs_topo.xml", "pc_usgs_shaded_relief.xml"}
REFERENCES = {
    "mvum_roads.kml": "ATAK_mvum_roads_current.kml",
    "mvum_trails.kml": "ATAK_mvum_trails_current.kml",
    "springs_seeps.kml": "ATAK_nhd_springs_seeps_current.kml",
    "private_land_generalized.kml": "ATAK_private_generalized.kml",
    "private_land_industrial.kml": "ATAK_private_industrial.kml",
    "public_land_management.kml": "ATAK_public_land_management.kml",
    "blm_public_trails.kml": "blm_orwa_public_trails.kml",
    "transmission_lines.kml": "hifld_transmission_lines.kml",
    "odot_bridges.kml": "odot_bridges.kml",
    "odot_low_clearance_bridges.kml": "odot_low_clearance_bridges.kml",
    "odot_posted_bridges.kml": "odot_posted_bridges.kml",
    "odot_weight_restricted_bridges.kml": "odot_weight_restricted_bridges.kml",
}
RUNTIME = {"runtime/pc_atak_update.py", "runtime/pcres_viirs_updater.py"}
CORE_LIMIT = 2 * 1024 * 1024
REFERENCE_LIMIT = 160 * 1024 * 1024
BOOTSTRAP_UPDATER_HASH = {
    "s26": "1af3c174a997fd238bc4f6580bbe601cf8d9e1b8ccad0081cf5a23c2d07fe65c",
    "s24": "606f91f3243a00af4046ca9869ad28414273c122d72765057514014d42af95c6",
}
BOOTSTRAP_WRAPPER_HASH = "2a83230376e36785af83281636413e57c9a599503d42fb323396e4c24033cb63"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def document(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def atomic(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.lstat().st_mode) if path.exists() else 0o600
    fd, name = tempfile.mkstemp(prefix=".pc-update-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, mode & 0o777)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def allowed(profile: str, pack: str) -> set[str]:
    if profile not in PROFILES or pack not in {"core", "references"}:
        raise ValueError("Unsupported profile or pack")
    if pack == "references":
        return {"reference/" + name for name in REFERENCES}
    return {"maps/" + n for n in NASA | BASEMAPS | (USGS if profile == "s24" else set())} | RUNTIME


def safe_path(path: Path, root: Path) -> None:
    path.absolute().relative_to(root.absolute())
    p = path
    while True:
        attributes = getattr(p.lstat(), "st_file_attributes", 0) if p.exists() else 0
        if p.is_symlink() or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("Linked update path")
        if p == root:
            break
        p = p.parent


def safe_bytes(path: Path, root: Path) -> bytes | None:
    safe_path(path, root)
    if not path.exists():
        return None
    if not path.is_file():
        raise ValueError("Nonregular update target")
    return path.read_bytes()


def verify_manifest(raw: bytes, signature: bytes, key: Path, openssl="openssl") -> dict:
    if len(raw) > 512 * 1024 or not 128 <= len(signature) <= 1024 or key.is_symlink():
        raise ValueError("Invalid signed manifest size/key")
    command = [openssl] if isinstance(openssl, str) else list(openssl)
    with tempfile.TemporaryDirectory(prefix="pc-manifest-") as folder:
        p = Path(folder)
        (p / "manifest").write_bytes(raw)
        (p / "signature").write_bytes(signature)
        try:
            result = subprocess.run(command + ["dgst", "-sha256", "-verify", str(key),
                "-signature", str(p / "signature"), str(p / "manifest")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Signature verifier unavailable") from exc
    if result.returncode:
        raise ValueError("Manifest signature rejected")
    d = document(raw)
    if (not isinstance(d, dict) or d.get("schema") != 1 or type(d.get("sequence")) is not int
            or d["sequence"] < 1 or not re.fullmatch(r"\d+\.\d+\.\d+", str(d.get("version", "")))
            or not isinstance(d.get("assets"), dict)):
        raise ValueError("Invalid release manifest")
    return d


def validate_archive(raw: bytes, asset: dict, profile: str, pack: str) -> dict[str, bytes]:
    limit = CORE_LIMIT if pack == "core" else REFERENCE_LIMIT
    if len(raw) > limit or len(raw) != asset.get("size") or digest(raw) != asset.get("sha256"):
        raise ValueError("Archive size/hash mismatch")
    rows = asset.get("members", [])
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        raise ValueError("Invalid member count")
    expected = {e["path"]: e for e in rows}
    if len(expected) != len(rows) or not set(expected) <= allowed(profile, pack):
        raise ValueError("Member allowlist mismatch")
    result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        infos = z.infolist()
        if len(infos) != len(rows) or {i.filename for i in infos} != set(expected):
            raise ValueError("Archive membership mismatch")
        total = 0
        for info in infos:
            name = info.filename
            mode = info.external_attr >> 16
            ceiling = 96 * 1024 * 1024 if pack == "references" else (64 * 1024 if name.startswith("maps/") else 1024 * 1024)
            if (name in result or "\\" in name or ".." in PurePosixPath(name).parts or info.is_dir()
                    or (mode and not stat.S_ISREG(mode)) or info.flag_bits & 1
                    or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or not 0 < info.file_size <= ceiling or info.file_size != expected[name].get("size")):
                raise ValueError("Unsafe ZIP member")
            total += info.file_size
            if total > limit or info.file_size / max(1, info.compress_size) > 100:
                raise ValueError("ZIP expansion exceeds policy")
            content = z.read(info)
            if digest(content) != expected[name].get("sha256"):
                raise ValueError("Member hash mismatch")
            if name.endswith((".xml", ".kml")) and re.search(br"<!\s*(DOCTYPE|ENTITY)", content, re.I):
                raise ValueError("XML declarations forbidden")
            if name.startswith("maps/"):
                root = ET.fromstring(content)
                if PurePosixPath(name).name in NASA:
                    fields = root.findall("additionalparameters")
                    if (root.tag != "customWmsMapSource" or len(fields) != 1
                            or root.find("additionalParameters") is not None
                            or not (fields[0].text or "").startswith("&TRANSPARENT=TRUE&TIME=")
                            or root.findtext("coordinatesystem") != "EPSG:3857"
                            or int(root.findtext("tileUpdate", "0")) <= 0):
                        raise ValueError("NASA definition violates the installed ATAK parser contract")
                    if is_dated(name):
                        dated(content)
            if name.startswith("runtime/"):
                tree = ast.parse(content)
                if name.endswith("pcres_viirs_updater.py"):
                    state = next(n.value for n in tree.body if isinstance(n, ast.Assign)
                                 and any(isinstance(t, ast.Name) and t.id == "STATE_ROOT" for t in n.targets))
                    expected_state = "/storage/emulated/0/PREPARED_CITIZEN/" + PROFILES[profile]["state"]
                    if not isinstance(state, ast.Call) or len(state.args) != 1 or ast.literal_eval(state.args[0]) != expected_state:
                        raise ValueError("Wrong runtime state profile")
            result[name] = content
    return result


def dated(raw: bytes):
    if re.search(br"<!\s*(DOCTYPE|ENTITY)", raw, re.I):
        raise ValueError("Unsafe dated XML")
    root = ET.fromstring(raw)
    fields = root.findall("additionalparameters")
    if len(fields) != 1:
        raise ValueError("Missing unique date parameters")
    match = re.fullmatch(r"&TRANSPARENT=TRUE&TIME=(\d{4}-\d{2}-\d{2})", fields[0].text or "")
    if not match:
        raise ValueError("Invalid dated source parameters")
    dt.date.fromisoformat(match[1])
    return root, fields[0], match[1]


def is_dated(name: str) -> bool:
    return name.startswith(("maps/PCRES_VIIRS_", "maps/PCRES_MODIS_"))


def fingerprint(name: str, raw: bytes | None) -> str | None:
    if raw is None:
        return None
    if is_dated(name):
        root, field, _ = dated(raw)
        field.text = "&TRANSPARENT=TRUE&TIME=@DATE@"
        raw = canonical([(n.tag, sorted(n.attrib.items()), (n.text or "").strip()) for n in root.iter()])
    return digest(raw)


def preserve_date(name: str, incoming: bytes, current: bytes | None) -> bytes:
    if not is_dated(name) or current is None:
        return incoming
    _, _, old = dated(current)
    _, _, new = dated(incoming)
    return incoming.replace(("TIME=" + new).encode(), ("TIME=" + max(old, new)).encode())


@contextlib.contextmanager
def lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(canonical({"pid": os.getpid(), "created_utc": dt.datetime.now(dt.timezone.utc).isoformat()}))
        yield
    finally:
        path.unlink()


def owner_alive(pid: int) -> bool | None:
    if os.name == "nt":
        # Windows os.kill(pid, 0) can terminate a process; query its status instead.
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False if ctypes.get_last_error() == 87 else None
        try:
            code = ctypes.c_ulong()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None
            return code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return None


class Updater:
    def __init__(self, home: Path, shared: Path, config: dict):
        if config.get("profile") not in PROFILES or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", config.get("repo", "")):
            raise ValueError("Invalid local profile/repository")
        self.home, self.shared, self.config = Path(home), Path(shared), config
        self.profile = config["profile"]
        self.root = self.home / ".pc_atak_updates"
        self.state_path = self.root / "installed.json"
        self.journal = self.root / "transaction.json"
        self.imagery_lock = self.shared / "PREPARED_CITIZEN" / PROFILES[self.profile]["state"] / "update.lock"

    def write(self, path: Path, raw: bytes):
        root = self.home if path.is_relative_to(self.home) else self.shared
        safe_path(path, root)
        atomic(path, raw)

    @contextlib.contextmanager
    def exclusive(self, imagery=True):
        safe_path(self.root / "client.lock", self.home)
        with lock(self.root / "client.lock"):
            if imagery:
                safe_path(self.imagery_lock, self.shared)
                with lock(self.imagery_lock):
                    yield
            else:
                yield

    def target(self, name: str, pack: str) -> Path:
        if name not in allowed(self.profile, pack):
            raise ValueError("Target outside managed scope")
        filename = PurePosixPath(name).name
        if name.startswith("maps/"):
            return self.shared / "atak/imagery" / filename
        if name.startswith("reference/"):
            return self.shared / "atak/overlays" / REFERENCES[filename]
        if filename == "pc_atak_update.py":
            return self.root / filename
        return self.home / PROFILES[self.profile]["home"] / filename

    def read_target(self, name: str, pack: str):
        return safe_bytes(self.target(name, pack), self.home if name.startswith("runtime/") else self.shared)

    def state(self):
        raw = safe_bytes(self.state_path, self.home)
        if raw is None:
            raise ValueError("Verified bootstrap baseline required")
        return document(raw)

    def recover_locks(self):
        abandoned = []
        for path, root in ((self.root / "client.lock", self.home), (self.imagery_lock, self.shared)):
            raw = safe_bytes(path, root)
            if raw is None:
                continue
            try:
                if len(raw) > 4096:
                    raise ValueError("Oversized lock")
                info = document(raw)
                pid = info["pid"]
                created = dt.datetime.fromisoformat(info["created_utc"])
                if type(pid) is not int or not 0 < pid < 2 ** 31 or created.tzinfo is None:
                    raise ValueError("Invalid lock owner")
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError("Ambiguous lock retained; inspect manually") from exc
            if owner_alive(pid) is not False:
                raise ValueError("Active or unproven lock owner retained")
            abandoned.append((path, root, raw, pid))
        for path, root, raw, pid in abandoned:
            if safe_bytes(path, root) != raw or owner_alive(pid) is not False:
                raise ValueError("Lock changed during recovery")
            path.unlink()
        return {"phase": "dead_owner_locks_recovered", "removed": len(abandoned)}

    def initialize_baseline(self):
        if self.state_path.exists():
            raise ValueError("Baseline already exists")
        managed = {name: fingerprint(name, self.read_target(name, pack))
                   for pack in ("core", "references") for name in allowed(self.profile, pack)}
        self.write(self.state_path, canonical({"managed": managed, "sequences": {}, "highest": {}, "releases": {}}))

    def plan(self, members: dict[str, bytes], pack: str, sequence: int) -> list[dict]:
        state = self.state()
        high, installed = state["highest"].get(pack, 0), state["sequences"].get(pack, 0)
        if sequence < high or (sequence == high and sequence != installed):
            raise ValueError("Older or rolled-back release rejected")
        if not members or not set(members) <= allowed(self.profile, pack):
            raise ValueError("Unexpected managed member")
        release_hash = digest(canonical({n: digest(b) for n, b in members.items()}))
        if sequence == installed and state["releases"].get(pack) != release_hash:
            raise ValueError("Same sequence contains changed release content")
        rows = []
        for name, raw in sorted(members.items()):
            current = self.read_target(name, pack)
            if name not in state["managed"] or fingerprint(name, current) != state["managed"][name]:
                raise ValueError("Unexplained managed-file drift; existing data preserved")
            after = preserve_date(name, raw, current)
            rows.append({"path": name, "before": digest(current) if current is not None else None,
                         "after": digest(after), "action": "retain" if current == after else "replace"})
        return rows

    def unfinished(self):
        raw = safe_bytes(self.journal, self.home)
        if raw and document(raw)["phase"] not in {"complete", "rolled_back"}:
            raise ValueError("Incomplete transaction; explicit rollback required")

    def apply(self, members: dict[str, bytes], pack: str, sequence: int):
        with self.exclusive():
            self.unfinished()
            rows = self.plan(members, pack, sequence)
            state = self.state()
            if sequence == state["sequences"].get(pack) and all(r["action"] == "retain" for r in rows):
                return {"phase": "unchanged", "sequence": sequence}
            ident = uuid.uuid4().hex
            backup = self.root / "backups" / ident
            safe_path(backup / "0", self.home)
            backup.mkdir(parents=True, exist_ok=False)
            j = {"phase": "started", "id": ident, "pack": pack, "rows": rows, "previous_state": state}
            for index, row in enumerate(rows):
                before = self.read_target(row["path"], pack)
                if (digest(before) if before is not None else None) != row["before"]:
                    raise ValueError("Target changed before backup")
                if before is not None:
                    self.write(backup / str(index), before)
                    if digest(safe_bytes(backup / str(index), self.home)) != row["before"]:
                        raise ValueError("Backup verification failed")
            self.write(self.journal, canonical(j))
            try:
                after_state = json.loads(json.dumps(state))
                for row in rows:
                    name = row["path"]
                    before = self.read_target(name, pack)
                    if (digest(before) if before is not None else None) != row["before"]:
                        raise ValueError("Target changed after planning")
                    after = preserve_date(name, members[name], before)
                    if digest(after) != row["after"]:
                        raise ValueError("Planned content changed")
                    if row["action"] != "retain":
                        self.write(self.target(name, pack), after)
                    if digest(self.read_target(name, pack)) != row["after"]:
                        raise ValueError("Written content verification failed")
                    after_state["managed"][name] = fingerprint(name, after)
                after_state["sequences"][pack] = sequence
                after_state["highest"][pack] = max(sequence, state["highest"].get(pack, 0))
                after_state["releases"][pack] = digest(canonical({n: digest(b) for n, b in members.items()}))
                j["after_state"] = after_state
                self.write(self.journal, canonical(j))
                self.write(self.state_path, canonical(after_state))
                j["phase"] = "complete"
                self.write(self.journal, canonical(j))
                return {"phase": "complete", "sequence": sequence, "changed": sum(r["action"] != "retain" for r in rows)}
            except BaseException:
                self._restore(j)
                raise

    def _restore(self, j):
        if not re.fullmatch(r"[a-f0-9]{32}", j["id"]) or j["pack"] not in {"core", "references"}:
            raise ValueError("Unsafe recovery journal")
        backup = self.root / "backups" / j["id"]
        current_state = self.state()
        if current_state not in [j["previous_state"], j.get("after_state"), j.get("rollback_state")]:
            raise ValueError("State drift blocks rollback")
        originals = []
        for index, row in enumerate(j["rows"]):
            raw = self.read_target(row["path"], j["pack"])
            if (digest(raw) if raw is not None else None) not in {row["before"], row["after"]}:
                raise ValueError("Unexpected edit preserved; rollback blocked")
            original = safe_bytes(backup / str(index), self.home) if row["before"] is not None else None
            if (digest(original) if original is not None else None) != row["before"]:
                raise ValueError("Recovery backup mismatch")
            originals.append(original)
        previous = json.loads(json.dumps(j["previous_state"]))
        for pack, high in current_state["highest"].items():
            previous["highest"][pack] = max(high, previous["highest"].get(pack, 0))
        j["rollback_state"] = previous
        j["phase"] = "rolling_back"
        self.write(self.journal, canonical(j))
        for row, original in reversed(list(zip(j["rows"], originals))):
            target = self.target(row["path"], j["pack"])
            current = self.read_target(row["path"], j["pack"])
            if (digest(current) if current is not None else None) not in {row["before"], row["after"]}:
                raise ValueError("Target drift during rollback")
            if original is None:
                if current is not None:
                    target.unlink()
            else:
                self.write(target, original)
        self.write(self.state_path, canonical(previous))
        j["phase"] = "rolled_back"
        self.write(self.journal, canonical(j))

    def rollback(self):
        with self.exclusive():
            j = document(safe_bytes(self.journal, self.home))
            if j["phase"] == "rolled_back":
                return {"phase": "already_rolled_back"}
            self._restore(j)
            return {"phase": "rolled_back"}


def github_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in {None, 443}
            or parsed.fragment or not (host in {"github.com", "api.github.com"} or host.endswith(".githubusercontent.com"))):
        raise ValueError("Non-GitHub HTTPS URL rejected")
    return url


class GitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, github_url(newurl))


def download(url: str, limit: int, etag: str | None = None):
    headers = {"User-Agent": "PreparedCitizen-ATAK-Updater/1.0", "Accept": "application/vnd.github+json"}
    if etag:
        headers["If-None-Match"] = etag
    request = urllib.request.Request(github_url(url), headers=headers)
    try:
        with urllib.request.build_opener(GitHubRedirect()).open(request, timeout=25) as response:
            raw = response.read(limit + 1)
            if len(raw) > limit:
                raise ValueError("Download exceeds limit")
            return raw, response.headers.get("ETag")
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None, etag
        raise


def check(client: Updater, key: Path, *, scheduled=False, pack="core", fetch=download):
    with client.exclusive(imagery=False):
        cache_path = client.root / "check.json"
        raw = safe_bytes(cache_path, client.home)
        cache = document(raw) if raw else {}
        now = time.time()
        attempts = cache.setdefault("attempted", {})
        if scheduled and 0 <= now - attempts.get(pack, 0) < 86400:
            return {"phase": "daily_check_already_attempted"}
        if scheduled and pack != "core":
            raise ValueError("References are manual only")
        attempts[pack] = now
        client.write(cache_path, canonical(cache))
        endpoint = "https://api.github.com/repos/" + client.config["repo"] + "/releases/latest"
        raw, etag = fetch(endpoint, 512 * 1024, cache.get("etag"))
        if raw is None and cache.get("validated_sequence") is not None:
            local_state = client.state()
            installed = local_state["sequences"].get(pack, 0)
            if installed == cache["validated_sequence"]:
                return {"phase": "unchanged", "sequence": installed}
            if cache["validated_sequence"] <= local_state["highest"].get(pack, 0):
                raise ValueError("Previously rolled-back release is not staged again")
            pending = client.root / ("pending-" + pack)
            pending_manifest = safe_bytes(pending / "manifest.json", client.home)
            if pending_manifest is not None:
                known = verify_manifest(pending_manifest, safe_bytes(pending / "manifest.sig", client.home), key)
                if known["sequence"] == cache["validated_sequence"]:
                    name = "pc-atak-" + (client.profile if pack == "core" else "references") + ".zip"
                    validate_archive(safe_bytes(pending / "payload.zip", client.home), known["assets"][name], client.profile, pack)
                    return {"phase": "staged_not_applied", "sequence": known["sequence"], "pack": pack}
        if raw is not None:
            release = document(raw)
            if release.get("draft") or release.get("prerelease"):
                raise ValueError("Nonstable release rejected")
            assets = release["assets"]
            urls = {}
            for item in assets:
                if item["name"] in urls:
                    raise ValueError("Duplicate release asset")
                urls[item["name"]] = github_url(item["browser_download_url"])
            cache["urls"], cache["etag"] = urls, etag
        urls = cache.get("urls", {})
        manifest_raw, _ = fetch(urls["pc-atak-manifest.json"], 512 * 1024)
        signature, _ = fetch(urls["pc-atak-manifest.sig"], 1024)
        manifest = verify_manifest(manifest_raw, signature, key)
        cache["validated_sequence"] = manifest["sequence"]
        state = client.state()
        sequence = manifest["sequence"]
        high = state["highest"].get(pack, 0)
        if sequence < high or (sequence == high and sequence != state["sequences"].get(pack, 0)):
            raise ValueError("Server attempted a downgrade")
        if sequence == state["sequences"].get(pack):
            asset_name = "pc-atak-" + (client.profile if pack == "core" else "references") + ".zip"
            expected = digest(canonical({r["path"]: r["sha256"] for r in manifest["assets"][asset_name]["members"]}))
            if expected != state["releases"].get(pack):
                raise ValueError("Same sequence changed release content")
            client.write(cache_path, canonical(cache))
            return {"phase": "unchanged", "sequence": sequence}
        name = "pc-atak-" + (client.profile if pack == "core" else "references") + ".zip"
        asset = manifest["assets"][name]
        payload, _ = fetch(urls[name], CORE_LIMIT if pack == "core" else REFERENCE_LIMIT)
        validate_archive(payload, asset, client.profile, pack)
        stage = client.root / ("pending-" + pack)
        if stage.is_symlink():
            raise ValueError("Linked pending stage")
        client.write(stage / "manifest.json", manifest_raw)
        client.write(stage / "manifest.sig", signature)
        client.write(stage / "payload.zip", payload)
        client.write(cache_path, canonical(cache))
        return {"phase": "staged_not_applied", "sequence": sequence, "pack": pack}


def bootstrap_plan(client: Updater, members: dict[str, bytes], key: bytes, manifest: dict):
    if client.root.exists() or client.root.is_symlink():
        previous = safe_bytes(client.root / "bootstrap.json", client.home)
        if (previous is None or document(previous)["phase"] != "rolled_back"
                or any(p.name not in {"bootstrap.json", "bootstrap-backups"} for p in client.root.iterdir())):
            raise ValueError("Bootstrap already present; preserve and review it")
    if set(members) != allowed(client.profile, "core"):
        raise ValueError("Bootstrap requires the complete signed core")
    source = Path(__file__).read_bytes()
    if members["runtime/pc_atak_update.py"] != source:
        raise ValueError("Bootstrap client is not the signed release client")
    profile = PROFILES[client.profile]
    updater = client.home / profile["home"] / "pcres_viirs_updater.py"
    wrapper = updater.parent / "run_viirs_refresh.sh"
    old_updater = safe_bytes(updater, client.home)
    old_wrapper = safe_bytes(wrapper, client.home)
    if old_updater is None or digest(old_updater) != BOOTSTRAP_UPDATER_HASH[client.profile]:
        raise ValueError("Existing updater does not match approved R3")
    if old_wrapper is None or digest(old_wrapper) != BOOTSTRAP_WRAPPER_HASH:
        raise ValueError("Existing wrapper changed")
    needle = b'exec python "$SCRIPT_DIR/pcres_viirs_updater.py" refresh --yes'
    if old_wrapper.count(needle) != 1:
        raise ValueError("Unexpected wrapper structure")
    new_wrapper = old_wrapper.replace(needle,
        b'python "$HOME/.pc_atak_updates/pc_atak_update.py" check --scheduled || true\n' + needle)
    managed = {}
    for name, raw in members.items():
        current = client.read_target(name, "core")
        if name.startswith("maps/") and fingerprint(name, current) != fingerprint(name, raw):
            raise ValueError("Map baseline differs from the reviewed current package")
        managed[name] = fingerprint(name, raw if name.startswith("runtime/") else current)
    references = manifest.get("assets", {}).get("pc-atak-references.zip")
    if references:
        rows = {r["path"]: r for r in references["members"]}
        if set(rows) != allowed(client.profile, "references") or len(rows) != len(references["members"]):
            raise ValueError("Reference baseline manifest mismatch")
        for name, row in rows.items():
            current = client.read_target(name, "references")
            if current is not None and digest(current) != row["sha256"]:
                raise ValueError("Existing reference differs; no baseline adopted")
            managed[name] = fingerprint(name, current)
    config = dict(client.config, key_sha256=digest(key))
    installed = {"managed": managed, "sequences": {}, "highest": {}, "releases": {}}
    pairs = [(client.root / "pc_atak_update.py", source),
             (client.root / "settings.json", canonical(config)),
             (client.root / "trusted-public.pem", key),
             (client.root / "installed.json", canonical(installed)),
             (updater, members["runtime/pcres_viirs_updater.py"]), (wrapper, new_wrapper)]
    result = []
    for target, after in pairs:
        before = safe_bytes(target, client.home)
        result.append({"target": target, "before": before, "after": after})
    return result


def bootstrap_apply(client: Updater, plan: list[dict], stage: Path):
    stage = stage.resolve()
    ident = uuid.uuid4().hex
    backup = client.root / "bootstrap-backups" / ident
    for row in plan:
        if safe_bytes(row["target"], client.home) != row["before"]:
            raise ValueError("Bootstrap preimage drift")
    with client.exclusive():
        safe_path(backup / "0", client.home)
        backup.mkdir(parents=True, exist_ok=False)
        for index, row in enumerate(plan):
            if row["before"] is not None:
                client.write(backup / str(index), row["before"])
                if (backup / str(index)).read_bytes() != row["before"]:
                    raise ValueError("Bootstrap backup verification failed")
        journal = {"phase": "started", "id": ident, "profile": client.profile,
            "rows": [{"target": str(r["target"].relative_to(client.home)).replace("\\", "/"),
                      "before": digest(r["before"]) if r["before"] is not None else None,
                      "after": digest(r["after"])} for r in plan]}
        client.write(client.root / "bootstrap.json", canonical(journal))
        try:
            for row in plan:
                if safe_bytes(row["target"], client.home) != row["before"]:
                    raise ValueError("Bootstrap target changed")
                client.write(row["target"], row["after"])
                if safe_bytes(row["target"], client.home) != row["after"]:
                    raise ValueError("Bootstrap write verification failed")
        except BaseException:
            _bootstrap_restore(client)
            raise
        journal["phase"] = "complete"
        client.write(client.root / "bootstrap.json", canonical(journal))
    atomic(stage / "bootstrap-receipt.json", canonical({"phase": "complete", "targets": len(plan),
        "jobs_changed": False, "shared_files_changed": False,
        "files": [{"role": r["target"].name, "before_sha256": digest(r["before"]) if r["before"] is not None else None,
                   "after_sha256": digest(r["after"])} for r in plan]}))
    return {"phase": "bootstrap_complete", "targets": len(plan), "job_registrations_changed": False}


def _bootstrap_restore(client):
    j = document(safe_bytes(client.root / "bootstrap.json", client.home))
    if j["profile"] != client.profile or not re.fullmatch(r"[a-f0-9]{32}", j["id"]):
        raise ValueError("Wrong bootstrap recovery profile")
    updater_home = PROFILES[client.profile]["home"]
    expected = {".pc_atak_updates/" + n for n in
                ("pc_atak_update.py", "settings.json", "trusted-public.pem", "installed.json")}
    expected |= {updater_home + "/" + n for n in ("pcres_viirs_updater.py", "run_viirs_refresh.sh")}
    if len(j["rows"]) != 6 or {r["target"] for r in j["rows"]} != expected:
        raise ValueError("Bootstrap recovery allowlist mismatch")
    originals = []
    for index, row in enumerate(j["rows"]):
        target = client.home / row["target"]
        current = safe_bytes(target, client.home)
        if (digest(current) if current is not None else None) not in {row["before"], row["after"]}:
            raise ValueError("Unexpected bootstrap edit retained")
        path = client.root / "bootstrap-backups" / j["id"] / str(index)
        before = safe_bytes(path, client.home) if row["before"] is not None else None
        if (digest(before) if before is not None else None) != row["before"]:
            raise ValueError("Bootstrap recovery preimage mismatch")
        originals.append(before)
    for row, original in reversed(list(zip(j["rows"], originals))):
        target = client.home / row["target"]
        current = safe_bytes(target, client.home)
        if (digest(current) if current is not None else None) not in {row["before"], row["after"]}:
            raise ValueError("Bootstrap target drift during recovery")
        if original is None:
            if current is not None:
                target.unlink()
        else:
            client.write(target, original)
    j["phase"] = "rolled_back"
    client.write(client.root / "bootstrap.json", canonical(j))


def bootstrap_rollback(client):
    with client.exclusive():
        _bootstrap_restore(client)
    return {"phase": "bootstrap_rolled_back"}


def main():
    parser = argparse.ArgumentParser(description="Verified ATAK package updates")
    parser.add_argument("command", choices=("check", "apply", "rollback", "bootstrap", "bootstrap-rollback", "recover-locks"))
    parser.add_argument("--pack", choices=("core", "references"), default="core")
    parser.add_argument("--scheduled", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--profile", choices=("s26", "s24"))
    parser.add_argument("--key", type=Path)
    parser.add_argument("--key-sha256")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--archive", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--yes", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    home = Path.home()
    root = home / ".pc_atak_updates"
    if args.command in {"bootstrap-rollback", "recover-locks"}:
        if not args.yes or not args.profile or not args.repo:
            raise ValueError("Recovery requires profile, repository and --yes")
        client = Updater(home, Path("/storage/emulated/0"), {"repo": args.repo, "profile": args.profile})
        model = subprocess.check_output(["getprop", "ro.product.model"], text=True).strip()
        if model != PROFILES[client.profile]["model"]:
            raise ValueError("Wrong bootstrap rollback phone")
        print(json.dumps(client.recover_locks() if args.command == "recover-locks" else bootstrap_rollback(client)))
        return
    if args.command == "bootstrap":
        if not all((args.repo, args.profile, args.key, args.key_sha256, args.manifest, args.signature, args.archive)):
            raise ValueError("Bootstrap requires all pinned inputs")
        client = Updater(home, Path("/storage/emulated/0"), {"repo": args.repo, "profile": args.profile})
        model = subprocess.check_output(["getprop", "ro.product.model"], text=True).strip()
        if model != PROFILES[client.profile]["model"]:
            raise ValueError("Wrong phone for bootstrap")
        def read_input(path):
            path = path.absolute()
            return safe_bytes(path, home if path.is_relative_to(home) else client.shared)
        key_raw = read_input(args.key)
        if digest(key_raw) != args.key_sha256:
            raise ValueError("Bootstrap key pin mismatch")
        manifest = verify_manifest(read_input(args.manifest), read_input(args.signature), args.key)
        name = "pc-atak-" + client.profile + ".zip"
        members = validate_archive(read_input(args.archive), manifest["assets"][name], client.profile, "core")
        plan = bootstrap_plan(client, members, key_raw, manifest)
        if args.yes:
            result = bootstrap_apply(client, plan, args.manifest.parent)
        else:
            result = {"phase": "bootstrap_dry_run", "operational_mutations": 0,
                "targets": [{"role": r["target"].name, "size": len(r["after"]),
                             "before_sha256": digest(r["before"]) if r["before"] is not None else None,
                             "after_sha256": digest(r["after"])} for r in plan]}
        print(json.dumps(result))
        return
    config = document(safe_bytes(root / "settings.json", home))
    client = Updater(home, Path("/storage/emulated/0"), config)
    model = subprocess.check_output(["getprop", "ro.product.model"], text=True).strip()
    if model != PROFILES[client.profile]["model"]:
        raise ValueError("Wrong phone for bootstrap profile")
    key = root / "trusted-public.pem"
    if digest(safe_bytes(key, home)) != config["key_sha256"]:
        raise ValueError("Pinned verification key changed")
    if args.command == "check":
        result = check(client, key, scheduled=args.scheduled, pack=args.pack)
    elif args.command == "rollback":
        if not args.yes:
            raise ValueError("Rollback requires --yes")
        result = client.rollback()
    else:
        stage = root / ("pending-" + args.pack)
        manifest = verify_manifest(safe_bytes(stage / "manifest.json", home), safe_bytes(stage / "manifest.sig", home), key)
        name = "pc-atak-" + (client.profile if args.pack == "core" else "references") + ".zip"
        members = validate_archive(safe_bytes(stage / "payload.zip", home), manifest["assets"][name], client.profile, args.pack)
        if args.yes:
            result = client.apply(members, args.pack, manifest["sequence"])
        else:
            with client.exclusive():
                client.unfinished()
                result = {"phase": "dry_run", "operational_mutations": 0,
                          "targets": client.plan(members, args.pack, manifest["sequence"])}
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("ATAK update stopped; existing data preserved. " + type(exc).__name__)
        raise SystemExit(1)

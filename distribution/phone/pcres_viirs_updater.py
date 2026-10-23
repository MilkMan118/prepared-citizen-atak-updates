from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import math
import os
import pathlib
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

try:
    from PIL import Image, ImageStat
except ImportError as exc:
    raise SystemExit(
        "Pillow is required. In Termux, install it with: pkg install python-pillow"
    ) from exc


VERSION = "1.1.0"
ENDPOINT = "https://gibs.earthdata.nasa.gov/wms/epsg3857/best/wms.cgi"
BBOX_WGS84 = (-125.2, 41.5, -116.0, 49.2)
TARGET_ROOT = pathlib.Path("/storage/emulated/0/atak/imagery")
STATE_ROOT = pathlib.Path(
    "/storage/emulated/0/PREPARED_CITIZEN/VIIRS_LIVE_UPDATER"
)
LOCK_MAX_AGE_SECONDS = 2 * 60 * 60
LOOKBACK_DAYS = 10
MAX_RESPONSE_BYTES = 20 * 1024 * 1024

SOURCES = {
    "true": {
        "filename": "PCRES_VIIRS_True_Live.xml",
        "name": "VIIRS True Live",
        "layer": "VIIRS_NOAA21_CorrectedReflectance_TrueColor",
    },
    "fire": {
        "filename": "PCRES_VIIRS_Fire_Live.xml",
        "name": "VIIRS Fire Live",
        "layer": "VIIRS_NOAA21_CorrectedReflectance_BandsM11-I2-I1",
    },
}


MODIS_SOURCES = {
    "true": {
        "filename": "PCRES_MODIS_Terra_True_Color.xml",
        "name": "MODIS Terra True Color (Recent usable)",
        "layer": "MODIS_Terra_CorrectedReflectance_TrueColor",
    },
    "fire": {
        "filename": "PCRES_MODIS_Terra_Fire_False_Color.xml",
        "name": "MODIS Terra Fire False (Recent usable)",
        "layer": "MODIS_Terra_CorrectedReflectance_Bands721",
    },
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mercator(lon: float, lat: float) -> tuple[float, float]:
    radius = 6378137.0
    x = radius * math.radians(lon)
    clamped_lat = max(min(lat, 85.05112878), -85.05112878)
    y = radius * math.log(math.tan(math.pi / 4 + math.radians(clamped_lat) / 2))
    return x, y


def canonical_xml(source: dict[str, str], date: str) -> bytes:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ValueError(f"Invalid ISO date: {date}")
    text = f"""<?xml version="1.0" encoding="UTF-8"?>
<customWmsMapSource>
  <name>{source["name"]}</name>
  <url>{ENDPOINT}</url>
  <layers>{source["layer"]}</layers>
  <styles></styles>
  <version>1.3.0</version>
  <coordinatesystem>EPSG:3857</coordinatesystem>
  <minZoom>2</minZoom>
  <maxZoom>9</maxZoom>
  <tileType>PNG</tileType>
  <backgroundColor>#00000000</backgroundColor>
  <tileUpdate>86400000</tileUpdate>
  <additionalparameters>&amp;TRANSPARENT=TRUE&amp;TIME={date}</additionalparameters>
</customWmsMapSource>
"""
    return text.encode("utf-8")


def inspect_xml(path: pathlib.Path, source: dict[str, str]) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"Required regular XML file is absent: {path}")
    if path.stat().st_size > 64 * 1024:
        raise ValueError(f"XML exceeds 64 KiB: {path}")
    raw = path.read_bytes()
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError(f"DTD/entity declarations are forbidden: {path}")
    root = ET.fromstring(raw)
    if root.tag != "customWmsMapSource":
        raise ValueError(f"Unexpected XML root in {path}: {root.tag}")

    children = list(root)
    tags = [child.tag for child in children]
    expected_tags = {
        "name",
        "url",
        "layers",
        "styles",
        "version",
        "coordinatesystem",
        "minZoom",
        "maxZoom",
        "tileType",
        "backgroundColor",
        "additionalparameters",
        "tileUpdate",
    }
    if set(tags) != expected_tags or len(tags) != len(expected_tags):
        raise ValueError(f"Unexpected or duplicate XML elements in {path.name}")
    values = {child.tag: (child.text or "").strip() for child in children}
    expected = {
        "name": source["name"],
        "url": ENDPOINT,
        "layers": source["layer"],
        "version": "1.3.0",
        "coordinatesystem": "EPSG:3857",
        "minZoom": "2",
        "maxZoom": "9",
        "tileType": "PNG",
        "backgroundColor": "#00000000",
        "tileUpdate": "86400000",
    }
    for key, value in expected.items():
        if values.get(key) != value:
            raise ValueError(
                f"Unexpected {key} in {path.name}: {values.get(key)!r}"
            )

    parameters = values.get("additionalparameters", "")
    match = re.fullmatch(r"&TRANSPARENT=TRUE&TIME=(\d{4}-\d{2}-\d{2})", parameters)
    if not match:
        raise ValueError(f"Unexpected additionalparameters in {path.name}")
    date = match.group(1)
    dt.date.fromisoformat(date)
    return {
        "date": date,
        "sha256": sha256_bytes(raw),
        "length_bytes": str(len(raw)),
    }


def image_metrics(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Response exceeded 20 MiB")
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Response was not PNG")
    with Image.open(io.BytesIO(raw)) as image:
        image.load()
        if image.size != (512, 512):
            raise ValueError(f"Unexpected image dimensions: {image.size}")
        rgba = image.convert("RGBA")
        rgb = rgba.convert("RGB")
        alpha = rgba.getchannel("A")
        alpha_histogram = alpha.histogram()
        rgb_histogram = rgb.histogram()
        luminance_histogram = rgb.convert("L").histogram()
        total = rgba.width * rgba.height
        transparent = alpha_histogram[0]
        black = luminance_histogram[0]
        quantized = rgb.quantize(colors=256)
        unique_bins = len(quantized.getcolors(maxcolors=256) or [])
        stats = ImageStat.Stat(rgb)
        visible_fraction = (total - transparent) / total
        nonblack_fraction = (total - black) / total
        useful = (
            visible_fraction >= 0.01
            and nonblack_fraction >= 0.01
            and unique_bins >= 16
            and max(rgb_histogram) < total
        )
        return {
            "format": image.format,
            "size": list(image.size),
            "visible_fraction": round(visible_fraction, 6),
            "nonblack_fraction": round(nonblack_fraction, 6),
            "unique_color_bins": unique_bins,
            "mean_rgb": [round(value, 3) for value in stats.mean],
            "useful": useful,
        }


def request_layer(layer: str, date: str) -> tuple[bytes, dict[str, object]]:
    west, south = mercator(BBOX_WGS84[0], BBOX_WGS84[1])
    east, north = mercator(BBOX_WGS84[2], BBOX_WGS84[3])
    query = {
        "SERVICE": "WMS",
        "REQUEST": "GetMap",
        "VERSION": "1.3.0",
        "LAYERS": layer,
        "STYLES": "",
        "CRS": "EPSG:3857",
        "BBOX": f"{west:.3f},{south:.3f},{east:.3f},{north:.3f}",
        "WIDTH": "512",
        "HEIGHT": "512",
        "FORMAT": "image/png",
        "TRANSPARENT": "TRUE",
        "TIME": date,
    }
    url = ENDPOINT + "?" + urllib.parse.urlencode(query)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"ATAK-PCRES-VIIRS-Updater/{VERSION}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
            content_type = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError:
        raise
    except OSError as exc:
        raise urllib.error.URLError("Imagery transport unavailable") from exc
    if status != 200 or "image/png" not in content_type.lower():
        raise ValueError(f"Unexpected response: HTTP {status}, {content_type}")
    metrics = image_metrics(raw)
    metrics["http_status"] = status
    metrics["content_type"] = content_type
    metrics["sha256"] = sha256_bytes(raw)
    return raw, metrics


def find_latest(current_date: str | None = None) -> dict[str, object]:
    today = dt.datetime.now(dt.timezone.utc).date()
    attempts: list[dict[str, object]] = []
    for days_back in range(0, LOOKBACK_DAYS + 1):
        date = (today - dt.timedelta(days=days_back)).isoformat()
        if current_date and date < current_date:
            break
        attempt: dict[str, object] = {"date": date, "sources": {}}
        try:
            useful = True
            for key, source in SOURCES.items():
                _, metrics = request_layer(source["layer"], date)
                attempt["sources"][key] = metrics
                useful = useful and bool(metrics["useful"])
            attempt["both_useful"] = useful
            attempts.append(attempt)
            if useful:
                return {
                    "selected_date": date,
                    "selected": attempt,
                    "attempts": attempts,
                }
        except urllib.error.HTTPError as exc:
            if exc.code not in {400, 404}:
                raise
            attempt["both_useful"] = False
            attempt["error"] = f"HTTPError: {exc.code}"
            attempts.append(attempt)
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            raise
        except Exception as exc:
            attempt["both_useful"] = False
            attempt["error"] = f"{type(exc).__name__}: {exc}"
            attempts.append(attempt)
    if current_date:
        return {"selected_date": current_date, "attempts": attempts,
                "retained_valid_current": True}
    raise RuntimeError(
        f"No common usable imagery date found in the last {LOOKBACK_DAYS + 1} days"
    )


def atomic_write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


class UpdateLock:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.acquired = False

    def __enter__(self) -> "UpdateLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError as exc:
            age = dt.datetime.now().timestamp() - self.path.stat().st_mtime
            suffix = " (stale; remove manually after review)" if age > LOCK_MAX_AGE_SECONDS else ""
            raise RuntimeError(f"Updater lock already exists: {self.path}{suffix}") from exc
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    }
                )
                + "\n"
            )
        self.acquired = True
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.acquired and self.path.exists():
            self.path.unlink()


def audit(target_root: pathlib.Path) -> dict[str, object]:
    sources: dict[str, object] = {}
    dates = set()
    for key, source in SOURCES.items():
        path = target_root / source["filename"]
        details = inspect_xml(path, source)
        sources[key] = {"path": str(path), **details}
        dates.add(details["date"])
    if len(dates) != 1:
        raise ValueError(f"VIIRS XML dates do not match: {sorted(dates)}")
    return {"current_date": dates.pop(), "sources": sources}


def recover_incomplete(
    target_root: pathlib.Path,
    state_root: pathlib.Path,
) -> dict[str, object] | None:
    sessions_root = state_root / "sessions"
    if not sessions_root.is_dir():
        return None
    incomplete: list[tuple[pathlib.Path, dict[str, object]]] = []
    for session in sorted(sessions_root.iterdir(), reverse=True):
        manifest_path = session / "manifest.json"
        if not session.is_dir() or session.is_symlink() or not manifest_path.is_file():
            continue
        if manifest_path.stat().st_size > 2 * 1024 * 1024:
            raise RuntimeError(f"Oversized session manifest: {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("status") == "started":
            incomplete.append((session, manifest))
    if not incomplete:
        return None
    if len(incomplete) != 1:
        raise RuntimeError(
            f"Multiple incomplete updater sessions require review: {len(incomplete)}"
        )

    session, manifest = incomplete[0]
    backup = session / "backup"
    restored: dict[str, object] = {}
    for key, source in SOURCES.items():
        backup_path = backup / source["filename"]
        details = inspect_xml(backup_path, source)
        atomic_write(
            target_root / source["filename"],
            backup_path.read_bytes(),
        )
        restored[key] = details
    audit(target_root)
    manifest["status"] = "recovered"
    manifest["recovered_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    manifest["recovered_sources"] = restored
    atomic_write(
        session / "manifest.json",
        (json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
    )
    return {"session": str(session), "restored": restored}


def refresh_modis(
    target_root: pathlib.Path,
    state_root: pathlib.Path,
    *,
    apply: bool,
) -> dict[str, object]:
    global SOURCES
    original_sources = SOURCES
    # shortcut: this CLI is single-threaded; parameterize profiles for threaded use.
    SOURCES = MODIS_SOURCES
    try:
        recovered = recover_incomplete(target_root, state_root)
        result = refresh(target_root, state_root, apply=apply)
        if recovered:
            result["recovered_incomplete_session"] = recovered
        return result
    finally:
        SOURCES = original_sources


def refresh(
    target_root: pathlib.Path,
    state_root: pathlib.Path,
    *,
    apply: bool,
) -> dict[str, object]:
    before = audit(target_root)
    online = find_latest(current_date=str(before["current_date"]))
    selected_date = str(online["selected_date"])
    current_date = str(before["current_date"])
    result: dict[str, object] = {
        "version": VERSION,
        "mode": "apply" if apply else "dry-run",
        "current_date": current_date,
        "selected_date": selected_date,
        "online_validation": online,
        "changed": False,
    }
    if selected_date <= current_date:
        result["reason"] = "No newer jointly usable date is available"
        return result
    if not apply:
        result["reason"] = "A newer validated date is available"
        return result

    session_id = (
        dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + f"-{os.getpid()}"
    )
    session = state_root / "sessions" / session_id
    backup = session / "backup"
    backup.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, object] = {
        "status": "started",
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "before": before,
        "selected_date": selected_date,
        "online_validation": online,
    }
    atomic_write(
        session / "manifest.json",
        (json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
    )

    for key, source in SOURCES.items():
        path = target_root / source["filename"]
        backup_path = backup / source["filename"]
        shutil.copy2(path, backup_path)
        expected_hash = before["sources"][key]["sha256"]
        if sha256_file(backup_path) != expected_hash:
            raise RuntimeError(f"Backup verification failed: {backup_path}")

    changed_paths: list[pathlib.Path] = []
    try:
        for source in SOURCES.values():
            path = target_root / source["filename"]
            atomic_write(path, canonical_xml(source, selected_date))
            changed_paths.append(path)
        after = audit(target_root)
        if after["current_date"] != selected_date:
            raise RuntimeError("Post-update date verification failed")
    except Exception:
        for source in SOURCES.values():
            backup_path = backup / source["filename"]
            target_path = target_root / source["filename"]
            if backup_path.is_file():
                atomic_write(target_path, backup_path.read_bytes())
        manifest["status"] = "rolled_back"
        manifest["rollback_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        atomic_write(
            session / "manifest.json",
            (json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
        )
        raise

    manifest["status"] = "complete"
    manifest["completed_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    manifest["after"] = after
    atomic_write(
        session / "manifest.json",
        (json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
    )
    result["changed"] = True
    result["session"] = str(session)
    result["after"] = after
    return result


def selftest() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        targets = root / "imagery"
        state = root / "state"
        targets.mkdir()
        for source in SOURCES.values():
            path = targets / source["filename"]
            path.write_bytes(canonical_xml(source, "2026-07-29"))
            details = inspect_xml(path, source)
            assert details["date"] == "2026-07-29"

        black = Image.new("RGBA", (512, 512), (0, 0, 0, 255))
        black_bytes = io.BytesIO()
        black.save(black_bytes, format="PNG")
        assert image_metrics(black_bytes.getvalue())["useful"] is False

        varied = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
        for x in range(512):
            color = (x % 256, (x * 3) % 256, (x * 7) % 256, 255)
            for y in range(512):
                varied.putpixel((x, y), color)
        varied_bytes = io.BytesIO()
        varied.save(varied_bytes, format="PNG")
        assert image_metrics(varied_bytes.getvalue())["useful"] is True

        audited = audit(targets)
        assert audited["current_date"] == "2026-07-29"

        lock_path = state / "update.lock"
        with UpdateLock(lock_path):
            assert lock_path.exists()
        assert not lock_path.exists()

        interrupted = state / "sessions" / "interrupted"
        interrupted_backup = interrupted / "backup"
        interrupted_backup.mkdir(parents=True)
        for source in SOURCES.values():
            shutil.copy2(
                targets / source["filename"],
                interrupted_backup / source["filename"],
            )
        atomic_write(
            interrupted / "manifest.json",
            b'{"status":"started"}\n',
        )
        atomic_write(
            targets / SOURCES["true"]["filename"],
            canonical_xml(SOURCES["true"], "2026-07-30"),
        )
        try:
            audit(targets)
        except ValueError as exc:
            assert "dates do not match" in str(exc)
        else:
            raise AssertionError("Interrupted pair mismatch was not detected")
        recovered = recover_incomplete(targets, state)
        assert recovered is not None
        assert audit(targets)["current_date"] == "2026-07-29"
        recovered_manifest = json.loads(
            (interrupted / "manifest.json").read_text(encoding="utf-8")
        )
        assert recovered_manifest["status"] == "recovered"

    print("PCRES VIIRS UPDATER SELFTEST PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("selftest")
    subparsers.add_parser("audit")
    subparsers.add_parser("check-online")
    refresh_parser = subparsers.add_parser("refresh")
    refresh_parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    if args.command == "selftest":
        selftest()
        return 0
    if args.command == "audit":
        print(json.dumps(audit(TARGET_ROOT), indent=2))
        return 0
    if args.command == "check-online":
        print(json.dumps(find_latest(), indent=2))
        return 0
    if args.command == "refresh":
        apply = bool(args.yes)
        with UpdateLock(STATE_ROOT / "update.lock"):
            recovered = recover_incomplete(TARGET_ROOT, STATE_ROOT)
            result = refresh(
                TARGET_ROOT,
                STATE_ROOT,
                apply=apply,
            )
            if recovered:
                result["recovered_incomplete_session"] = recovered
            try:
                result["modis"] = refresh_modis(
                    TARGET_ROOT, STATE_ROOT / "modis", apply=apply
                )
            except Exception as exc:
                result["modis"] = {
                    "changed": False, "error": f"{type(exc).__name__}: {exc}"
                }
        print(json.dumps(result, indent=2))
        if not apply and result["selected_date"] > result["current_date"]:
            print("DRY RUN ONLY: rerun with --yes to apply the validated date.")
        elif result["changed"]:
            print("VIIRS LIVE UPDATE COMPLETE")
            print("ATAK will read the new date on its next start.")
        else:
            print("VIIRS LIVE UPDATE NO CHANGE")
        if "error" in result["modis"]:
            print("MODIS LAST-USABLE CHECK FAILED; prior imagery retained")
            return 1
        print(f"MODIS SELECTED USABLE DATE {result['modis']['selected_date']}")
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())

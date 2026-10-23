"""Build an explicit public distribution; never bundle the working repository."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

from .golden_release import privacy_scan
from .review_bundle import build_review_bundle, members_from_paths


def phone_module(root: Path):
    path = root / "distribution/phone/pc_atak_update.py"
    # The source is local reviewed product code; published input is still allowlisted.
    spec = importlib.util.spec_from_file_location("wireless_phone", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked(root: Path, path: str, expected: str | None = None) -> bytes:
    raw = members_from_paths(root, [path])[path]
    if expected and hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ValueError("Curated source no longer matches its recorded hash")
    return raw


def make_reference_archive(members: dict[str, bytes]) -> bytes:
    # The existing review-archive policy is unchanged; one known KML exceeds 50 MiB.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, raw in sorted(members.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.create_system = 3
            z.writestr(info, raw)
    return buffer.getvalue()


def build_release(root: Path, output: Path, version: str, sequence: int,
                  signing_key: Path | None = None, openssl="openssl", references=False) -> dict:
    root, output = Path(root), Path(output)
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or type(sequence) is not int or sequence < 1:
        raise ValueError("Invalid version/sequence")
    phone = phone_module(root)
    maps = {"maps/" + name: checked(root, "distribution/maps/" + name)
            for name in sorted(phone.NASA | phone.BASEMAPS | phone.USGS)}
    reference_members = {}
    if references:
        original = json.loads(checked(root, "releases/s24-readiness-20261022-r1/MANIFEST.json"))
        for row in original["entries"]:
            if row["stage"].startswith("reference/") and row["stage"].endswith(".kml"):
                reference_members[row["stage"]] = checked(root, row["source"], row["sha256"])
    client_source = checked(root, "distribution/phone/pc_atak_update.py")
    engine = checked(root, "distribution/phone/pcres_viirs_updater.py")
    files, assets = {}, {}
    with tempfile.TemporaryDirectory(prefix="pc-public-release-") as folder:
        for profile in ("s26", "s24"):
            members = {n: b for n, b in maps.items() if n in phone.allowed(profile, "core")}
            rendered = engine
            if profile == "s24":
                if rendered.count(b'"/storage/emulated/0/PREPARED_CITIZEN/VIIRS_LIVE_UPDATER"') != 1:
                    raise ValueError("Unexpected engine profile template")
                rendered = rendered.replace(b'"/storage/emulated/0/PREPARED_CITIZEN/VIIRS_LIVE_UPDATER"',
                                            b'"/storage/emulated/0/PREPARED_CITIZEN/VIIRS_UPDATER_S24_20261022"')
            members.update({"runtime/pcres_viirs_updater.py": rendered, "runtime/pc_atak_update.py": client_source})
            if set(members) != phone.allowed(profile, "core") or privacy_scan(members)["status"] != "pass":
                raise ValueError("Core input allowlist/privacy failure")
            name = f"pc-atak-{profile}.zip"
            path = Path(folder) / name
            build_review_bundle(members, path)
            raw = path.read_bytes()
            asset = {"name": name, "size": len(raw), "sha256": phone.digest(raw),
                     "members": [{"path": n, "size": len(b), "sha256": phone.digest(b)} for n, b in sorted(members.items())]}
            phone.validate_archive(raw, asset, profile, "core")
            files[name], assets[name] = raw, asset
        if references:
            if set(reference_members) != phone.allowed("s24", "references"):
                raise ValueError("Reference input allowlist mismatch")
            name = "pc-atak-references.zip"
            raw = make_reference_archive(reference_members)
            asset = {"name": name, "size": len(raw), "sha256": phone.digest(raw),
                     "members": [{"path": n, "size": len(b), "sha256": phone.digest(b)} for n, b in sorted(reference_members.items())]}
            phone.validate_archive(raw, asset, "s24", "references")
            files[name], assets[name] = raw, asset
        source_paths = ["distribution/phone/pc_atak_update.py", "distribution/phone/pcres_viirs_updater.py",
                        "scripts/build_wireless_release.py"]
        source_paths += ["distribution/" + n for n in sorted(maps)]
        source_paths += ["src/prepared_citizen_atak/" + n + ".py" for n in
                        ("__init__", "catalog_models", "golden_release", "review_bundle", "source_validation", "validation", "wireless_release")]
        source_members = members_from_paths(root, source_paths)
        source_members["README.md"] = checked(root, "distribution/README.md")
        source_members["distribution/README.md"] = source_members["README.md"]
        source_members[".gitignore"] = b"__pycache__/\n*.py[cod]\n*.pem\n*.key\n*.p12\n*.apk\n*.db\n*.sqlite\noutput/\nbuild/\n"
        if privacy_scan(source_members)["status"] != "pass":
            raise ValueError("Public source privacy failure")
        source_path = Path(folder) / "pc-atak-sources.zip"
        build_review_bundle(source_members, source_path)
        files["pc-atak-sources.zip"] = source_path.read_bytes()
        manifest = phone.canonical({"schema": 1, "version": version, "sequence": sequence, "assets": assets})
        files["pc-atak-manifest.json"] = manifest
        files["pc-atak-bootstrap.py"] = client_source
        if signing_key is not None:
            mpath, signature = Path(folder) / "manifest.json", Path(folder) / "manifest.sig"
            mpath.write_bytes(manifest)
            command = [openssl] if isinstance(openssl, str) else list(openssl)
            if isinstance(openssl, str) and shutil.which(openssl) is None:
                # The desktop bundled runtime already supplies this backend; phones use OpenSSL.
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding, rsa
                key = serialization.load_pem_private_key(signing_key.read_bytes(), None)
                if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
                    raise ValueError("Signing requires RSA 3072 bits or stronger")
                files["pc-atak-manifest.sig"] = key.sign(manifest, padding.PKCS1v15(), hashes.SHA256())
            else:
                result = subprocess.run(command + ["dgst", "-sha256", "-sign", str(signing_key),
                    "-out", str(signature), str(mpath)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                if result.returncode:
                    raise ValueError("Release signing failed")
                files["pc-atak-manifest.sig"] = signature.read_bytes()
    if output.is_symlink() or any(p.is_symlink() for p in output.parents):
        raise ValueError("Linked output directory")
    if output.exists():
        if not output.is_dir() or any(p.name not in files or p.is_symlink() or not p.is_file() for p in output.iterdir()):
            raise ValueError("Unexpected existing release output")
        if any((output / n).exists() and (output / n).read_bytes() != b for n, b in files.items()):
            raise ValueError("Existing different release preserved")
    output.mkdir(parents=True, exist_ok=True)
    for name, raw in sorted(files.items()):
        if not (output / name).exists():
            (output / name).write_bytes(raw)
    return {"status": "signed_release_candidate" if signing_key else "unsigned_candidate_not_installable",
            "version": version, "sequence": sequence,
            "assets": {n: {"size": len(b), "sha256": phone.digest(b)} for n, b in sorted(files.items())}}

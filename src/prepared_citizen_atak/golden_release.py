"""Deterministic modular review-release builder for WP-02."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Mapping

from .catalog_models import canonical_json_bytes
from .review_bundle import build_review_bundle, is_link_or_reparse, members_from_paths
from .validation import ValidationError


PRIVATE_PATTERNS = (
    re.compile(rb"(?i)(password|secret|api[_-]?key|bearer|private[_-]?key)\s*[:=]\s*[^\s,}\]]+"),
    re.compile(rb"(?i)C:\\Users\\[^\\\s]+"),
    re.compile(rb"(?i)/data/user/\d+/"),
    re.compile(rb"(?i)/sdcard/(?:DCIM|Pictures|Android/data)/"),
)


LIMITATIONS = [
    "This is a review bundle, not an ATAK import package and not device authorization.",
    "It contains definitions and evidence only; no private offline tiles, map databases, terrain, APKs, or personal state.",
    "OSIP endpoint/tile health passed Local checks, but the user-reported blank ATAK presentation remains unresolved.",
    "Offline topo, imagery, and terrain require grouped Real ATAK UI airplane-mode acceptance; Field validation is separate.",
]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def privacy_scan(members: Mapping[str, bytes]) -> dict[str, object]:
    findings: list[dict[str, str]] = []
    for name, content in sorted(members.items()):
        for pattern in PRIVATE_PATTERNS:
            if pattern.search(content):
                findings.append({"path": name, "rule": pattern.pattern.decode("ascii")})
    return {
        "schema_version": "1.0",
        "status": "pass" if not findings else "fail",
        "files_scanned": len(members),
        "findings": findings,
        "public_service_bounds_and_generic_public_test_areas_allowed": True,
    }


def publish_release_files(output: Path, files: Mapping[str, bytes]) -> None:
    """Publish an exact flat release set without tolerating stale payloads."""

    if not files:
        raise ValidationError("release output set is empty")
    folded: set[str] = set()
    for name in files:
        pure = PurePosixPath(name)
        if len(pure.parts) != 1 or pure.is_absolute() or name in {"", ".", ".."}:
            raise ValidationError("release output name is not a flat safe path")
        normalized = name.casefold()
        if normalized in folded:
            raise ValidationError("release output contains a normalized duplicate")
        folded.add(normalized)

    expected = set(files)
    if output.exists():
        if is_link_or_reparse(output) or not output.is_dir():
            raise ValidationError("release output is not a regular directory")
        for child in output.iterdir():
            if (
                child.name not in expected
                or is_link_or_reparse(child)
                or not child.is_file()
            ):
                raise ValidationError("release output contains an unexpected or non-regular entry")
    else:
        output.mkdir(parents=True, exist_ok=False)

    for name, content in sorted(files.items()):
        target = output / name
        if target.exists() and (is_link_or_reparse(target) or not target.is_file()):
            raise ValidationError("release output target is not a regular file")
        target.write_bytes(content)


def _module_members(root: Path, module: Mapping[str, object], config: Mapping[str, object]) -> dict[str, bytes]:
    paths = [str(item) for item in module["members"]]
    source = members_from_paths(root, paths)
    source_rows = [
        {"path": path, "size_bytes": len(source[path]), "sha256": sha256_bytes(source[path])}
        for path in sorted(source)
    ]
    manifest = {
        "schema_version": "1.0",
        "release_id": config["release_id"],
        "module_id": module["id"],
        "status": "deterministic_review_bundle_not_an_ATAK_import_package",
        "apply_authorized": False,
        "compatibility": config["compatibility"],
        "source_members": source_rows,
        "limitations": LIMITATIONS,
    }
    members = {f"source/{path}": content for path, content in source.items()}
    members["MANIFEST/release.json"] = canonical_json_bytes(manifest)
    checksums = "".join(
        f"{sha256_bytes(content)}  {name}\n" for name, content in sorted(members.items())
    ).encode("utf-8")
    members["MANIFEST/SHA256SUMS.txt"] = checksums
    scan = privacy_scan(members)
    if scan["status"] != "pass":
        raise ValidationError(f"privacy scan failed for module {module['id']}")
    members["MANIFEST/privacy_report.json"] = canonical_json_bytes(scan)
    return members


def build_release_tree(root: Path, output: Path) -> dict[str, bytes]:
    config = json.loads((root / "config/wp02_release.json").read_text(encoding="utf-8"))
    if config.get("apply_authorized") is not False:
        raise ValidationError("review release must not authorize Apply")
    output.mkdir(parents=True, exist_ok=True)
    files: dict[str, bytes] = {}
    module_rows: list[dict[str, object]] = []
    for module in config["modules"]:
        module_id = str(module["id"])
        bundle_name = f"{module_id}.review.zip"
        validation = build_review_bundle(_module_members(root, module, config), output / bundle_name)
        content = (output / bundle_name).read_bytes()
        files[bundle_name] = content
        module_rows.append({
            "id": module_id,
            "bundle": bundle_name,
            "size_bytes": len(content),
            "sha256": validation["sha256"],
            "member_count": len(validation["members"]),
        })
        validation_name = f"{module_id}.validation.json"
        files[validation_name] = canonical_json_bytes(validation)
    index = {
        "schema_version": "1.0",
        "release_id": config["release_id"],
        "release_date": config["release_date"],
        "status": config["status"],
        "apply_authorized": False,
        "modules": module_rows,
        "excluded_payloads": config["excluded_payloads"],
        "validation_classes": {
            "Local": "deterministic build and source checks passed",
            "Emulator": "unavailable_no_authorized_exact_installer",
            "Device File": "separate recovered catalog evidence; current baseline required",
            "Real ATAK UI": "pending",
            "Field": "pending"
        }
    }
    files["release_index.json"] = canonical_json_bytes(index)
    files["KNOWN_LIMITATIONS.md"] = ("# Known limitations\n\n" + "\n".join(f"- {item}" for item in LIMITATIONS) + "\n").encode("utf-8")
    files["IMPORT_ORDER.md"] = (
        "# Review and eventual import order\n\n"
        "1. Do not import these review ZIPs into ATAK.\n"
        "2. Review CORE-NAV first; it remains blocked on exact offline payload and Real ATAK UI proof.\n"
        "3. Review LAND-OUTDOOR and HAZARD-LIVE separately; keep on-demand content off by default.\n"
        "4. A later approved device package must contain only accepted exact artifacts and its own rollback manifest.\n"
    ).encode("utf-8")
    files["COMPATIBILITY.md"] = (
        "# Compatibility\n\n"
        "Target evidence: ATAK-CIV 5.6.0.12, plug-in API 5.6.0.CIV, Android 16/API 36. "
        "No APK is bundled. Compatibility is Local/Device File metadata only until Real ATAK UI acceptance.\n"
    ).encode("utf-8")
    scan = privacy_scan(files)
    if scan["status"] != "pass":
        raise ValidationError("release-tree privacy scan failed")
    files["privacy_report.json"] = canonical_json_bytes(scan)
    files["SHA256SUMS.txt"] = "".join(
        f"{sha256_bytes(content)}  {name}\n" for name, content in sorted(files.items())
    ).encode("utf-8")
    for name, content in files.items():
        target = output / Path(*PurePosixPath(name).parts)
        target.write_bytes(content)
    return files

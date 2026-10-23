"""Deterministic, recursively audited review-bundle builder."""

from __future__ import annotations

import hashlib
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

from .source_validation import reject_known_artifact
from .validation import ValidationError


MAX_MEMBER_COUNT = 500
MAX_MEMBER_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 250 * 1024 * 1024
NESTED_ARCHIVE_SUFFIXES = {".zip", ".kmz", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar"}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def is_link_or_reparse(path: Path) -> bool:
    """Return true for symlinks and Windows junction/reparse points."""

    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def audit_members(members: Mapping[str, bytes]) -> list[dict[str, object]]:
    if not members or len(members) > MAX_MEMBER_COUNT:
        raise ValidationError("bundle member count is outside policy")
    total = 0
    folded: set[str] = set()
    rows: list[dict[str, object]] = []
    for name in sorted(members):
        pure = PurePosixPath(name)
        if "\x00" in name or "\\" in name or pure.is_absolute() or ".." in pure.parts:
            raise ValidationError("bundle contains an unsafe member path")
        normalized = name.casefold()
        if normalized in folded:
            raise ValidationError("bundle contains a normalized duplicate")
        folded.add(normalized)
        data = members[name]
        if len(data) > MAX_MEMBER_BYTES:
            raise ValidationError("bundle member exceeds size policy")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValidationError("bundle exceeds total size policy")
        digest = _sha256(data)
        reject_known_artifact(digest)
        if pure.suffix.casefold() in NESTED_ARCHIVE_SUFFIXES:
            raise ValidationError("bundle contains a nested archive")
        if pure.suffix.casefold() in {".sqlite", ".db", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".log"}:
            raise ValidationError("bundle contains a forbidden payload type")
        rows.append({"path": name, "size_bytes": len(data), "sha256": digest})
    return rows


def build_review_bundle(
    members: Mapping[str, bytes], output_path: Path
) -> dict[str, object]:
    member_rows = audit_members(members)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.create_system = 3
            archive.writestr(info, members[name])
    validation = audit_zip(output_path)
    if validation["members"] != member_rows:
        raise ValidationError("written bundle does not match input members")
    return validation


def audit_zip(path: Path) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    total_uncompressed = 0
    folded: set[str] = set()
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_MEMBER_COUNT:
            raise ValidationError("ZIP member count is outside policy")
        for info in infos:
            name = info.filename
            pure = PurePosixPath(name)
            if "\x00" in name or "\\" in name or pure.is_absolute() or ".." in pure.parts:
                raise ValidationError("ZIP contains traversal or unsafe separators")
            normalized = name.casefold()
            if normalized in folded:
                raise ValidationError("ZIP contains a normalized duplicate")
            folded.add(normalized)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ValidationError("ZIP symlink is forbidden")
            if info.is_dir() or (mode and not stat.S_ISREG(mode)):
                raise ValidationError("ZIP non-regular member is forbidden")
            if info.flag_bits & 0x1:
                raise ValidationError("encrypted ZIP member is forbidden")
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise ValidationError("unsupported ZIP compression")
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValidationError("ZIP member exceeds size policy")
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_TOTAL_BYTES:
                raise ValidationError("ZIP exceeds total size policy")
            if info.compress_size and info.file_size / info.compress_size > 100:
                raise ValidationError("ZIP member compression ratio is suspicious")
            data = archive.read(info)
            digest = _sha256(data)
            reject_known_artifact(digest)
            if pure.suffix.casefold() in NESTED_ARCHIVE_SUFFIXES:
                raise ValidationError("ZIP contains a nested archive")
            if pure.suffix.casefold() in {".sqlite", ".db", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".log"}:
                raise ValidationError("ZIP contains a forbidden payload type")
            rows.append({"path": name, "size_bytes": len(data), "sha256": digest})
    rows.sort(key=lambda row: str(row["path"]))
    return {
        "schema_version": "2.0",
        "status": "valid_deterministic_review_bundle_not_an_ATAK_import_package",
        "bundle": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest().upper(),
        "members": rows,
    }


def members_from_paths(
    repository_root: Path, relative_paths: Iterable[str]
) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    root = repository_root.resolve()
    for relative in sorted(set(relative_paths)):
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValidationError("release member path is unsafe")
        unresolved = root
        for part in pure.parts:
            unresolved = unresolved / part
            if is_link_or_reparse(unresolved):
                raise ValidationError("release member traverses a symlink or reparse point")
            if not unresolved.exists():
                raise ValidationError("release member is absent")
        try:
            path = unresolved.resolve(strict=True)
        except OSError as exc:
            raise ValidationError("release member cannot be resolved safely") from exc
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValidationError("release member escapes repository") from exc
        if is_link_or_reparse(path) or not path.is_file():
            raise ValidationError("release member is absent or not a regular file")
        members[relative] = path.read_bytes()
    return members

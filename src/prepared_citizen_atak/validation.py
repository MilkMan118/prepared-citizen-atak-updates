"""Evidence and historical-regression validators independent of phone source."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence


class ValidationError(ValueError):
    """Raised when a fail-closed validation rule rejects input."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def validate_artifact_manifest(manifest_path: Path, root: Path) -> list[dict[str, object]]:
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    results: list[dict[str, object]] = []
    for artifact in manifest.get("artifacts", []):
        status = artifact.get("status")
        external_environment = artifact.get("external_path_environment")
        raw_value = os.environ.get(str(external_environment), "") if external_environment else str(artifact["path"])
        if external_environment and not raw_value:
            raise ValidationError(f"external artifact path environment is unset: {artifact['id']}")
        raw_path = Path(raw_value)
        candidate = raw_path if raw_path.is_absolute() else root / raw_path
        if status == "present_hash_verified":
            if not candidate.is_file():
                raise ValidationError(f"required artifact missing: {artifact['id']}")
            if candidate.stat().st_size != artifact.get("size_bytes"):
                raise ValidationError(f"artifact size mismatch: {artifact['id']}")
            if sha256_file(candidate) != str(artifact.get("sha256", "")).upper():
                raise ValidationError(f"artifact hash mismatch: {artifact['id']}")
            results.append({"id": artifact["id"], "status": "verified"})
        elif status == "missing_not_supplied":
            if candidate.exists():
                raise ValidationError(
                    f"artifact is marked missing but now exists: {artifact['id']}"
                )
            if artifact.get("sha256") is not None:
                raise ValidationError(
                    f"missing artifact has an invented hash: {artifact['id']}"
                )
            results.append({"id": artifact["id"], "status": "missing_explicit"})
        else:
            raise ValidationError(f"unsupported artifact status: {artifact['id']}")
    return results


def require_expected_outputs(expected: Iterable[str], actual: Iterable[str]) -> None:
    missing = sorted(set(expected) - set(actual))
    if missing:
        raise ValidationError("expected output missing: " + ", ".join(missing))


def validate_arcgis_metadata(
    status_code: int,
    metadata: Mapping[str, object],
    *,
    expected_layer: int,
    required_fields: Iterable[str],
) -> None:
    if status_code != 200:
        raise ValidationError(f"ArcGIS endpoint returned HTTP {status_code}")
    if metadata.get("id") != expected_layer:
        raise ValidationError("ArcGIS layer ID changed")
    fields = {
        str(field.get("name"))
        for field in metadata.get("fields", [])
        if isinstance(field, Mapping)
    }
    missing = set(required_fields) - fields
    if missing:
        raise ValidationError("ArcGIS required fields changed")


def validate_polygon_ring(ring: Sequence[Sequence[float]]) -> None:
    if len(ring) < 4 or list(ring[0]) != list(ring[-1]):
        raise ValidationError("polygon ring is empty, short, or not closed")
    unique = {tuple(point) for point in ring[:-1]}
    if len(unique) < 3:
        raise ValidationError("polygon ring has fewer than three unique points")


def require_placemark_geometry(coordinates: Sequence[Sequence[float]]) -> None:
    if not coordinates:
        raise ValidationError("placemark has no geometry")


def validate_archive_members(names: Iterable[str]) -> None:
    folded: set[str] = set()
    for name in names:
        if "\x00" in name or "\\" in name:
            raise ValidationError("archive member uses unsafe separators")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValidationError("archive traversal or absolute member")
        normalized = name.casefold()
        if normalized in folded:
            raise ValidationError("archive contains duplicate normalized member")
        folded.add(normalized)
        if pure.suffix.casefold() in {".zip", ".kmz"}:
            raise ValidationError("nested archive requires explicit approval")


def parse_json_response(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError("response was not valid JSON") from exc


def resolve_profile_selection(selected: Iterable[str], available: Iterable[str]) -> list[str]:
    selected_set = set(selected)
    available_set = set(available)
    unknown = selected_set - available_set
    if unknown:
        raise ValidationError("unknown profile selection")
    return sorted(selected_set)


def validate_tile_template(url: str) -> None:
    if not url.startswith("https://"):
        raise ValidationError("tile endpoint must use HTTPS")
    for token in ("{z}", "{x}", "{y}"):
        if token not in url:
            raise ValidationError("tile endpoint is missing required placeholders")


def validate_atak_map_destination(path: str) -> None:
    root = PurePosixPath("/sdcard/atak/imagery/mobile/mapsources")
    candidate = PurePosixPath(path)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValidationError("map definition is outside the ATAK indexed path") from exc
    if len(relative.parts) != 1 or candidate.suffix.casefold() != ".xml":
        raise ValidationError("map definition is nested or has the wrong file type")


def validate_command_argv(argv: Sequence[str]) -> None:
    if not argv or not argv[0].startswith("/"):
        raise ValidationError("scheduled command must use an absolute executable path")
    if any(re.search(r"[;&|`]", argument) for argument in argv):
        raise ValidationError("scheduled command contains shell control syntax")


def redact_mapping(value: object, secret_fields: set[str]) -> object:
    """Redact exact sensitive keys without corrupting identifiers containing 'api'."""

    if isinstance(value, dict):
        return {
            key: "<redacted>"
            if key.casefold() in secret_fields
            else redact_mapping(nested, secret_fields)
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [redact_mapping(nested, secret_fields) for nested in value]
    return value


def promotion_plan(current: str, candidate: str, *, validation_passed: bool) -> dict[str, object]:
    if not validation_passed:
        return {
            "active": current,
            "candidate": candidate,
            "action": "retain_last_known_good",
            "delete": [],
        }
    return {
        "active": candidate,
        "previous": current,
        "action": "atomic_promote_and_retain_previous",
        "delete": [],
    }

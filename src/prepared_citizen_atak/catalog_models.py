"""Shared, deterministic models for map/catalog reconciliation.

The models deliberately keep evidence classes independent.  A successful local
validator never becomes Real ATAK UI or Field evidence by implication.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class ContentKind(StrEnum):
    BASEMAP = "basemap"
    RASTER_OVERLAY = "raster_overlay"
    FEATURE_OVERLAY = "feature_overlay"
    GRG_IMAGE_OVERLAY = "grg_image_overlay"
    TERRAIN = "terrain"
    CACHE = "cache"
    PACKAGE_COPY = "package_copy"
    INCONCLUSIVE = "inconclusive"


class InterfaceType(StrEnum):
    ARCGIS_REST = "arcgis_rest"
    OGC_WMS = "ogc_wms"
    OGC_WMTS = "ogc_wmts"
    XYZ = "xyz"
    CACHED_TILES = "cached_tiles"
    LOCAL_FILE = "local_file"


class Disposition(StrEnum):
    KEEP = "keep"
    KEEP_HIDDEN = "keep_hidden"
    CANONICALIZE = "canonicalize"
    ARCHIVE_DEFINITION = "archive_definition"
    ARCHIVE_CACHE_AFTER_VALIDATION = "archive_cache_after_validation"
    PROTECTED = "protected"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class EvidenceClass(StrEnum):
    LOCAL = "Local"
    EMULATOR = "Emulator"
    DEVICE_FILE = "Device File"
    REAL_ATAK_UI = "Real ATAK UI"
    FIELD = "Field"


@dataclass(frozen=True, slots=True)
class ServiceDefinition:
    stable_id: str
    service_family: str
    interface_type: InterfaceType
    service_url: str
    layer_identifier: str
    layer_identifier_namespace: str
    layer_title: str
    capabilities_or_metadata_url: str
    metadata_retrieved_at: str
    metadata_raw_sha256: str
    metadata_semantic_fingerprint_sha256: str

    def identity(self) -> tuple[str, str, str, str, str]:
        return (
            self.service_family,
            str(self.interface_type),
            self.service_url,
            self.layer_identifier_namespace,
            self.layer_identifier,
        )


@dataclass(frozen=True, slots=True)
class ValidationObservation:
    evidence_class: EvidenceClass
    status: str
    evidence_reference: str
    observed_at: str
    detail: str


@dataclass(frozen=True, slots=True)
class ClassificationProbe:
    path: str
    suffix: str
    xml_root: str | None = None
    contains_feature_geometry: bool = False
    contains_ground_overlay: bool = False
    transparent_requested: bool = False
    alpha_verified: bool = False
    catalog_reference_verified: bool = False


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    content_kind: ContentKind
    confidence: str
    reasons: tuple[str, ...]


def canonical_json_bytes(value: Any) -> bytes:
    """Stable JSON bytes used by manifests and deterministic release members."""

    def default(item: Any) -> Any:
        if isinstance(item, StrEnum):
            return str(item)
        if hasattr(item, "__dataclass_fields__"):
            return asdict(item)
        raise TypeError(f"unsupported canonical JSON type: {type(item)!r}")

    return (
        json.dumps(
            value,
            default=default,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")

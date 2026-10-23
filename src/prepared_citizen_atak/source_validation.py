"""Pure validators for captured source responses.

Fetching is intentionally outside this module so deterministic tests never
depend on the network.  Identifier equality always includes its namespace.
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence
from xml.etree import ElementTree

from .catalog_models import InterfaceType, ServiceDefinition, canonical_json_bytes
from .validation import ValidationError, validate_polygon_ring


FEMA_REJECTED_WMS28_SHA256 = (
    "1648D7C18F1DBA37D3EE1C2881F82F769A04D78EE939E010349B8EE15EC13EF8"
)


@dataclass(frozen=True, slots=True)
class ServiceValidation:
    valid: bool
    status: str
    semantic_fingerprint_sha256: str | None
    errors: tuple[str, ...]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def require_interface_identity(
    actual_namespace: str,
    actual_identifier: str | int,
    expected: ServiceDefinition,
) -> None:
    if (
        actual_namespace != expected.layer_identifier_namespace
        or str(actual_identifier) != expected.layer_identifier
    ):
        raise ValidationError("source identifier or identifier namespace changed")


def validate_arcgis_rest_capture(
    definition: ServiceDefinition,
    *,
    status_code: int,
    body: bytes,
    required_fields: Iterable[str] = (),
) -> ServiceValidation:
    errors: list[str] = []
    semantic: str | None = None
    if definition.interface_type is not InterfaceType.ARCGIS_REST:
        errors.append("definition is not ArcGIS REST")
    if status_code != 200:
        errors.append(f"HTTP {status_code}")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
        errors.append("response is not JSON")
    if isinstance(payload, Mapping):
        try:
            require_interface_identity(
                "arcgis_rest.layer_id", payload.get("id", ""), definition
            )
        except ValidationError as exc:
            errors.append(str(exc))
        if payload.get("name") != definition.layer_title:
            errors.append("ArcGIS layer title changed")
        fields = {
            str(field.get("name"))
            for field in payload.get("fields", [])
            if isinstance(field, Mapping)
        }
        missing = sorted(set(required_fields) - fields)
        if missing:
            errors.append("missing fields: " + ", ".join(missing))
        projection = {
            "id": str(payload.get("id", "")),
            "name": payload.get("name"),
            "type": payload.get("type"),
            "geometryType": payload.get("geometryType"),
            "fields": sorted(fields),
            "maxRecordCount": payload.get("maxRecordCount"),
        }
        semantic = sha256_bytes(canonical_json_bytes(projection))
    return ServiceValidation(
        not errors,
        "valid" if not errors else "rejected",
        semantic,
        tuple(errors),
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def validate_wms_capture(
    definition: ServiceDefinition,
    *,
    status_code: int,
    body: bytes,
    required_crs: str | None = None,
    required_format: str = "image/png",
) -> ServiceValidation:
    errors: list[str] = []
    semantic: str | None = None
    if definition.interface_type is not InterfaceType.OGC_WMS:
        errors.append("definition is not OGC WMS")
    if status_code != 200:
        errors.append(f"HTTP {status_code}")
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        root = None
        errors.append("response is not WMS XML")
    if root is not None:
        layers: list[tuple[str, str, tuple[str, ...]]] = []
        formats: set[str] = set()
        for request in root.iter():
            if _local_name(request.tag) != "GetMap":
                continue
            for node in request:
                if _local_name(node.tag) == "Format" and (node.text or "").strip():
                    formats.add((node.text or "").strip())

        def visit_layer(node: ElementTree.Element, inherited: set[str]) -> None:
            children = list(node)
            local_crs = {
                (child.text or "").strip()
                for child in children
                if _local_name(child.tag) in {"CRS", "SRS"}
                and (child.text or "").strip()
            }
            effective = inherited | local_crs
            name_node = next(
                (child for child in children if _local_name(child.tag) == "Name"), None
            )
            title_node = next(
                (child for child in children if _local_name(child.tag) == "Title"), None
            )
            if name_node is not None:
                layers.append(
                    (
                        (name_node.text or "").strip(),
                        (title_node.text or "").strip() if title_node is not None else "",
                        tuple(sorted(effective)),
                    )
                )
            for child in children:
                if _local_name(child.tag) == "Layer":
                    visit_layer(child, effective)

        for top in root.iter():
            if _local_name(top.tag) == "Capability":
                for child in top:
                    if _local_name(child.tag) == "Layer":
                        visit_layer(child, set())
                break
        match = next(
            (item for item in layers if item[0] == definition.layer_identifier), None
        )
        if definition.layer_identifier_namespace != "ogc_wms.layer_name":
            errors.append("definition uses the wrong WMS identifier namespace")
        if match is None:
            errors.append("WMS layer Name is absent")
        elif match[1] != definition.layer_title:
            errors.append("WMS layer Title changed")
        elif required_crs and required_crs not in match[2]:
            errors.append("required WMS CRS is absent")
        if required_format not in formats:
            errors.append("required WMS image format is absent")
        projection = {
            "layer": (
                {"name": match[0], "title": match[1], "crs": list(match[2])}
                if match is not None
                else None
            ),
            "formats": sorted(formats),
        }
        semantic = sha256_bytes(canonical_json_bytes(projection))
    return ServiceValidation(
        not errors,
        "valid" if not errors else "rejected",
        semantic,
        tuple(errors),
    )


def validate_cached_tile_metadata(
    *, status_code: int, metadata: Mapping[str, object], expected_url: str
) -> None:
    if status_code != 200:
        raise ValidationError(f"tile metadata returned HTTP {status_code}")
    if not expected_url.startswith("https://"):
        raise ValidationError("tile source is not HTTPS")
    if metadata.get("singleFusedMapCache") is not True or not metadata.get("tileInfo"):
        raise ValidationError("service is not a cached tile service")
    capabilities = {part.strip() for part in str(metadata.get("capabilities", "")).split(",")}
    if not ({"TilesOnly", "Map"} & capabilities):
        raise ValidationError("service does not advertise tile capability")


def _paeth(a: int, b: int, c: int) -> int:
    estimate = a + b - c
    pa, pb, pc = abs(estimate - a), abs(estimate - b), abs(estimate - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def png_has_transparency(data: bytes) -> bool:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValidationError("response is not a PNG")
    offset = 8
    color_type: int | None = None
    bit_depth: int | None = None
    width: int | None = None
    height: int | None = None
    interlace: int | None = None
    transparent_chunk = False
    idat = bytearray()
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        content_start = offset + 8
        content_end = content_start + length
        if content_end + 4 > len(data):
            raise ValidationError("PNG chunk is truncated")
        if chunk_type == b"IHDR":
            if length != 13:
                raise ValidationError("PNG IHDR has an invalid size")
            width, height = struct.unpack(">II", data[content_start : content_start + 8])
            bit_depth = data[content_start + 8]
            color_type = data[content_start + 9]
            interlace = data[content_start + 12]
        elif chunk_type == b"tRNS":
            transparent_chunk = True
        elif chunk_type == b"IDAT":
            idat.extend(data[content_start:content_end])
        elif chunk_type == b"IEND":
            break
        offset = content_end + 4
    if color_type is None:
        raise ValidationError("PNG lacks IHDR")
    if transparent_chunk:
        return True
    if color_type not in {4, 6}:
        return False
    if bit_depth != 8 or interlace != 0 or not width or not height:
        raise ValidationError("PNG alpha pixels cannot be deterministically inspected")
    channels = 2 if color_type == 4 else 4
    stride = width * channels
    try:
        inflated = zlib.decompress(bytes(idat))
    except zlib.error as exc:
        raise ValidationError("PNG image data is invalid") from exc
    if len(inflated) != height * (stride + 1):
        raise ValidationError("PNG scanline size is invalid")
    previous = bytearray(stride)
    offset = 0
    saw_nonopaque = False
    saw_visible = False
    for _ in range(height):
        filter_type = inflated[offset]
        raw = inflated[offset + 1 : offset + 1 + stride]
        offset += stride + 1
        recon = bytearray(stride)
        for index, value in enumerate(raw):
            left = recon[index - channels] if index >= channels else 0
            up = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = up
            elif filter_type == 3:
                predictor = (left + up) // 2
            elif filter_type == 4:
                predictor = _paeth(left, up, upper_left)
            else:
                raise ValidationError("PNG uses an invalid scanline filter")
            recon[index] = (value + predictor) & 0xFF
        alpha_offset = 1 if color_type == 4 else 3
        for index in range(alpha_offset, stride, channels):
            alpha = recon[index]
            saw_nonopaque = saw_nonopaque or alpha < 255
            saw_visible = saw_visible or alpha > 0
        previous = recon
    return saw_nonopaque and saw_visible


def validate_feature_query(
    payload: Mapping[str, object],
    *,
    geometry_required: bool,
    allow_zero_features: bool,
    expected_extent: tuple[float, float, float, float] | None = None,
    max_features: int | None = None,
    pagination_complete: bool = True,
) -> None:
    features = payload.get("features")
    if not isinstance(features, list):
        raise ValidationError("query response lacks a features array")
    if not features and not allow_zero_features:
        raise ValidationError("query unexpectedly returned zero features")
    if max_features is not None and len(features) > max_features:
        raise ValidationError("query exceeded the feature budget")
    for feature in features:
        if not isinstance(feature, Mapping):
            raise ValidationError("query contains a malformed feature")
        geometry = feature.get("geometry")
        if geometry_required and not isinstance(geometry, Mapping):
            raise ValidationError("feature lacks geometry")
        if isinstance(geometry, Mapping) and "rings" in geometry:
            rings = geometry.get("rings")
            if not isinstance(rings, list) or not rings:
                raise ValidationError("polygon feature has no rings")
            for ring in rings:
                validate_polygon_ring(ring)
    if payload.get("exceededTransferLimit") is True and not pagination_complete:
        raise ValidationError("query pagination is truncated")
    if expected_extent is not None and isinstance(payload.get("extent"), Mapping):
        extent = payload["extent"]
        try:
            actual = tuple(float(extent[key]) for key in ("xmin", "ymin", "xmax", "ymax"))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("query extent is malformed") from exc
        ex = expected_extent
        if actual[2] < ex[0] or actual[0] > ex[2] or actual[3] < ex[1] or actual[1] > ex[3]:
            raise ValidationError("query extent is outside the expected operating area")


def reject_known_artifact(sha256: str) -> None:
    if sha256.upper() == FEMA_REJECTED_WMS28_SHA256:
        raise ValidationError("artifact is the rejected FEMA WMS-28 candidate")


def require_interface_dispatch(interface_type: InterfaceType) -> None:
    if interface_type not in {
        InterfaceType.ARCGIS_REST,
        InterfaceType.OGC_WMS,
        InterfaceType.OGC_WMTS,
        InterfaceType.XYZ,
        InterfaceType.CACHED_TILES,
        InterfaceType.LOCAL_FILE,
    }:
        raise ValidationError("unsupported interface type")

import argparse
import re
import struct
import shutil
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple


CAS_MARKERS = (
    b"cas values",
    b"casvalues",
    b"caspart",
    b"body type",
    b"bodytype",
)

BUILD_BUY_MARKERS = (
    b"build/buy values",
    b"buildbuy values",
    b"buildbuy",
    b"build buy",
    b"object definition",
    b"catalog",
)

TUNING_MARKERS = (
    b"snippet_tuning",
    b"interaction_tuning",
    b"object_tuning",
    b"trait_tuning",
    b"situation_tuning",
    b"buff_tuning",
    b"statistic_tuning",
)

BODY_TYPE_ALIASES: Dict[str, str] = {
    "accessory": "Accessories",
    "accessories": "Accessories",
    "fingernail": "Accessories",
    "fingernails": "Accessories",
    "finger nail": "Accessories",
    "finger nails": "Accessories",
    "nail": "Accessories",
    "nails": "Accessories",
    "hat": "Hat",
    "hats": "Hat",
    "earring": "Earrings",
    "earrings": "Earrings",
    "choker": "Necklace",
    "necklace": "Necklace",
    "necklaces": "Necklace",
    "pendant": "Necklace",
    "ring": "Rings",
    "rings": "Rings",
    "bracelet": "Bracelet",
    "bracelets": "Bracelet",
    "glass": "Glasses",
    "glasses": "Glasses",
    "sunglasses": "Glasses",
    "spectacles": "Glasses",
    "glove": "Gloves",
    "gloves": "Gloves",
    "sock": "Socks",
    "socks": "Socks",
    "tight": "Tights",
    "tights": "Tights",
    "shoe": "Shoes",
    "shoes": "Shoes",
    "slipper": "Shoes",
    "slippers": "Shoes",
    "boot": "Shoes",
    "boots": "Shoes",
    "top": "Top",
    "tops": "Top",
    "tshirt": "Top",
    "tshirts": "Top",
    "t shirt": "Top",
    "t shirts": "Top",
    "sweatshirt": "Top",
    "sweatshirts": "Top",
    "sweater": "Top",
    "sweaters": "Top",
    "hoodie": "Top",
    "hoodies": "Top",
    "jacket": "Top",
    "jackets": "Top",
    "bottom": "Bottom",
    "bottoms": "Bottom",
    "body": "FullBody",
    "fullbody": "FullBody",
    "full body": "FullBody",
    "outfit": "FullBody",
    "outfits": "FullBody",
    "suit": "FullBody",
    "suits": "FullBody",
    "dress": "FullBody",
    "dresses": "FullBody",
    "jumpsuit": "FullBody",
    "jumpsuits": "FullBody",
    "romper": "FullBody",
    "rompers": "FullBody",
    "hair": "Hair",
    "hairstyle": "Hair",
    "eyebrow": "Eyebrows",
    "eyebrows": "Eyebrows",
    "beard": "FacialHair",
    "facial hair": "FacialHair",
    "mustache": "FacialHair",
    "moustache": "FacialHair",
    "eyeliner": "Eyeliner",
    "eyeshadow": "Eyeshadow",
    "eye shadow": "Eyeshadow",
    "eyelid": "Eyeshadow",
    "eyelids": "Eyeshadow",
    "eyelash": "Eyelashes",
    "eyelashes": "Eyelashes",
    "lash": "Eyelashes",
    "lashes": "Eyelashes",
    "mascara": "Eyelashes",
    "blush": "Blush",
    "cheek": "Blush",
    "cheeks": "Blush",
    "lipstick": "Lipstick",
    "lipliner": "Lipstick",
    "lip liner": "Lipstick",
    "facepaint": "FacePaint",
    "face paint": "FacePaint",
    "facemask": "FacePaint",
    "face mask": "FacePaint",
    "nosemask": "FacePaint",
    "nose mask": "FacePaint",
    "tattoo": "Tattoo",
    "tattoos": "Tattoo",
    "freckle": "Freckles",
    "freckles": "Freckles",
    "skin detail": "SkinDetails",
    "skindetail": "SkinDetails",
}

BODY_TYPE_BY_ID: Dict[int, str] = {
    0x00: "All",
    0x01: "Hat",
    0x02: "Hair",
    0x03: "Head",
    0x04: "Face",
    0x05: "FullBody",
    0x06: "Top",
    0x07: "Bottom",
    0x08: "Shoes",
    0x09: "Accessories",
    0x0A: "Earrings",
    0x0B: "Glasses",
    0x0C: "Necklace",
    0x0D: "Gloves",
    0x0E: "BraceletLeft",
    0x0F: "BraceletRight",
    0x10: "LipRingLeft",
    0x11: "LipRingRight",
    0x12: "NoseRingLeft",
    0x13: "NoseRingRight",
    0x14: "BrowRingLeft",
    0x15: "BrowRingRight",
    0x16: "RingIndexLeft",
    0x17: "RingIndexRight",
    0x18: "RingThirdLeft",
    0x19: "RingThirdRight",
    0x1A: "RingMidLeft",
    0x1B: "RingMidRight",
    0x1C: "FacialHair",
    0x1D: "Lipstick",
    0x1E: "Eyeshadow",
    0x1F: "Eyeliner",
    0x20: "Blush",
    0x21: "Facepaint",
    0x22: "Eyebrows",
    0x23: "Eyecolor",
    0x24: "Socks",
    0x25: "Eyelashes",
    0x26: "ForeheadCrease",
    0x27: "Freckles",
    0x28: "DimpleLeft",
    0x29: "DimpleRight",
    0x2A: "Tights",
    0x2B: "MoleLeftLip",
    0x2C: "MoleRightLip",
    0x2D: "TattooArmLowerLeft",
    0x2E: "TattooArmUpperLeft",
    0x2F: "TattooArmLowerRight",
    0x30: "TattooArmUpperRight",
    0x31: "TattooLegLeft",
    0x32: "TattooLegRight",
    0x33: "TattooTorsoBackLower",
    0x34: "TattooTorsoBackUpper",
    0x35: "TattooTorsoFrontLower",
    0x36: "TattooTorsoFrontUpper",
    0x37: "MoleLeftCheek",
    0x38: "MoleRightCheek",
    0x39: "MouthCrease",
    0x3A: "SkinOverlay",
}

CAS_RESOURCE_TYPES = {
    0x034AEECB,  # CASP
    0x015A1849,  # GEOM
    0xAC16FBEC,  # RMAP
    0x0354796A,  # SkinTone
    0x71BDB8A2,  # StyledLook
}

BUILD_BUY_RESOURCE_TYPES = {
    0x319E4F1D,  # COBJ
    0xC0DB5AE7,  # OBJD
    0xB91E18DB,  # Object Catalog Set
    0x9F5CFF10,  # Style
    0xD5F0F921,  # Wall
    0xB4F762C9,  # Floor
    0x0418FE2A,  # Fence
    0x2FAE983E,  # Foundation
    0x1C1CF1F7,  # Railing
    0x91EDBD3E,  # Roof
    0xF1EDBD86,  # Roof Pattern
    0xB0311D0F,  # Roof Trim
    0x3F0C529A,  # Spandrel
    0x9A20CD1C,  # Stairs
    0xEBCBB16C,  # Terrain Paint
    0xA5DFFCF3,  # Pool Trim
    0x1D6DF1CF,  # Column
}

TUNING_RESOURCE_TYPES = {
    0x03B33DDF,  # Tuning / TuningMarkup
    0xE882D22F,  # InteractionTuning
    0xB61DE6B4,  # ObjectTuning
    0x7DF2169C,  # SnippetTuning
    0xCB5FDDC7,  # TraitTuning
    0x6017E896,  # BuffTuning
    0x339BC5BD,  # StatisticTuning
    0xFBC3AEEB,  # SituationTuning
    0x62E94D38,  # CombinedTuning (binary)
}

MERGED_MANIFEST_TYPES = {
    0x7FB6AD8A,  # modern package manifest used by merge/unmerge tools
    0x73E93EEB,  # legacy package manifest type
}

# Strong fallback for legacy/manual merged CAS packages without a manifest resource.
LEGACY_MERGED_MIN_CASPART_COUNT = 200
LEGACY_MERGED_MIN_CASPART_DENSITY = 0.25
LEGACY_MERGED_MAX_RESOURCE_TYPES = 10

MERGED_FILENAME_HINTS = (
    "tsrlibrary",
    "tsr_library",
    "merged",
)

MERGED_FOLDER_HINTS = (
    "posmerged",
    "mergedsure",
    "tsrlibrary",
    "tsr_library",
)

CASP_RESOURCE_TYPE = 0x034AEECB
CAS_PRESET_TYPE = 0xEAA32ADD  # CASPresetResource – identifies CAS preset packages

ANIMATION_RESOURCE_TYPES = {
    0x6B20C4F3,  # ClipResource – animation clips
    0xBC4A5044,  # Jazz script – animation state machine bytecode
}

SIM_MODIFIER_TYPE = 0x8B18FF6E  # SimModifier – CAS sliders / body-face modifiers

OVERRIDE_FILENAME_TOKENS = (
    "override",
    "replacement",
)

CAS_FLAG_CATEGORY_TO_BODY_TYPE: Dict[int, str] = {
    0x004D: "Hair",
    0x004E: "FacialHair",
    0x004F: "Hat",
    0x0050: "Facepaint",
    0x0051: "Top",
    0x0052: "Bottom",
    0x0053: "FullBody",
    0x0054: "Shoes",
    0x005C: "Accessories",
}

# Candidate CASP header layouts ordered by version range.
# Each tuple: (min_version, max_version, pre_flags_size, per_flag_size, post_flags_size)
_CASP_LAYOUTS = [
    (50, 999, 54, 6, 17),
    (41,  49, 40, 6, 17),
    (38,  40, 32, 6, 13),
    (37,  37, 31, 6, 13),
    (36,  36, 31, 4, 13),
    ( 0,  35, 27, 4, 13),
]


def read_uint32(data: bytes, offset: int) -> Optional[int]:
    if offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def read_uint64(data: bytes, offset: int) -> Optional[int]:
    if offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, offset)[0]


def read_7bit_int(data: bytes, offset: int) -> Tuple[Optional[int], int]:
    value = 0
    shift = 0
    cursor = offset
    while cursor < len(data) and shift <= 35:
        byte_value = data[cursor]
        cursor += 1
        value |= (byte_value & 0x7F) << shift
        if (byte_value & 0x80) == 0:
            return value, cursor
        shift += 7
    return None, cursor


def parse_dbpf_entries(data: bytes) -> List[Dict[str, int]]:
    if len(data) < 96 or data[:4] != b"DBPF":
        return []

    index_count = read_uint32(data, 36)
    short_index_offset = read_uint32(data, 40)
    long_index_offset = read_uint64(data, 64)

    if index_count is None or long_index_offset is None or short_index_offset is None:
        return []

    index_offset = short_index_offset if short_index_offset != 0 else long_index_offset
    if index_count == 0 or index_offset >= len(data):
        return []

    cursor = int(index_offset)
    index_flags = read_uint32(data, cursor)
    if index_flags is None:
        return []
    cursor += 4

    constant_type: Optional[int] = None
    constant_group: Optional[int] = None
    constant_instance_hi: Optional[int] = None

    if index_flags & 0x1:
        constant_type = read_uint32(data, cursor)
        if constant_type is None:
            return []
        cursor += 4

    if index_flags & 0x2:
        constant_group = read_uint32(data, cursor)
        if constant_group is None:
            return []
        cursor += 4

    if index_flags & 0x4:
        constant_instance_hi = read_uint32(data, cursor)
        if constant_instance_hi is None:
            return []
        cursor += 4

    entries: List[Dict[str, int]] = []

    for _ in range(index_count):
        entry_type = constant_type
        if entry_type is None:
            entry_type = read_uint32(data, cursor)
            if entry_type is None:
                break
            cursor += 4

        if constant_group is None:
            group = read_uint32(data, cursor)
            if group is None:
                break
            cursor += 4

        if constant_instance_hi is None:
            instance_hi = read_uint32(data, cursor)
            if instance_hi is None:
                break
            cursor += 4

        instance_lo = read_uint32(data, cursor)
        resource_offset = read_uint32(data, cursor + 4)
        size_and_flag = read_uint32(data, cursor + 8)
        uncompressed_size = read_uint32(data, cursor + 12)
        if instance_lo is None or resource_offset is None or size_and_flag is None or uncompressed_size is None:
            break
        cursor += 16

        compressed_size = size_and_flag & 0x7FFFFFFF
        extended_entry = (size_and_flag & 0x80000000) != 0

        compression_type = 0x0000
        if extended_entry:
            if cursor + 4 > len(data):
                break
            compression_type = struct.unpack_from("<H", data, cursor)[0]
            cursor += 4

        entries.append(
            {
                "type": entry_type,
                "offset": resource_offset,
                "compressed_size": compressed_size,
                "uncompressed_size": uncompressed_size,
                "compression_type": compression_type,
            }
        )

    return entries


def read_resource_payload(data: bytes, entry: Dict[str, int]) -> Optional[bytes]:
    offset = entry["offset"]
    compressed_size = entry["compressed_size"]
    if compressed_size <= 0 or offset < 0 or offset + compressed_size > len(data):
        return None

    blob = data[offset : offset + compressed_size]
    compression_type = entry["compression_type"]
    if compression_type == 0x0000:
        return blob
    if compression_type == 0x5A42:
        try:
            return zlib.decompress(blob)
        except zlib.error:
            return None

    # unsupported/internal compression types
    return None


def _try_casp_layout(
    data: bytes,
    name_end: int,
    pre_flags_size: int,
    per_flag_size: int,
    post_flags_size: int,
) -> Optional[str]:
    """Try a specific CASP layout and return the body type if it validates."""
    fc_offset = name_end + pre_flags_size
    if fc_offset + 4 > len(data):
        return None

    flag_count = struct.unpack_from("<I", data, fc_offset)[0]
    if flag_count > 256:
        return None

    entries_start = fc_offset + 4
    flags_end = entries_start + flag_count * per_flag_size
    bt_offset = flags_end + post_flags_size
    if bt_offset + 4 > len(data):
        return None

    body_type_value = struct.unpack_from("<i", data, bt_offset)[0]
    if body_type_value < 0:
        return None

    bt_name = BODY_TYPE_BY_ID.get(body_type_value)
    if bt_name is None or bt_name == "All":
        return None

    # Validate: check flag category values are in the expected CAS range.
    if flag_count > 0:
        valid = 0
        check = min(flag_count, 5)
        for i in range(check):
            cat_off = entries_start + i * per_flag_size
            if cat_off + 2 > len(data):
                break
            cat = struct.unpack_from("<H", data, cat_off)[0]
            if 0x0040 <= cat <= 0x0070:
                valid += 1
        if valid < max(1, check // 2):
            return None

    return bt_name


def extract_casp_body_type_from_resource(resource_data: bytes) -> Optional[str]:
    if len(resource_data) < 20:
        return None

    cursor = 0
    version = read_uint32(resource_data, cursor)
    if version is None:
        return None
    cursor += 4

    tgi_offset = read_uint32(resource_data, cursor)
    if tgi_offset is None:
        return None
    cursor += 4

    preset_count = read_uint32(resource_data, cursor)
    if preset_count is None:
        return None
    cursor += 4

    name_length, cursor = read_7bit_int(resource_data, cursor)
    if name_length is None:
        return None
    if cursor + name_length > len(resource_data):
        return None
    cursor += name_length

    # Build candidate layouts ordered by likelihood for this version.
    # Each tuple: (pre_flags_size, per_flag_size, post_flags_size)
    # Empirically verified across versions v27-v51.
    if version >= 50:
        candidates = [(54, 6, 17), (40, 6, 17)]
    elif version >= 41:
        candidates = [(40, 6, 17)]
    elif version >= 38:
        candidates = [(32, 6, 13), (40, 6, 17), (31, 6, 13)]
    elif version >= 37:
        candidates = [(31, 6, 13), (32, 6, 13)]
    elif version >= 36:
        candidates = [(31, 4, 13), (27, 4, 13)]
    else:
        candidates = [(27, 4, 13)]

    for pfs, pfl, post_fs in candidates:
        result = _try_casp_layout(resource_data, cursor, pfs, pfl, post_fs)
        if result is not None:
            return result

    return None


def extract_casp_body_type_from_flag_table(resource_data: bytes) -> Optional[str]:
    best_score = -1
    best_body_type: Optional[str] = None

    search_end = min(len(resource_data) - 32, 420)
    for flag_count_offset in range(96, search_end):
        flag_count = read_uint32(resource_data, flag_count_offset)
        if flag_count is None or flag_count <= 0 or flag_count > 256:
            continue

        entries_start = flag_count_offset + 4
        entries_end = entries_start + (flag_count * 6)
        body_value_offset = entries_end + 13

        if body_value_offset + 4 > len(resource_data):
            continue

        valid_category_count = 0
        first_mapped_category: Optional[str] = None

        probe_count = min(flag_count, 40)
        for index in range(probe_count):
            category_offset = entries_start + (index * 6)
            if category_offset + 2 > len(resource_data):
                break

            category = struct.unpack_from("<H", resource_data, category_offset)[0]
            if 0x0040 <= category <= 0x0070:
                valid_category_count += 1

            mapped = CAS_FLAG_CATEGORY_TO_BODY_TYPE.get(category)
            if first_mapped_category is None and mapped is not None:
                first_mapped_category = mapped

        if valid_category_count < min(3, probe_count):
            continue

        body_type_value = struct.unpack_from("<i", resource_data, body_value_offset)[0]
        mapped_body = BODY_TYPE_BY_ID.get(body_type_value)
        if mapped_body == "All":
            mapped_body = None

        candidate = mapped_body or first_mapped_category
        if candidate is None:
            continue

        score = (valid_category_count * 1000) - flag_count_offset
        if score > best_score:
            best_score = score
            best_body_type = candidate

    return best_body_type


# Body-type IDs whose integer values are common in binary data and produce
# false positives when scanning aligned int32 values (e.g. 0x20 = space).
_NOISY_BODY_TYPE_IDS = {0x20}


def extract_casp_body_type_from_id_frequency(resource_data: bytes) -> Optional[str]:
    # Last-resort heuristic for CASP variants where known structured offsets are not stable.
    counts: Dict[str, int] = {}

    # Start at offset 4 to skip the CASP version field (e.g. version 43 = 0x2B
    # which would falsely match MoleLeftLip).
    for offset in range(4, len(resource_data) - 3, 4):
        value = struct.unpack_from("<i", resource_data, offset)[0]
        if value < 0 or value in _NOISY_BODY_TYPE_IDS:
            continue

        body_type = BODY_TYPE_BY_ID.get(value)
        if body_type is None or body_type == "All":
            continue

        counts[body_type] = counts.get(body_type, 0) + 1

    if not counts:
        return None

    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    top_body_type, top_count = ranked[0]
    if top_count < 2:
        return None

    return top_body_type


def to_searchable_text(data: bytes) -> str:
    stripped = data.replace(b"\x00", b"")
    return stripped.decode("latin-1", errors="ignore").lower()


def find_first_marker_offset(data: bytes, markers: Tuple[bytes, ...]) -> Optional[int]:
    indexes: List[int] = []
    for marker in markers:
        position = data.find(marker)
        if position >= 0:
            indexes.append(position)

    if not indexes:
        return None

    return min(indexes)


def normalize_body_type(raw_value: str) -> Optional[str]:
    normalized = re.sub(r"[^a-z0-9 ]+", " ", raw_value.lower()).strip()
    if not normalized:
        return None

    if normalized in BODY_TYPE_ALIASES:
        return BODY_TYPE_ALIASES[normalized]

    compact = normalized.replace(" ", "")
    if compact in BODY_TYPE_ALIASES:
        return BODY_TYPE_ALIASES[compact]

    parts = normalized.split()
    for part in parts:
        if part in BODY_TYPE_ALIASES:
            return BODY_TYPE_ALIASES[part]

    return None


def detect_first_body_type(data: bytes) -> Optional[str]:
    search_spaces = [
        data.decode("latin-1", errors="ignore").lower(),
        to_searchable_text(data),
    ]

    patterns = (
        r"body\s*type\s*[:=\-]?\s*([a-z][a-z\s/_-]{1,40})",
        r"bodytype\s*[:=\-]?\s*([a-z][a-z\s/_-]{1,40})",
    )

    best_match: Optional[Tuple[int, str]] = None
    for lowered in search_spaces:
        for pattern in patterns:
            for match in re.finditer(pattern, lowered):
                candidate = normalize_body_type(match.group(1))
                if candidate is None:
                    continue

                offset = match.start()
                if best_match is None or offset < best_match[0]:
                    best_match = (offset, candidate)

        marker_spans = (
            r"body\s*type\s*[:=\-]?\s*([^\r\n]{1,80})",
            r"bodytype\s*[:=\-]?\s*([^\r\n]{1,80})",
        )
        for span_pattern in marker_spans:
            for match in re.finditer(span_pattern, lowered):
                snippet = match.group(1)
                words = re.findall(r"[a-z][a-z ]{1,40}", snippet)
                for word in words:
                    candidate = normalize_body_type(word)
                    if candidate is None:
                        continue

                    offset = match.start()
                    if best_match is None or offset < best_match[0]:
                        best_match = (offset, candidate)
                    break

    if best_match is not None:
        return best_match[1]

    # Fallback: pick first known body-type token seen in file text.
    first_token: Optional[Tuple[int, str]] = None
    for lowered in search_spaces:
        for token, canonical in BODY_TYPE_ALIASES.items():
            pattern = r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])"
            match = re.search(pattern, lowered)
            if not match:
                continue

            index = match.start()
            if first_token is None or index < first_token[0]:
                first_token = (index, canonical)

    if first_token is not None:
        return first_token[1]

    # Loose fallback for compacted naming like "ymtop_tshirt".
    loose_match: Optional[Tuple[int, str]] = None
    for lowered in search_spaces:
        for token, canonical in BODY_TYPE_ALIASES.items():
            index = lowered.find(token)
            if index < 0:
                continue

            if loose_match is None or index < loose_match[0]:
                loose_match = (index, canonical)

    if loose_match is not None:
        return loose_match[1]

    return None


def detect_body_type_from_explicit_markers(data: bytes) -> Optional[str]:
    search_spaces = [
        data.decode("latin-1", errors="ignore").lower(),
        to_searchable_text(data),
    ]

    patterns = (
        r"body\s*type\s*[:=\-]?\s*([a-z][a-z\s/_-]{1,40})",
        r"bodytype\s*[:=\-]?\s*([a-z][a-z\s/_-]{1,40})",
    )

    best_match: Optional[Tuple[int, str]] = None
    for lowered in search_spaces:
        for pattern in patterns:
            for match in re.finditer(pattern, lowered):
                candidate = normalize_body_type(match.group(1))
                if candidate is None:
                    continue

                offset = match.start()
                if best_match is None or offset < best_match[0]:
                    best_match = (offset, candidate)

        marker_spans = (
            r"body\s*type\s*[:=\-]?\s*([^\r\n]{1,80})",
            r"bodytype\s*[:=\-]?\s*([^\r\n]{1,80})",
        )
        for span_pattern in marker_spans:
            for match in re.finditer(span_pattern, lowered):
                snippet = match.group(1)
                words = re.findall(r"[a-z][a-z ]{1,40}", snippet)
                for word in words:
                    candidate = normalize_body_type(word)
                    if candidate is None:
                        continue

                    offset = match.start()
                    if best_match is None or offset < best_match[0]:
                        best_match = (offset, candidate)
                    break

    if best_match is not None:
        return best_match[1]

    return None


def detect_body_type_from_filename(package_path: Path) -> Optional[str]:
    stem = package_path.stem.lower()
    normalized = re.sub(r"[^a-z0-9 ]+", " ", stem).strip()
    if not normalized:
        return None

    direct = normalize_body_type(normalized)
    if direct is not None:
        return direct

    best_match: Optional[Tuple[int, str]] = None
    for token, canonical in BODY_TYPE_ALIASES.items():
        index = normalized.find(token)
        if index < 0:
            continue

        if best_match is None or index < best_match[0]:
            best_match = (index, canonical)

    if best_match is not None:
        return best_match[1]

    return None


def classify_package(package_path: Path) -> Tuple[str, Optional[str]]:
    try:
        raw_data = package_path.read_bytes()
    except OSError:
        return "Unknown", None

    entries = parse_dbpf_entries(raw_data)
    if entries:
        has_merged_manifest = any(entry["type"] in MERGED_MANIFEST_TYPES for entry in entries)
        if has_merged_manifest:
            return "Merged", None

        type_counts: Dict[int, int] = {}
        casp_count = 0

        first_cas_index: Optional[int] = None
        first_build_index: Optional[int] = None
        first_tuning_index: Optional[int] = None
        first_body_type: Optional[str] = None
        has_casp = False
        has_cas_preset = False
        has_animation = False
        has_sim_modifier = False

        for index, entry in enumerate(entries):
            entry_type = entry["type"]
            type_counts[entry_type] = type_counts.get(entry_type, 0) + 1
            if entry_type == CASP_RESOURCE_TYPE:
                casp_count += 1

            if first_cas_index is None and entry_type in CAS_RESOURCE_TYPES:
                first_cas_index = index

            if first_build_index is None and entry_type in BUILD_BUY_RESOURCE_TYPES:
                first_build_index = index

            if first_tuning_index is None and entry_type in TUNING_RESOURCE_TYPES:
                first_tuning_index = index

            if first_body_type is None and entry_type == CASP_RESOURCE_TYPE:
                has_casp = True
                payload = read_resource_payload(raw_data, entry)
                if payload is not None:
                    first_body_type = extract_casp_body_type_from_resource(payload)
                    if first_body_type is None:
                        first_body_type = extract_casp_body_type_from_flag_table(payload)
                    if first_body_type is None:
                        first_body_type = extract_casp_body_type_from_id_frequency(payload)
                    if first_body_type is None:
                        first_body_type = detect_first_body_type(payload)
            elif entry_type == CASP_RESOURCE_TYPE:
                has_casp = True

            if entry_type == CAS_PRESET_TYPE:
                has_cas_preset = True

            if entry_type in ANIMATION_RESOURCE_TYPES:
                has_animation = True

            if entry_type == SIM_MODIFIER_TYPE:
                has_sim_modifier = True

        casp_density = (casp_count / len(entries)) if entries else 0.0
        if (
            casp_count >= LEGACY_MERGED_MIN_CASPART_COUNT
            and casp_density >= LEGACY_MERGED_MIN_CASPART_DENSITY
            and len(type_counts) <= LEGACY_MERGED_MAX_RESOURCE_TYPES
            and not has_cas_preset
        ):
            return "Merged", None

        if first_cas_index is not None and (first_build_index is None or first_cas_index <= first_build_index):
            if first_body_type is None:
                # Some files include tuning resources and are misclassified as CAS by weak markers.
                if first_tuning_index is not None and not has_casp:
                    return "Tuning", None

                # Fallback to full-package marker scan before filename heuristics.
                first_body_type = detect_body_type_from_explicit_markers(raw_data)
                if first_body_type is None:
                    first_body_type = detect_body_type_from_filename(package_path)
            return "CAS", first_body_type

        if first_build_index is not None:
            return "BuildBuy", None

        if first_tuning_index is not None:
            if has_animation:
                return "Animation", None
            return "Tuning", None

        if has_cas_preset:
            return "Preset", None

        if has_animation:
            return "Animation", None

        if has_sim_modifier:
            return "Slider", None

    search_buffers = [raw_data.lower(), raw_data.replace(b"\x00", b"").lower()]

    cas_candidates = [
        find_first_marker_offset(buffer_data, CAS_MARKERS)
        for buffer_data in search_buffers
    ]
    build_buy_candidates = [
        find_first_marker_offset(buffer_data, BUILD_BUY_MARKERS)
        for buffer_data in search_buffers
    ]

    cas_offsets = [offset for offset in cas_candidates if offset is not None]
    build_buy_offsets = [offset for offset in build_buy_candidates if offset is not None]

    cas_offset = min(cas_offsets) if cas_offsets else None
    build_buy_offset = min(build_buy_offsets) if build_buy_offsets else None

    if cas_offset is None and build_buy_offset is None:
        tuning_candidates = [
            find_first_marker_offset(buffer_data, TUNING_MARKERS)
            for buffer_data in search_buffers
        ]
        tuning_offsets = [offset for offset in tuning_candidates if offset is not None]
        if tuning_offsets:
            return "Tuning", None
        if _is_override_filename(package_path):
            return "Override", None
        return "Unknown", None

    if cas_offset is not None and (build_buy_offset is None or cas_offset <= build_buy_offset):
        body_type = detect_first_body_type(raw_data)
        return "CAS", body_type

    tuning_candidates = [
        find_first_marker_offset(buffer_data, TUNING_MARKERS)
        for buffer_data in search_buffers
    ]
    tuning_offsets = [offset for offset in tuning_candidates if offset is not None]
    tuning_offset = min(tuning_offsets) if tuning_offsets else None
    if tuning_offset is not None and (build_buy_offset is None or tuning_offset < build_buy_offset):
        return "Tuning", None

    return "BuildBuy", None


def detect_merged_status(package_path: Path) -> str:
    """Return merged detection status: Merged, ProbablyMerged, NotMerged, or Unreadable."""
    # Only treat strong folder hints as merged. Avoid generic "Merged" folder names,
    # which are often used for manual sorting and can contain non-merged packages.
    for parent in package_path.parents:
        parent_name = parent.name.lower()
        if any(token in parent_name for token in MERGED_FOLDER_HINTS):
            return "Merged"

    try:
        raw_data = package_path.read_bytes()
    except OSError:
        return "Unreadable"

    entries = parse_dbpf_entries(raw_data)
    if not entries:
        return "Unreadable"

    if any(entry["type"] in MERGED_MANIFEST_TYPES for entry in entries):
        return "Merged"

    casp_count = sum(1 for entry in entries if entry["type"] == CASP_RESOURCE_TYPE)
    has_cas_preset = any(entry["type"] == CAS_PRESET_TYPE for entry in entries)
    casp_density = (casp_count / len(entries)) if entries else 0.0
    unique_type_count = len({int(entry["type"]) for entry in entries})

    if (
        casp_count >= LEGACY_MERGED_MIN_CASPART_COUNT
        and casp_density >= LEGACY_MERGED_MIN_CASPART_DENSITY
        and unique_type_count <= LEGACY_MERGED_MAX_RESOURCE_TYPES
        and not has_cas_preset
    ):
        return "Merged"

    name_lower = package_path.name.lower()
    if any(token in name_lower for token in MERGED_FILENAME_HINTS):
        return "ProbablyMerged"

    if casp_count > LEGACY_MERGED_MIN_CASPART_COUNT:
        return "ProbablyMerged"

    return "NotMerged"


def _is_override_filename(package_path: Path) -> bool:
    name_lower = package_path.stem.lower()
    return any(token in name_lower for token in OVERRIDE_FILENAME_TOKENS)


def build_unique_destination(target_folder: Path, file_name: str) -> Path:
    destination = target_folder / file_name
    if not destination.exists():
        return destination

    stem = Path(file_name).stem
    suffix = Path(file_name).suffix
    counter = 1

    while True:
        candidate = target_folder / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def move_file(source: Path, destination_folder: Path, dry_run: bool) -> Optional[Path]:
    destination_folder.mkdir(parents=True, exist_ok=True)
    destination = build_unique_destination(destination_folder, source.name)

    if source.resolve() == destination.resolve():
        return source

    if dry_run:
        return destination

    try:
        shutil.move(str(source), str(destination))
    except OSError:
        return None

    return destination


def list_package_files(base_path: Path) -> List[Path]:
    return [path for path in base_path.rglob("*") if path.is_file() and path.suffix.lower() == ".package"]


def organize_packages(base_path: Path, output_base: Path, dry_run: bool) -> Dict[str, int]:
    stats = {
        "total": 0,
        "merged_moved": 0,
        "probable_merged_moved": 0,
        "cas_moved": 0,
        "cas_unknown_body_type": 0,
        "buildbuy_moved": 0,
        "tuning_moved": 0,
        "preset_moved": 0,
        "animation_moved": 0,
        "slider_moved": 0,
        "override_moved": 0,
        "unknown_moved": 0,
        "failed_moves": 0,
    }

    package_files = list_package_files(base_path)

    for package_file in package_files:
        stats["total"] += 1
        try:
            display_path = str(package_file.relative_to(base_path))
        except ValueError:
            display_path = str(package_file)

        merged_status = detect_merged_status(package_file)
        if merged_status == "Merged":
            target_folder = output_base / "Merged"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as Merged - move failed to Merged")
            else:
                stats["merged_moved"] += 1
                print(f"{display_path} - identified as Merged - moved to Merged")

            continue

        if merged_status == "ProbablyMerged":
            target_folder = output_base / "ProbableMerged"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as ProbablyMerged - move failed to ProbableMerged")
            else:
                stats["probable_merged_moved"] += 1
                print(f"{display_path} - identified as ProbablyMerged - moved to ProbableMerged")

            continue

        package_type, body_type = classify_package(package_file)
        if package_type == "Merged":
            target_folder = output_base / "Merged"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as Merged - move failed to Merged")
            else:
                stats["merged_moved"] += 1
                print(f"{display_path} - identified as Merged - moved to Merged")

            continue

        if package_type == "CAS":
            target_name = body_type or "UnknownBodyType"
            if body_type is None:
                stats["cas_unknown_body_type"] += 1
            target_folder = output_base / target_name
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as CAS - move failed to {target_name}")
            else:
                stats["cas_moved"] += 1
                print(f"{display_path} - identified as CAS - moved to {target_name}")

            continue

        if package_type == "BuildBuy":
            target_folder = output_base / "BuildItem"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as Build - move failed to BuildItem")
            else:
                stats["buildbuy_moved"] += 1
                print(f"{display_path} - identified as Build - moved to BuildItem")

            continue

        if package_type == "Tuning":
            target_folder = output_base / "Tuning"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as Tuning - move failed to Tuning")
            else:
                stats["tuning_moved"] += 1
                print(f"{display_path} - identified as Tuning - moved to Tuning")

            continue

        if package_type == "Preset":
            target_folder = output_base / "Presets"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as Preset - move failed to Presets")
            else:
                stats["preset_moved"] += 1
                print(f"{display_path} - identified as Preset - moved to Presets")

            continue

        if package_type == "Animation":
            target_folder = output_base / "Animations"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as Animation - move failed to Animations")
            else:
                stats["animation_moved"] += 1
                print(f"{display_path} - identified as Animation - moved to Animations")

            continue

        if package_type == "Slider":
            target_folder = output_base / "Sliders"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as Slider - move failed to Sliders")
            else:
                stats["slider_moved"] += 1
                print(f"{display_path} - identified as Slider - moved to Sliders")

            continue

        if package_type == "Override":
            target_folder = output_base / "Overrides"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as Override - move failed to Overrides")
            else:
                stats["override_moved"] += 1
                print(f"{display_path} - identified as Override - moved to Overrides")

            continue

        target_folder = output_base / "Other"
        moved_to = move_file(package_file, target_folder, dry_run=dry_run)

        if moved_to is None:
            stats["failed_moves"] += 1
            print(f"{display_path} - identified as Unknown - move failed to Other")
        else:
            stats["unknown_moved"] += 1
            print(f"{display_path} - identified as Unknown - moved to Other")

    return stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a Sims 4 mods folder recursively, detect CAS/Build-Buy metadata in .package files, "
            "and move files into body-type or BuildItem folders."
        )
    )
    parser.add_argument("path", help="Path to scan recursively")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview detected targets without moving files",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    base_path = Path(args.path).expanduser().resolve()
    output_base = base_path.parent / f"{base_path.name}_Organized"

    if not base_path.exists() or not base_path.is_dir():
        print(f"Invalid directory: {base_path}")
        raise SystemExit(1)

    stats = organize_packages(base_path, output_base, dry_run=args.dry_run)

    mode = "DRY RUN" if args.dry_run else "APPLY"
    print(f"Scan finished. Mode: {mode}")
    print(f"Output base folder: {output_base}")
    print(f"Total .package files scanned: {stats['total']}")
    print(f"Merged files moved: {stats['merged_moved']}")
    print(f"Probable merged files moved: {stats['probable_merged_moved']}")
    print(f"CAS files moved: {stats['cas_moved']}")
    print(f"CAS files with unknown body type: {stats['cas_unknown_body_type']}")
    print(f"Build/Buy files moved: {stats['buildbuy_moved']}")
    print(f"Tuning files moved: {stats['tuning_moved']}")
    print(f"Preset files moved: {stats['preset_moved']}")
    print(f"Animation files moved: {stats['animation_moved']}")
    print(f"Slider files moved: {stats['slider_moved']}")
    print(f"Override files moved: {stats['override_moved']}")
    print(f"Other/unknown files moved: {stats['unknown_moved']}")
    print(f"Failed moves: {stats['failed_moves']}")


if __name__ == "__main__":
    main()
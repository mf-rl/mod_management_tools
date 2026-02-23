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
    "necklace": "Necklace",
    "necklaces": "Necklace",
    "ring": "Rings",
    "rings": "Rings",
    "bracelet": "Bracelet",
    "bracelets": "Bracelet",
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
    "fullbody": "FullBody",
    "full body": "FullBody",
    "outfit": "FullBody",
    "outfits": "FullBody",
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
    "blush": "Blush",
    "lipstick": "Lipstick",
    "facepaint": "FacePaint",
    "face paint": "FacePaint",
    "tattoo": "Tattoo",
    "tattoos": "Tattoo",
    "skin detail": "SkinDetails",
    "skindetail": "SkinDetails",
}

BODY_TYPE_BY_ID: Dict[int, str] = {
    0x00: "All",
    0x01: "Hat",
    0x02: "Hair",
    0x03: "Head",
    0x04: "Face",
    0x05: "Body",
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
    0x25: "Mascara",
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

CASP_RESOURCE_TYPE = 0x034AEECB

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

    fixed_prefix = 4 + 2 + 4 + 4 + 1 + 8
    if cursor + fixed_prefix > len(resource_data):
        return None
    cursor += fixed_prefix

    if version >= 36:
        if cursor + 8 > len(resource_data):
            return None
        cursor += 8
    else:
        if cursor + 4 > len(resource_data):
            return None
        cursor += 4

    flag_count = read_uint32(resource_data, cursor)
    if flag_count is None:
        return None
    cursor += 4

    per_flag_size = 6 if version >= 37 else 4
    flags_byte_size = flag_count * per_flag_size
    if cursor + flags_byte_size > len(resource_data):
        return None
    cursor += flags_byte_size

    if cursor + 4 + 4 + 4 + 1 + 4 > len(resource_data):
        return None

    # deprecatedPrice, partTitleKey, partDescriptionKey, uniqueTextureSpace
    cursor += 4 + 4 + 4 + 1
    body_type_value = struct.unpack_from("<i", resource_data, cursor)[0]

    if body_type_value < 0:
        return None

    parsed = BODY_TYPE_BY_ID.get(body_type_value)
    if parsed == "All":
        return None
    return parsed


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
        first_cas_index: Optional[int] = None
        first_build_index: Optional[int] = None
        first_body_type: Optional[str] = None

        for index, entry in enumerate(entries):
            entry_type = entry["type"]
            if first_cas_index is None and entry_type in CAS_RESOURCE_TYPES:
                first_cas_index = index

            if first_build_index is None and entry_type in BUILD_BUY_RESOURCE_TYPES:
                first_build_index = index

            if first_body_type is None and entry_type == CASP_RESOURCE_TYPE:
                payload = read_resource_payload(raw_data, entry)
                if payload is not None:
                    first_body_type = extract_casp_body_type_from_resource(payload)
                    if first_body_type is None:
                        first_body_type = extract_casp_body_type_from_flag_table(payload)
                    if first_body_type is None:
                        first_body_type = detect_first_body_type(payload)

        if first_cas_index is not None and (first_build_index is None or first_cas_index <= first_build_index):
            if first_body_type is None:
                first_body_type = detect_body_type_from_filename(package_path)
            return "CAS", first_body_type

        if first_build_index is not None:
            return "BuildBuy", None

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
        return "Unknown", None

    if cas_offset is not None and (build_buy_offset is None or cas_offset <= build_buy_offset):
        body_type = detect_first_body_type(raw_data)
        return "CAS", body_type

    return "BuildBuy", None


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
    destination_folder.mkdir(exist_ok=True)
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


def organize_packages(base_path: Path, dry_run: bool) -> Dict[str, int]:
    stats = {
        "total": 0,
        "cas_moved": 0,
        "cas_unknown_body_type": 0,
        "buildbuy_moved": 0,
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

        package_type, body_type = classify_package(package_file)
        if package_type == "CAS":
            target_name = body_type or "UnknownBodyType"
            if body_type is None:
                stats["cas_unknown_body_type"] += 1
            target_folder = base_path / target_name
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as CAS - move failed to {target_name}")
            else:
                stats["cas_moved"] += 1
                print(f"{display_path} - identified as CAS - moved to {target_name}")

            continue

        if package_type == "BuildBuy":
            target_folder = base_path / "BuildItem"
            moved_to = move_file(package_file, target_folder, dry_run=dry_run)

            if moved_to is None:
                stats["failed_moves"] += 1
                print(f"{display_path} - identified as Build - move failed to BuildItem")
            else:
                stats["buildbuy_moved"] += 1
                print(f"{display_path} - identified as Build - moved to BuildItem")

            continue

        target_folder = base_path / "PossiblyMerged"
        moved_to = move_file(package_file, target_folder, dry_run=dry_run)

        if moved_to is None:
            stats["failed_moves"] += 1
            print(f"{display_path} - identified as Unknown - move failed to PossiblyMerged")
        else:
            stats["unknown_moved"] += 1
            print(f"{display_path} - identified as Unknown - moved to PossiblyMerged")

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

    if not base_path.exists() or not base_path.is_dir():
        print(f"Invalid directory: {base_path}")
        raise SystemExit(1)

    stats = organize_packages(base_path, dry_run=args.dry_run)

    mode = "DRY RUN" if args.dry_run else "APPLY"
    print(f"Scan finished. Mode: {mode}")
    print(f"Total .package files scanned: {stats['total']}")
    print(f"CAS files moved: {stats['cas_moved']}")
    print(f"CAS files with unknown body type: {stats['cas_unknown_body_type']}")
    print(f"Build/Buy files moved: {stats['buildbuy_moved']}")
    print(f"Unknown metadata moved to PossiblyMerged: {stats['unknown_moved']}")
    print(f"Failed moves: {stats['failed_moves']}")


if __name__ == "__main__":
    main()
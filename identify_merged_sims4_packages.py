import argparse
import ctypes
import json
import os
import shutil
import struct
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


CASP_RESOURCE_TYPE = 0x034AEECB
MERGED_MANIFEST_TYPES = {
    0x7FB6AD8A,  # modern package manifest used by merge/unmerge tooling
    0x73E93EEB,  # legacy package manifest type
}


TGI = Tuple[int, int, int, int]


def read_uint32(data: bytes, offset: int) -> Optional[int]:
    if offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def read_uint64(data: bytes, offset: int) -> Optional[int]:
    if offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, offset)[0]


def parse_dbpf_entries(data: bytes) -> List[Dict[str, int]]:
    if len(data) < 96 or data[:4] != b"DBPF":
        return []

    index_count = read_uint32(data, 36)
    short_index_offset = read_uint32(data, 40)
    long_index_offset = read_uint64(data, 64)

    if index_count is None or short_index_offset is None or long_index_offset is None:
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

        group = constant_group
        if constant_group is None:
            group = read_uint32(data, cursor)
            if group is None:
                break
            cursor += 4

        instance_hi = constant_instance_hi
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
        compression_flags = 0x0000
        if extended_entry:
            if cursor + 4 > len(data):
                break
            compression_type = struct.unpack_from("<H", data, cursor)[0]
            compression_flags = struct.unpack_from("<H", data, cursor + 2)[0]
            cursor += 4

        entries.append(
            {
                "type": entry_type,
                "group": group,
                "instance_hi": instance_hi,
                "instance_lo": instance_lo,
                "offset": resource_offset,
                "compressed_size": compressed_size,
                "uncompressed_size": uncompressed_size,
                "compression_type": compression_type,
                "compression_flags": compression_flags,
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

    return None


def read_resource_blob(data: bytes, entry: Dict[str, int]) -> Optional[bytes]:
    offset = entry["offset"]
    compressed_size = entry["compressed_size"]
    if compressed_size <= 0 or offset < 0 or offset + compressed_size > len(data):
        return None
    return data[offset : offset + compressed_size]


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


def try_parse_manifest_entry_count(payload: bytes) -> Optional[int]:
    alternate_count = read_uint32(payload, 12) if len(payload) >= 16 else None
    if alternate_count is not None and 0 < alternate_count <= 200000:
        return alternate_count

    # Common manifest layouts start with at least 3 uint32 values where the third is count.
    if len(payload) >= 12:
        maybe_count = read_uint32(payload, 8)
        if maybe_count is not None and 0 < maybe_count <= 200000:
            return maybe_count

    # Some variants may store a 7-bit length string after a short header.
    if len(payload) > 16:
        count = read_uint32(payload, 8)
        if count is None or count <= 0 or count > 200000:
            return None

        cursor = 12
        for _ in range(min(count, 3)):
            name_len, cursor = read_7bit_int(payload, cursor)
            if name_len is None:
                return count
            if cursor + name_len > len(payload):
                return None
            cursor += name_len

            resource_count = read_uint32(payload, cursor)
            if resource_count is None or resource_count > 200000:
                return None
            cursor += 4

            tgi_bytes = resource_count * 16
            if cursor + tgi_bytes > len(payload):
                return None
            cursor += tgi_bytes

        return count

    return None


def try_parse_manifest_entries(payload: bytes) -> Optional[List[Dict[str, object]]]:
    def parse_with_u32_name_length(data: bytes) -> Optional[List[Dict[str, object]]]:
        if len(data) < 16:
            return None

        entry_count = read_uint32(data, 12)
        if entry_count is None or entry_count <= 0 or entry_count > 200000:
            return None

        cursor = 16
        parsed_entries: List[Dict[str, object]] = []

        for _ in range(entry_count):
            name_length = read_uint32(data, cursor)
            if name_length is None or name_length > 32768:
                return None
            cursor += 4

            if cursor + name_length > len(data):
                return None

            raw_name = data[cursor : cursor + name_length]
            cursor += name_length

            try:
                name = raw_name.decode("utf-8")
            except UnicodeDecodeError:
                name = raw_name.decode("latin-1", errors="ignore")

            resource_count = read_uint32(data, cursor)
            if resource_count is None or resource_count > 200000:
                return None
            cursor += 4

            tgis: List[TGI] = []
            for _resource_index in range(resource_count):
                if cursor + 16 > len(data):
                    return None
                word0 = struct.unpack_from("<I", data, cursor)[0]
                word1 = struct.unpack_from("<I", data, cursor + 4)[0]
                word2 = struct.unpack_from("<I", data, cursor + 8)[0]
                word3 = struct.unpack_from("<I", data, cursor + 12)[0]
                cursor += 16

                # Sims 4 package-manifest layout commonly stores instance parts first, then type/group.
                resource_type = word2
                group = word3
                instance_hi = word1
                instance_lo = word0
                tgis.append((resource_type, group, instance_hi, instance_lo))

            parsed_entries.append({"name": name, "tgis": tgis})

        return parsed_entries

    def parse_with_7bit_name_length(data: bytes) -> Optional[List[Dict[str, object]]]:
        if len(data) < 12:
            return None

        entry_count = read_uint32(data, 8)
        if entry_count is None or entry_count <= 0 or entry_count > 200000:
            return None

        cursor = 12
        parsed_entries: List[Dict[str, object]] = []

        for _ in range(entry_count):
            name_length, cursor = read_7bit_int(data, cursor)
            if name_length is None:
                return None

            if cursor + name_length > len(data):
                return None

            raw_name = data[cursor : cursor + name_length]
            cursor += name_length

            try:
                name = raw_name.decode("utf-8")
            except UnicodeDecodeError:
                name = raw_name.decode("latin-1", errors="ignore")

            resource_count = read_uint32(data, cursor)
            if resource_count is None or resource_count > 200000:
                return None
            cursor += 4

            tgis: List[TGI] = []
            for _resource_index in range(resource_count):
                if cursor + 16 > len(data):
                    return None
                word0 = struct.unpack_from("<I", data, cursor)[0]
                word1 = struct.unpack_from("<I", data, cursor + 4)[0]
                word2 = struct.unpack_from("<I", data, cursor + 8)[0]
                word3 = struct.unpack_from("<I", data, cursor + 12)[0]
                cursor += 16

                resource_type = word2
                group = word3
                instance_hi = word1
                instance_lo = word0
                tgis.append((resource_type, group, instance_hi, instance_lo))

            parsed_entries.append({"name": name, "tgis": tgis})

        return parsed_entries

    parsed = parse_with_u32_name_length(payload)
    if parsed is not None:
        return parsed

    return parse_with_7bit_name_length(payload)


def find_manifest_entry(data: bytes, entries: List[Dict[str, int]]) -> Optional[Dict[str, object]]:
    for entry in entries:
        if entry["type"] not in MERGED_MANIFEST_TYPES:
            continue

        payload = read_resource_payload(data, entry)
        if payload is None:
            continue

        parsed_entries = try_parse_manifest_entries(payload)
        if parsed_entries is None:
            return {
                "manifest_type": entry["type"],
                "manifest_entries": [],
                "manifest_unparsed": True,
            }

        return {
            "manifest_type": entry["type"],
            "manifest_entries": parsed_entries,
            "manifest_unparsed": False,
        }

    return None


def sanitize_package_name(name: str) -> str:
    cleaned = name.replace("\x00", "").strip()
    cleaned = cleaned.replace("/", "_").replace("\\", "_")
    cleaned = "".join(char for char in cleaned if char not in '<>:"|?*').strip(" .")
    if not cleaned:
        cleaned = "unmerged_item"
    if not cleaned.lower().endswith(".package"):
        cleaned += ".package"
    return cleaned


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


def build_dbpf_package(resources: List[Dict[str, object]]) -> bytes:
    header_size = 96
    index_flags = 0
    index_size = 4 + (len(resources) * 32)
    data_start = header_size
    index_offset = data_start + sum(len(resource["blob"]) for resource in resources)

    output = bytearray(index_offset + index_size)
    output[0:4] = b"DBPF"

    struct.pack_into("<I", output, 4, 2)
    struct.pack_into("<I", output, 8, 1)
    struct.pack_into("<I", output, 32, 0)
    struct.pack_into("<I", output, 36, len(resources))
    struct.pack_into("<I", output, 40, 0)
    struct.pack_into("<I", output, 44, index_size)
    struct.pack_into("<I", output, 60, 3)
    struct.pack_into("<Q", output, 64, index_offset)

    cursor = data_start
    indexed_resources: List[Dict[str, int]] = []
    for resource in resources:
        blob = resource["blob"]
        size = len(blob)
        output[cursor : cursor + size] = blob
        indexed_resources.append(
            {
                "type": int(resource["type"]),
                "group": int(resource["group"]),
                "instance_hi": int(resource["instance_hi"]),
                "instance_lo": int(resource["instance_lo"]),
                "offset": cursor,
                "compressed_size": size,
                "uncompressed_size": int(resource["uncompressed_size"]),
                "compression_type": int(resource["compression_type"]),
                "compression_flags": int(resource.get("compression_flags", 0)),
            }
        )
        cursor += size

    struct.pack_into("<I", output, index_offset, index_flags)
    cursor = index_offset + 4
    for resource in indexed_resources:
        struct.pack_into("<I", output, cursor, resource["type"])
        struct.pack_into("<I", output, cursor + 4, resource["group"])
        struct.pack_into("<I", output, cursor + 8, resource["instance_hi"])
        struct.pack_into("<I", output, cursor + 12, resource["instance_lo"])
        struct.pack_into("<I", output, cursor + 16, resource["offset"])
        size_and_flag = resource["compressed_size"] | 0x80000000
        struct.pack_into("<I", output, cursor + 20, size_and_flag)
        struct.pack_into("<I", output, cursor + 24, resource["uncompressed_size"])
        cursor += 28
        struct.pack_into("<H", output, cursor, resource["compression_type"])
        struct.pack_into("<H", output, cursor + 2, resource["compression_flags"])
        cursor += 4

    return bytes(output)


def unmerge_package_file(package_path: Path, output_folder: Path) -> Tuple[List[Path], str]:
    try:
        raw_data = package_path.read_bytes()
    except OSError as exc:
        return [], f"read failed: {exc}"

    entries = parse_dbpf_entries(raw_data)
    if not entries:
        return [], "invalid DBPF"

    manifest = find_manifest_entry(raw_data, entries)
    if manifest is None:
        return [], "manifest not found or unsupported manifest format"

    manifest_entries: List[Dict[str, object]] = manifest["manifest_entries"]

    resource_map: Dict[TGI, Dict[str, object]] = {}
    for entry in entries:
        if entry["type"] in MERGED_MANIFEST_TYPES:
            continue

        blob = read_resource_blob(raw_data, entry)
        if blob is None:
            continue

        key: TGI = (
            int(entry["type"]),
            int(entry["group"]),
            int(entry["instance_hi"]),
            int(entry["instance_lo"]),
        )
        resource_map[key] = {
            "type": key[0],
            "group": key[1],
            "instance_hi": key[2],
            "instance_lo": key[3],
            "blob": blob,
            "compression_type": int(entry["compression_type"]),
            "compression_flags": int(entry.get("compression_flags", 0)),
            "uncompressed_size": int(entry["uncompressed_size"]),
        }

    if not manifest_entries:
        return unmerge_empty_manifest_by_casp_instance(package_path, output_folder, resource_map)

    created_paths: List[Path] = []
    used_keys: Set[TGI] = set()
    matched_resources_total = 0
    swapped_match_total = 0

    def resolve_resource_from_manifest_tgi(key: TGI) -> Tuple[Optional[Dict[str, object]], TGI, bool]:
        resource = resource_map.get(key)
        if resource is not None:
            return resource, key, False

        # Compatibility fallback: some tools/dumps may serialize instance halves swapped.
        swapped_key: TGI = (key[0], key[1], key[3], key[2])
        resource = resource_map.get(swapped_key)
        if resource is not None:
            return resource, swapped_key, True

        return None, key, False

    for entry in manifest_entries:
        original_name = str(entry["name"])
        tgis = entry["tgis"]

        selected_resources: List[Dict[str, object]] = []
        for key in tgis:
            resource, resolved_key, used_swapped_key = resolve_resource_from_manifest_tgi(key)
            if resource is None:
                continue

            if resolved_key in used_keys:
                continue

            selected_resources.append(resource)
            used_keys.add(resolved_key)
            matched_resources_total += 1
            if used_swapped_key:
                swapped_match_total += 1

        if not selected_resources:
            continue

        safe_name = sanitize_package_name(original_name)
        destination = build_unique_destination(output_folder, safe_name)

        package_bytes = build_dbpf_package(selected_resources)
        destination.write_bytes(package_bytes)
        created_paths.append(destination)

    if not created_paths:
        reason = "manifest parsed but no matching resources were reconstructed"
        if manifest_entries:
            first_entry = manifest_entries[0]
            first_tgis: List[TGI] = first_entry.get("tgis", [])
            if first_tgis:
                sample = first_tgis[0]
                reason += (
                    " | sample manifest TGI="
                    f"0x{sample[0]:08X}:0x{sample[1]:08X}:0x{sample[2]:08X}:0x{sample[3]:08X}"
                )
        reason += f" | index resource keys available={len(resource_map)}"
        return [], reason

    if swapped_match_total > 0:
        return created_paths, (
            f"ok (used swapped-instance fallback for {swapped_match_total}/{matched_resources_total} resource matches)"
        )

    return created_paths, "ok"


def unmerge_empty_manifest_by_casp_instance(
    package_path: Path,
    output_folder: Path,
    resource_map: Dict[TGI, Dict[str, object]],
) -> Tuple[List[Path], str]:
    by_instance: Dict[Tuple[int, int], List[TGI]] = {}
    for key in resource_map.keys():
        instance_key = (key[2], key[3])
        by_instance.setdefault(instance_key, []).append(key)

    casp_instances = [
        instance_key
        for instance_key, keys in by_instance.items()
        if any(key[0] == CASP_RESOURCE_TYPE for key in keys)
    ]

    if not casp_instances:
        return [], "empty-manifest merged package has no CASP resources to split"

    created_paths: List[Path] = []
    used_keys: Set[TGI] = set()

    sorted_instances = sorted(casp_instances, key=lambda item: (item[1], item[0]))
    for index, instance_key in enumerate(sorted_instances, start=1):
        keys = by_instance.get(instance_key, [])
        selected_resources = [resource_map[key] for key in keys if key in resource_map]
        if not selected_resources:
            continue

        safe_name = sanitize_package_name(f"{package_path.stem}_{index:04d}")
        destination = build_unique_destination(output_folder, safe_name)
        package_bytes = build_dbpf_package(selected_resources)
        destination.write_bytes(package_bytes)
        created_paths.append(destination)

        for key in keys:
            used_keys.add(key)

    shared_resources = [
        resource
        for key, resource in resource_map.items()
        if key not in used_keys
    ]
    if shared_resources:
        shared_name = sanitize_package_name(f"{package_path.stem}_shared")
        shared_destination = build_unique_destination(output_folder, shared_name)
        shared_bytes = build_dbpf_package(shared_resources)
        shared_destination.write_bytes(shared_bytes)
        created_paths.append(shared_destination)

    if not created_paths:
        return [], "empty-manifest fallback split produced no files"

    return created_paths, (
        "ok (empty-manifest fallback: split by CASP instance"
        f" into {len(sorted_instances)} package(s)"
        f" with {'1' if shared_resources else '0'} shared package)"
    )


def prompt_delete_originals() -> bool:
    while True:
        answer = input(
            "Delete original merged files after unmerge (send to trash)? [y/N]: "
        ).strip().lower()

        if answer in {"y", "yes"}:
            return True
        if answer in {"", "n", "no"}:
            return False

        print("Please answer with 'y' or 'n'.")


def send_path_to_trash_windows(path: Path) -> bool:
    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", ctypes.c_void_p),
            ("wFunc", ctypes.c_uint),
            ("pFrom", ctypes.c_wchar_p),
            ("pTo", ctypes.c_wchar_p),
            ("fFlags", ctypes.c_ushort),
            ("fAnyOperationsAborted", ctypes.c_bool),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", ctypes.c_wchar_p),
        ]

    FO_DELETE = 3
    FOF_SILENT = 0x0004
    FOF_NOCONFIRMATION = 0x0010
    FOF_ALLOWUNDO = 0x0040
    FOF_NOERRORUI = 0x0400

    operation = SHFILEOPSTRUCTW()
    operation.wFunc = FO_DELETE
    operation.pFrom = f"{str(path)}\0\0"
    operation.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT

    result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(operation))
    return result == 0 and not operation.fAnyOperationsAborted


def send_paths_to_trash(paths: List[Path]) -> List[Path]:
    failed: List[Path] = []

    try:
        from send2trash import send2trash

        for path in paths:
            try:
                send2trash(str(path))
            except Exception:
                failed.append(path)
        return failed
    except ImportError:
        pass

    if os.name == "nt":
        for path in paths:
            if not send_path_to_trash_windows(path):
                failed.append(path)
        return failed

    failed.extend(paths)
    return failed


def move_paths_to_folder(paths: List[Path], destination_folder: Path) -> Tuple[List[Path], List[Tuple[Path, str]]]:
    destination_folder.mkdir(parents=True, exist_ok=True)

    moved: List[Path] = []
    failed: List[Tuple[Path, str]] = []

    for source in paths:
        if not source.exists():
            failed.append((source, "source does not exist"))
            continue

        destination = build_unique_destination(destination_folder, source.name)
        try:
            shutil.move(str(source), str(destination))
            moved.append(source)
        except OSError as exc:
            failed.append((source, str(exc)))

    return moved, failed


def detect_merged_package(
    package_path: Path,
    *,
    min_casparts_primary: int,
    min_casparts_secondary: int,
    min_caspart_density: float,
) -> Dict[str, object]:
    result: Dict[str, object] = {
        "path": str(package_path),
        "status": "NotMerged",
        "confidence": "none",
        "reason": "no merged indicators found",
        "manifest_type": None,
        "manifest_entry_count": None,
        "casp_count": 0,
        "resource_count": 0,
    }

    try:
        raw_data = package_path.read_bytes()
    except OSError as exc:
        result["status"] = "Unreadable"
        result["confidence"] = "none"
        result["reason"] = f"could not read file: {exc}"
        return result

    entries = parse_dbpf_entries(raw_data)
    if not entries:
        result["status"] = "Unreadable"
        result["reason"] = "not a valid/parseable DBPF package"
        return result

    result["resource_count"] = len(entries)

    casp_count = sum(1 for entry in entries if entry["type"] == CASP_RESOURCE_TYPE)
    result["casp_count"] = casp_count

    for entry in entries:
        entry_type = entry["type"]
        if entry_type not in MERGED_MANIFEST_TYPES:
            continue

        payload = read_resource_payload(raw_data, entry)
        entry_count = try_parse_manifest_entry_count(payload) if payload is not None else None

        result["status"] = "Merged"
        result["confidence"] = "high"
        result["manifest_type"] = f"0x{entry_type:08X}"
        result["manifest_entry_count"] = entry_count

        if entry_count is None:
            result["reason"] = (
                f"found manifest resource type {result['manifest_type']} (known merged-package marker)"
            )
        else:
            result["reason"] = (
                f"found manifest resource type {result['manifest_type']} with {entry_count} entry/entries"
            )
        return result

    casp_density = (casp_count / len(entries)) if entries else 0.0
    file_name_lower = package_path.name.lower()

    if "tsrlibrary" in file_name_lower or "tsr_library" in file_name_lower:
        result["status"] = "ProbablyMerged"
        result["confidence"] = "medium"
        result["reason"] = "filename suggests TSR library/merged package"
        return result

    if casp_count > min_casparts_primary:
        result["status"] = "ProbablyMerged"
        result["confidence"] = "medium"
        result["reason"] = (
            f"very high CASPART count ({casp_count}) in one package"
        )
        return result

    if casp_count > min_casparts_secondary and casp_density > min_caspart_density:
        result["status"] = "ProbablyMerged"
        result["confidence"] = "medium"
        result["reason"] = (
            f"high CASPART count ({casp_count}) and density ({casp_density:.2f})"
        )
        return result

    return result


def list_package_files(base_path: Path) -> List[Path]:
    return [
        path for path in base_path.rglob("*") if path.is_file() and path.suffix.lower() == ".package"
    ]


def analyze_folder(
    base_path: Path,
    *,
    include_probable: bool,
    min_casparts_primary: int,
    min_casparts_secondary: int,
    min_caspart_density: float,
) -> Tuple[List[Dict[str, object]], Dict[str, int]]:
    package_files = list_package_files(base_path)
    findings: List[Dict[str, object]] = []

    stats = {
        "total": 0,
        "merged_high": 0,
        "merged_probable": 0,
        "not_merged": 0,
        "unreadable": 0,
    }

    for package_file in package_files:
        stats["total"] += 1
        finding = detect_merged_package(
            package_file,
            min_casparts_primary=min_casparts_primary,
            min_casparts_secondary=min_casparts_secondary,
            min_caspart_density=min_caspart_density,
        )

        status = finding["status"]
        if status == "Merged":
            stats["merged_high"] += 1
            findings.append(finding)
        elif status == "ProbablyMerged":
            stats["merged_probable"] += 1
            if include_probable:
                findings.append(finding)
        elif status == "Unreadable":
            stats["unreadable"] += 1
        else:
            stats["not_merged"] += 1

    return findings, stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a Sims 4 mods folder recursively and identify merged .package files. "
            "High confidence = manifest marker found; medium confidence = heuristic fallback."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to scan recursively (optional if --path is provided)",
    )
    parser.add_argument(
        "--path",
        dest="scan_path",
        default=None,
        help="Path to scan recursively",
    )
    parser.add_argument(
        "--include-probable",
        action="store_true",
        help="Include heuristic probable merged files in output",
    )
    parser.add_argument(
        "--unmerge",
        action="store_true",
        help="Unmerge high-confidence merged packages into a sibling '<path>_unmerged' folder",
    )
    parser.add_argument(
        "--move",
        dest="move_path",
        default=None,
        help="Move detected merged files to this folder (folder is created if needed)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print findings as JSON",
    )
    parser.add_argument(
        "--min-casparts-primary",
        type=int,
        default=200,
        help="Heuristic threshold: probable merged if CASPART count is above this value (default: 200)",
    )
    parser.add_argument(
        "--min-casparts-secondary",
        type=int,
        default=50,
        help="Heuristic threshold: secondary CASPART count gate (default: 50)",
    )
    parser.add_argument(
        "--min-caspart-density",
        type=float,
        default=0.5,
        help="Heuristic threshold: secondary CASPART density gate (default: 0.5)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    selected_path = args.scan_path or args.path
    if selected_path is None:
        print("No path provided. Use positional path or --path.")
        raise SystemExit(1)

    base_path = Path(selected_path).expanduser().resolve()

    if not base_path.exists() or not base_path.is_dir():
        print(f"Invalid directory: {base_path}")
        raise SystemExit(1)

    findings, stats = analyze_folder(
        base_path,
        include_probable=args.include_probable,
        min_casparts_primary=args.min_casparts_primary,
        min_casparts_secondary=args.min_casparts_secondary,
        min_caspart_density=args.min_caspart_density,
    )

    detected_merged_paths = [
        Path(str(finding["path"]))
        for finding in findings
        if finding["status"] in {"Merged", "ProbablyMerged"}
    ]

    move_target: Optional[Path] = None
    if args.move_path:
        move_target = Path(args.move_path).expanduser().resolve()

    if args.unmerge:
        merged_files = [Path(str(finding["path"])) for finding in findings if finding["status"] == "Merged"]

        if not merged_files:
            if args.json:
                print(json.dumps({"findings": findings, "stats": stats, "unmerge": {"processed": 0}}, indent=2))
                return

            print(f"Scanning path: {base_path}")
            print("No high-confidence merged files found to unmerge.")
            return

        delete_originals = prompt_delete_originals()

        unmerged_folder = base_path.parent / f"{base_path.name}_unmerged"
        unmerged_folder.mkdir(parents=True, exist_ok=True)

        processed_files: List[Path] = []
        failed_files: List[Tuple[Path, str]] = []
        total_created = 0

        for merged_file in merged_files:
            created_paths, status_text = unmerge_package_file(merged_file, unmerged_folder)
            if not created_paths:
                failed_files.append((merged_file, status_text))
                continue

            processed_files.append(merged_file)
            total_created += len(created_paths)

        trashed_failures: List[Path] = []
        if delete_originals and processed_files:
            trashed_failures = send_paths_to_trash(processed_files)

        moved_files: List[Path] = []
        move_failures: List[Tuple[Path, str]] = []
        if move_target is not None and not delete_originals:
            move_candidates = [path for path in merged_files if path.exists()]
            moved_files, move_failures = move_paths_to_folder(move_candidates, move_target)

        unmerge_report = {
            "output_folder": str(unmerged_folder),
            "merged_detected": len(merged_files),
            "processed": len(processed_files),
            "failed": len(failed_files),
            "unmerged_files_created": total_created,
            "delete_originals_requested": delete_originals,
            "trash_delete_failures": len(trashed_failures),
            "move_target": str(move_target) if move_target is not None else None,
            "moved_after_unmerge": len(moved_files),
            "move_failures": len(move_failures),
        }

        if args.json:
            payload: Dict[str, object] = {
                "findings": findings,
                "stats": stats,
                "unmerge": {
                    **unmerge_report,
                    "failed_details": [
                        {"path": str(path), "reason": reason} for path, reason in failed_files
                    ],
                    "trash_delete_failures_paths": [str(path) for path in trashed_failures],
                    "move_failures_details": [
                        {"path": str(path), "reason": reason} for path, reason in move_failures
                    ],
                },
            }
            print(json.dumps(payload, indent=2))
            return

        print(f"Scanning path: {base_path}")
        print(f"Unmerge output folder: {unmerged_folder}")
        print(f"Merged files detected: {unmerge_report['merged_detected']}")
        print(f"Merged files processed: {unmerge_report['processed']}")
        print(f"Unmerged files created: {unmerge_report['unmerged_files_created']}")
        print(f"Files failed to unmerge: {unmerge_report['failed']}")

        if failed_files:
            print("Failed files:")
            for failed_path, reason in failed_files:
                try:
                    display_path = str(failed_path.relative_to(base_path))
                except ValueError:
                    display_path = str(failed_path)
                print(f"- {display_path} | reason={reason}")

        if delete_originals:
            deleted_count = len(processed_files) - len(trashed_failures)
            print(f"Original merged files sent to trash: {deleted_count}")
            if trashed_failures:
                print("Failed to send these originals to trash:")
                for failed_path in trashed_failures:
                    try:
                        display_path = str(failed_path.relative_to(base_path))
                    except ValueError:
                        display_path = str(failed_path)
                    print(f"- {display_path}")

        if move_target is not None:
            if delete_originals:
                print("Move step skipped because originals were sent to trash.")
            else:
                print(f"Merged files moved: {len(moved_files)} -> {move_target}")
                if move_failures:
                    print("Failed to move these files:")
                    for failed_path, reason in move_failures:
                        try:
                            display_path = str(failed_path.relative_to(base_path))
                        except ValueError:
                            display_path = str(failed_path)
                        print(f"- {display_path} | reason={reason}")

        return

    moved_files: List[Path] = []
    move_failures: List[Tuple[Path, str]] = []
    if move_target is not None and detected_merged_paths:
        moved_files, move_failures = move_paths_to_folder(detected_merged_paths, move_target)

    if args.json:
        payload: Dict[str, object] = {"findings": findings, "stats": stats}
        if move_target is not None:
            payload["move"] = {
                "target": str(move_target),
                "moved": len(moved_files),
                "failed": len(move_failures),
                "failed_details": [
                    {"path": str(path), "reason": reason} for path, reason in move_failures
                ],
            }
        print(json.dumps(payload, indent=2))
        return

    print(f"Scanning path: {base_path}")
    print(f"Scanned .package files: {stats['total']}")
    print(f"High-confidence merged: {stats['merged_high']}")
    print(f"Probable merged: {stats['merged_probable']}")
    print(f"Unreadable/invalid package files: {stats['unreadable']}")

    if not findings:
        if args.include_probable:
            print("No merged or probable merged files found.")
        else:
            print("No high-confidence merged files found.")
            print("Tip: rerun with --include-probable to show heuristic matches.")
        return

    if move_target is not None:
        print(f"Merged files moved: {len(moved_files)} -> {move_target}")
        if move_failures:
            print("Failed to move these files:")
            for failed_path, reason in move_failures:
                try:
                    display_path = str(failed_path.relative_to(base_path))
                except ValueError:
                    display_path = str(failed_path)
                print(f"- {display_path} | reason={reason}")

    print("\nDetected merged packages:")
    for finding in findings:
        file_path = Path(str(finding["path"]))
        try:
            display_path = str(file_path.relative_to(base_path))
        except ValueError:
            display_path = str(file_path)

        print(
            f"- {display_path} | status={finding['status']} | confidence={finding['confidence']} | "
            f"reason={finding['reason']}"
        )


if __name__ == "__main__":
    main()

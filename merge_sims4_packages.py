import argparse
import ctypes
import os
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


MERGED_MANIFEST_TYPE = 0x7FB6AD8A
MAX_FILES_PER_MERGE = 300
MAX_BYTES_PER_MERGE = 900 * 1024 * 1024  # 900 MB


# ---------------------------------------------------------------------------
# DBPF reading helpers
# ---------------------------------------------------------------------------


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


def read_resource_blob(data: bytes, entry: Dict[str, int]) -> Optional[bytes]:
    offset = entry["offset"]
    compressed_size = entry["compressed_size"]
    if compressed_size <= 0 or offset < 0 or offset + compressed_size > len(data):
        return None
    return data[offset : offset + compressed_size]


# ---------------------------------------------------------------------------
# DBPF building helpers
# ---------------------------------------------------------------------------


def build_manifest_blob(file_entries: List[Dict]) -> bytes:
    """Build a manifest resource blob (u32 name length format).

    Layout:
        u32 version (1)
        u32 flags   (0)
        u32 reserved(0)
        u32 entry_count
        Per entry:
            u32 name_length
            bytes name (utf-8)
            u32 resource_count
            Per resource: u32 instance_lo, u32 instance_hi, u32 type, u32 group
    """
    parts: List[bytes] = []
    # Header: version=1, flags=0, reserved=0, entry_count
    parts.append(struct.pack("<IIII", 1, 0, 0, len(file_entries)))

    for entry in file_entries:
        name_bytes = entry["name"].encode("utf-8")
        parts.append(struct.pack("<I", len(name_bytes)))
        parts.append(name_bytes)

        tgis: List[Tuple[int, int, int, int]] = entry["tgis"]
        parts.append(struct.pack("<I", len(tgis)))
        for res_type, group, instance_hi, instance_lo in tgis:
            parts.append(struct.pack("<IIII", instance_lo, instance_hi, res_type, group))

    return b"".join(parts)


def build_dbpf_package(resources: List[Dict]) -> bytes:
    header_size = 96
    index_flags = 0
    index_size = 4 + (len(resources) * 32)
    data_start = header_size
    index_offset = data_start + sum(len(resource["blob"]) for resource in resources)

    output = bytearray(index_offset + index_size)
    output[0:4] = b"DBPF"

    struct.pack_into("<I", output, 4, 2)   # major version
    struct.pack_into("<I", output, 8, 1)   # minor version
    struct.pack_into("<I", output, 32, 0)  # unused
    struct.pack_into("<I", output, 36, len(resources))  # index entry count
    struct.pack_into("<I", output, 40, 0)  # short index offset (0 = use long)
    struct.pack_into("<I", output, 44, index_size)
    struct.pack_into("<I", output, 60, 3)  # index version
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


# ---------------------------------------------------------------------------
# Package loading
# ---------------------------------------------------------------------------


def load_package_resources(
    file_path: Path,
) -> Optional[Dict]:
    """Read a .package file and return its filename, resources, and total blob size."""
    try:
        raw_data = file_path.read_bytes()
    except OSError as exc:
        print(f"  WARNING: Could not read {file_path.name}: {exc}")
        return None

    entries = parse_dbpf_entries(raw_data)
    if not entries:
        print(f"  WARNING: Invalid DBPF in {file_path.name}, skipping")
        return None

    resources: List[Dict] = []
    total_blob_size = 0

    for entry in entries:
        blob = read_resource_blob(raw_data, entry)
        if blob is None:
            continue
        resources.append(
            {
                "type": entry["type"],
                "group": entry["group"],
                "instance_hi": entry["instance_hi"],
                "instance_lo": entry["instance_lo"],
                "blob": blob,
                "compression_type": entry["compression_type"],
                "compression_flags": entry["compression_flags"],
                "uncompressed_size": entry["uncompressed_size"],
            }
        )
        total_blob_size += len(blob)

    if not resources:
        print(f"  WARNING: No resources found in {file_path.name}, skipping")
        return None

    return {
        "name": file_path.name,
        "resources": resources,
        "total_blob_size": total_blob_size,
    }


# ---------------------------------------------------------------------------
# Batching
# ---------------------------------------------------------------------------


def create_batches(
    loaded_packages: List[Dict],
) -> List[List[Dict]]:
    """Split loaded packages into batches respecting file count and size limits."""
    batches: List[List[Dict]] = []
    current_batch: List[Dict] = []
    current_size = 0

    for pkg in loaded_packages:
        pkg_size = pkg["total_blob_size"]
        if current_batch and (
            len(current_batch) >= MAX_FILES_PER_MERGE
            or current_size + pkg_size > MAX_BYTES_PER_MERGE
        ):
            batches.append(current_batch)
            current_batch = []
            current_size = 0
        current_batch.append(pkg)
        current_size += pkg_size

    if current_batch:
        batches.append(current_batch)

    return batches


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------


def merge_batch(batch: List[Dict]) -> bytes:
    """Merge a batch of loaded packages into a single DBPF with manifest."""
    all_resources: List[Dict] = []
    manifest_entries: List[Dict] = []

    for pkg in batch:
        tgis: List[Tuple[int, int, int, int]] = []
        for res in pkg["resources"]:
            tgis.append((res["type"], res["group"], res["instance_hi"], res["instance_lo"]))
            all_resources.append(res)
        manifest_entries.append({"name": pkg["name"], "tgis": tgis})

    # Build manifest resource and prepend it
    manifest_blob = build_manifest_blob(manifest_entries)
    manifest_resource = {
        "type": MERGED_MANIFEST_TYPE,
        "group": 0,
        "instance_hi": 0,
        "instance_lo": 0,
        "blob": manifest_blob,
        "compression_type": 0x0000,
        "compression_flags": 0x0000,
        "uncompressed_size": len(manifest_blob),
    }
    all_resources.insert(0, manifest_resource)

    return build_dbpf_package(all_resources)


def process_folder(
    folder_path: Path, dry_run: bool = False
) -> Tuple[Dict[str, int], List[Path]]:
    """Process a single folder: load packages, batch, merge, write output.

    Returns a tuple of (stats dict, list of original source file paths that were merged).
    """
    stats = {"files_found": 0, "files_merged": 0, "files_skipped": 0, "merges_written": 0}
    merged_source_files: List[Path] = []

    package_files = sorted(folder_path.glob("*.package"))
    if not package_files:
        return stats, merged_source_files

    stats["files_found"] = len(package_files)
    folder_name = folder_path.name

    print(f"\n  Folder: {folder_name}")
    print(f"    Found {len(package_files)} .package file(s)")

    # Load all packages, remembering their source paths
    loaded_packages: List[Dict] = []
    for pkg_file in package_files:
        pkg_data = load_package_resources(pkg_file)
        if pkg_data is None:
            stats["files_skipped"] += 1
            continue
        pkg_data["source_path"] = pkg_file
        loaded_packages.append(pkg_data)

    if not loaded_packages:
        print("    No valid packages to merge")
        return stats, merged_source_files

    # Create batches
    batches = create_batches(loaded_packages)
    use_numbering = len(batches) > 1

    print(f"    Merging into {len(batches)} file(s)")

    for batch_index, batch in enumerate(batches):
        file_count = len(batch)
        total_blob_size = sum(pkg["total_blob_size"] for pkg in batch)

        if use_numbering:
            merged_name = f"{folder_name}_Merged_{batch_index + 1:02d}.package"
        else:
            merged_name = f"{folder_name}_Merged.package"

        merged_path = folder_path / merged_name

        size_mb = total_blob_size / (1024 * 1024)
        print(f"    -> {merged_name} ({file_count} files, {size_mb:.1f} MB)")

        if dry_run:
            stats["files_merged"] += file_count
            stats["merges_written"] += 1
            continue

        merged_data = merge_batch(batch)
        try:
            merged_path.write_bytes(merged_data)
        except OSError as exc:
            print(f"    ERROR: Failed to write {merged_name}: {exc}")
            continue

        stats["files_merged"] += file_count
        stats["merges_written"] += 1
        for pkg in batch:
            merged_source_files.append(pkg["source_path"])

    return stats, merged_source_files


# ---------------------------------------------------------------------------
# Trash helpers
# ---------------------------------------------------------------------------


def _send_path_to_trash_windows(path: Path) -> bool:
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
            if not _send_path_to_trash_windows(path):
                failed.append(path)
        return failed

    failed.extend(paths)
    return failed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge .package files in subfolders into combined DBPF packages."
    )
    parser.add_argument("path", type=str, help="Root path containing subfolders with .package files")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be merged without writing any files",
    )
    args = parser.parse_args()

    root_path = Path(args.path)
    if not root_path.is_dir():
        print(f"Error: '{args.path}' is not a valid directory")
        sys.exit(1)

    subfolders = sorted(p for p in root_path.iterdir() if p.is_dir())
    if not subfolders:
        print(f"No subfolders found in '{args.path}'")
        sys.exit(0)

    print(f"Scanning {len(subfolders)} subfolder(s) in: {root_path}")
    if args.dry_run:
        print("(DRY RUN - no files will be written)")

    total_stats = {
        "folders_processed": 0,
        "files_found": 0,
        "files_merged": 0,
        "files_skipped": 0,
        "merges_written": 0,
    }
    all_merged_source_files: List[Path] = []

    for folder in subfolders:
        folder_stats, source_files = process_folder(folder, dry_run=args.dry_run)
        if folder_stats["files_found"] > 0:
            total_stats["folders_processed"] += 1
            for key in ("files_found", "files_merged", "files_skipped", "merges_written"):
                total_stats[key] += folder_stats[key]
            all_merged_source_files.extend(source_files)

    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  Folders processed : {total_stats['folders_processed']}")
    print(f"  Files found       : {total_stats['files_found']}")
    print(f"  Files merged      : {total_stats['files_merged']}")
    print(f"  Files skipped     : {total_stats['files_skipped']}")
    print(f"  Merged files out  : {total_stats['merges_written']}")

    # Offer to send original source files to trash
    if all_merged_source_files and not args.dry_run:
        answer = input(
            "\nDelete original unmerged files (send to trash)? [y/N]: "
        ).strip().lower()
        if answer == "y":
            failed = send_paths_to_trash(all_merged_source_files)
            deleted = len(all_merged_source_files) - len(failed)
            for f in failed:
                print(f"  WARNING: Could not trash {f.name}")
            print(f"  Sent {deleted} original file(s) to trash" + (f", {len(failed)} failed" if failed else ""))
        else:
            print("  Original files kept.")


if __name__ == "__main__":
    main()

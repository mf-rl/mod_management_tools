import argparse
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}


def normalize_for_matching(text: str) -> str:
    return "".join(character.lower() for character in text if character.isalnum())


def extract_display_prefix(original_stem: str, normalized_prefix: str) -> str:
    if not normalized_prefix:
        return ""

    collected_raw: List[str] = []
    collected_norm: List[str] = []

    for character in original_stem:
        if not character.isalnum():
            continue

        collected_raw.append(character)
        collected_norm.append(character.lower())

        if "".join(collected_norm) == normalized_prefix:
            break

    return "".join(collected_raw)


def sanitize_folder_name(name: str) -> str:
    cleaned = re.sub(r"[<>:\"/\\|?*]", "_", name).strip()
    cleaned = cleaned.rstrip(". ")

    if not cleaned:
        cleaned = "Unknown"

    if cleaned.upper() in WINDOWS_RESERVED_NAMES:
        cleaned = f"_{cleaned}"

    return cleaned


def build_unique_destination(folder: Path, original_name: str) -> Path:
    destination = folder / original_name
    if not destination.exists():
        return destination

    stem = Path(original_name).stem
    suffix = Path(original_name).suffix
    counter = 1

    while True:
        candidate = folder / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def list_files(base_path: Path) -> List[Path]:
    return [path for path in base_path.rglob("*") if path.is_file()]


def build_prefix_counters(
    file_data: Sequence[Tuple[Path, str, str]],
    min_prefix_length: int,
    max_prefix_length: int,
) -> Tuple[Counter[str], Dict[str, Counter[str]]]:
    prefix_counts: Counter[str] = Counter()
    prefix_display_counts: Dict[str, Counter[str]] = defaultdict(Counter)

    for _, stem, normalized in file_data:
        if len(normalized) < min_prefix_length:
            continue

        limit = min(len(normalized), max_prefix_length)
        for length in range(min_prefix_length, limit + 1):
            prefix = normalized[:length]
            prefix_counts[prefix] += 1

            display = extract_display_prefix(stem, prefix)
            if display:
                prefix_display_counts[prefix][display] += 1

    return prefix_counts, prefix_display_counts


def choose_group_prefix(
    normalized_name: str,
    prefix_counts: Counter[str],
    min_prefix_length: int,
    max_prefix_length: int,
    min_group_size: int,
) -> Optional[str]:
    if len(normalized_name) < min_prefix_length:
        return None

    best_prefix: Optional[str] = None
    best_score: Optional[int] = None

    limit = min(len(normalized_name), max_prefix_length)
    for length in range(min_prefix_length, limit + 1):
        prefix = normalized_name[:length]
        group_size = prefix_counts.get(prefix, 0)
        if group_size < min_group_size:
            continue

        score = (group_size * 1000) + length
        if best_score is None or score > best_score:
            best_score = score
            best_prefix = prefix

    return best_prefix


def folder_name_for_prefix(
    prefix: str,
    prefix_display_counts: Dict[str, Counter[str]],
) -> str:
    display_counter = prefix_display_counts.get(prefix)
    if display_counter:
        display, _ = display_counter.most_common(1)[0]
        return sanitize_folder_name(display)

    return sanitize_folder_name(prefix)


def organize_files(
    base_path: Path,
    min_group_size: int,
    min_prefix_length: int,
    max_prefix_length: int,
) -> Tuple[List[Tuple[Path, Path]], List[Tuple[Path, str]], Dict[str, int]]:
    files = list_files(base_path)
    file_data = [(file_path, file_path.stem, normalize_for_matching(file_path.stem)) for file_path in files]

    prefix_counts, prefix_display_counts = build_prefix_counters(
        file_data=file_data,
        min_prefix_length=min_prefix_length,
        max_prefix_length=max_prefix_length,
    )

    moved: List[Tuple[Path, Path]] = []
    failed: List[Tuple[Path, str]] = []
    grouped_counts: Dict[str, int] = defaultdict(int)

    for file_path, _, normalized in file_data:
        prefix = choose_group_prefix(
            normalized_name=normalized,
            prefix_counts=prefix_counts,
            min_prefix_length=min_prefix_length,
            max_prefix_length=max_prefix_length,
            min_group_size=min_group_size,
        )

        group_name = folder_name_for_prefix(prefix, prefix_display_counts) if prefix else "Unknown"
        group_folder = base_path / group_name
        group_folder.mkdir(exist_ok=True)

        destination = build_unique_destination(group_folder, file_path.name)

        if destination == file_path:
            grouped_counts[group_name] += 1
            continue

        try:
            shutil.move(str(file_path), str(destination))
            moved.append((file_path, destination))
            grouped_counts[group_name] += 1
        except OSError as error:
            failed.append((file_path, str(error)))

    sorted_counts = dict(sorted(grouped_counts.items(), key=lambda item: item[0].lower()))
    return moved, failed, sorted_counts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a folder recursively, find common filename prefix patterns, "
            "and move files into subfolders grouped by those shared patterns."
        )
    )
    parser.add_argument("path", help="Folder path to organize")
    parser.add_argument(
        "--min-group-size",
        type=int,
        default=2,
        help="Minimum number of files that must share a prefix to create a group (default: 2)",
    )
    parser.add_argument(
        "--min-prefix-length",
        type=int,
        default=4,
        help="Minimum normalized prefix length to consider (default: 4)",
    )
    parser.add_argument(
        "--max-prefix-length",
        type=int,
        default=24,
        help="Maximum normalized prefix length to consider (default: 24)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    base_path = Path(args.path).expanduser().resolve()

    if not base_path.exists() or not base_path.is_dir():
        print(f"Invalid directory: {base_path}")
        raise SystemExit(1)

    if args.min_group_size < 2:
        print("--min-group-size must be at least 2")
        raise SystemExit(1)

    if args.min_prefix_length < 1:
        print("--min-prefix-length must be at least 1")
        raise SystemExit(1)

    if args.max_prefix_length < args.min_prefix_length:
        print("--max-prefix-length must be greater than or equal to --min-prefix-length")
        raise SystemExit(1)

    moved, failed, grouped_counts = organize_files(
        base_path=base_path,
        min_group_size=args.min_group_size,
        min_prefix_length=args.min_prefix_length,
        max_prefix_length=args.max_prefix_length,
    )

    if moved:
        print("Moved files:")
        for source, destination in moved:
            print(f"- {source} -> {destination}")
    else:
        print("No files were moved.")

    print("\nFiles per grouped folder:")
    for folder_name, count in grouped_counts.items():
        print(f"- {folder_name}: {count}")

    print(f"\nTotal files moved: {len(moved)}")

    if failed:
        print("\nFiles that could not be moved:")
        for file_path, reason in failed:
            print(f"- {file_path}: {reason}")


if __name__ == "__main__":
    main()

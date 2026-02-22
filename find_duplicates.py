import argparse
import hashlib
import shutil
from pathlib import Path
from typing import Dict, List, Tuple


CHUNK_SIZE = 1024 * 1024  # 1MB


def file_hash(path: Path) -> str:
    sha256 = hashlib.sha256()
    with path.open("rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def build_unique_destination(duplicated_dir: Path, original_name: str) -> Path:
    candidate = duplicated_dir / original_name
    if not candidate.exists():
        return candidate

    stem = Path(original_name).stem
    suffix = Path(original_name).suffix
    counter = 1
    while True:
        candidate = duplicated_dir / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def find_files(base_path: Path, duplicated_dir: Path) -> List[Path]:
    files: List[Path] = []
    for path in base_path.rglob("*"):
        if not path.is_file():
            continue
        try:
            path.relative_to(duplicated_dir)
            continue
        except ValueError:
            pass
        files.append(path)
    return files


def move_duplicates(base_path: Path) -> List[Tuple[Path, Path, Path]]:
    duplicated_dir = base_path / "Duplicated"
    duplicated_dir.mkdir(exist_ok=True)

    files = find_files(base_path, duplicated_dir)

    # Group by file size first to reduce hashing work.
    size_groups: Dict[int, List[Path]] = {}
    for file_path in files:
        size = file_path.stat().st_size
        size_groups.setdefault(size, []).append(file_path)

    moved_duplicates: List[Tuple[Path, Path, Path]] = []

    for _, group in size_groups.items():
        if len(group) < 2:
            continue

        # Within same size group, hash content to verify duplicates.
        hash_groups: Dict[str, List[Path]] = {}
        for file_path in group:
            try:
                digest = file_hash(file_path)
            except (OSError, PermissionError):
                continue
            hash_groups.setdefault(digest, []).append(file_path)

        for _, same_content_files in hash_groups.items():
            if len(same_content_files) < 2:
                continue

            # Keep first file, move all others as duplicates.
            original = same_content_files[0]
            for duplicate in same_content_files[1:]:
                destination = build_unique_destination(duplicated_dir, duplicate.name)
                try:
                    shutil.move(str(duplicate), str(destination))
                    moved_duplicates.append((duplicate, destination, original))
                except (OSError, PermissionError):
                    continue

    return moved_duplicates


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Find duplicated files by content and move duplicates to a 'Duplicated' folder."
    )
    parser.add_argument("path", help="Path to scan")
    args = parser.parse_args()

    base_path = Path(args.path).expanduser().resolve()

    if not base_path.exists() or not base_path.is_dir():
        print(f"Invalid directory: {base_path}")
        raise SystemExit(1)

    moved_duplicates = move_duplicates(base_path)

    if not moved_duplicates:
        print("No duplicated files were found.")
        return

    print("Duplicated files found and moved:")
    for original_path, moved_path, kept_original in moved_duplicates:
        print(f"- {original_path} -> {moved_path} (duplicate of: {kept_original})")

    print(f"\nTotal duplicates moved: {len(moved_duplicates)}")


if __name__ == "__main__":
    main()

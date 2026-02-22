import argparse
import unicodedata
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from unidecode import unidecode
except ImportError:  # pragma: no cover
    unidecode = None


def transliterate_character(character: str) -> str:
    if character.isascii():
        return character

    replacement = ""
    if unidecode is not None:
        replacement = unidecode(character)

    if not replacement:
        replacement = (
            unicodedata.normalize("NFKD", character)
            .encode("ascii", "ignore")
            .decode("ascii")
        )

    replacement = "".join(ch for ch in replacement if ch.isascii())
    if replacement:
        return replacement

    return str(ord(character))


def normalize_filename(name: str) -> Tuple[str, bool]:
    changed = False
    normalized_parts: List[str] = []

    for character in name:
        if character.isascii():
            normalized_parts.append(character)
            continue

        normalized_parts.append(transliterate_character(character))
        changed = True

    normalized_name = "".join(normalized_parts)
    if not normalized_name:
        normalized_name = "file"

    return normalized_name, changed


def build_unique_target(original_path: Path, candidate_name: str) -> Path:
    candidate = original_path.with_name(candidate_name)
    if candidate == original_path:
        return original_path

    if not candidate.exists():
        return candidate

    stem = Path(candidate_name).stem
    suffix = Path(candidate_name).suffix
    counter = 1

    while True:
        numbered_candidate = original_path.with_name(f"{stem}_{counter}{suffix}")
        if numbered_candidate == original_path:
            counter += 1
            continue
        if not numbered_candidate.exists():
            return numbered_candidate
        counter += 1


def rename_non_latin_files(base_path: Path) -> Tuple[List[Tuple[Path, Path]], List[Tuple[Path, str]]]:
    files = [path for path in base_path.rglob("*") if path.is_file()]

    renamed_files: List[Tuple[Path, Path]] = []
    failed_files: List[Tuple[Path, str]] = []

    for file_path in files:
        normalized_name, changed = normalize_filename(file_path.name)
        if not changed:
            continue

        target_path = build_unique_target(file_path, normalized_name)
        try:
            file_path.rename(target_path)
            renamed_files.append((file_path, target_path))
        except OSError as error:
            failed_files.append((file_path, str(error)))

    return renamed_files, failed_files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a folder recursively and rename files that contain non-ASCII characters "
            "to Latin equivalents (or character code numbers when no equivalent exists)."
        )
    )
    parser.add_argument("path", help="Path to scan")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    base_path = Path(args.path).expanduser().resolve()

    if not base_path.exists() or not base_path.is_dir():
        print(f"Invalid directory: {base_path}")
        raise SystemExit(1)

    renamed_files, failed_files = rename_non_latin_files(base_path)

    if renamed_files:
        print("Renamed files:")
        for old_path, new_path in renamed_files:
            print(f"- {old_path.name} -> {new_path.name} : {new_path.parent}")
    else:
        print("No files with non-Latin characters were found.")

    print(f"\nTotal files renamed: {len(renamed_files)}")

    if failed_files:
        print("\nFiles that could not be renamed:")
        for file_path, reason in failed_files:
            print(f"- {file_path}: {reason}")


if __name__ == "__main__":
    main()

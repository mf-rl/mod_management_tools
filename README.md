# Sims 4 Mod File Helper Scripts

A small set of Python utilities I use to organize my mod files. These scripts operate directly on your folders, so make a backup before running them.

## Requirements

- Python 3.9+ (any recent 3.x should work)
- Optional: `unidecode` for better transliteration in `rename_non_latin_files.py`

Install optional dependency:

```bash
python -m pip install unidecode
```

## Scripts

### `organize_sims4_packages.py`

Scans a mods folder recursively, detects whether `.package` files are CAS or Build/Buy content, and moves them into folders:

- CAS files: moved into a body-type folder like `Hair`, `Top`, `Shoes`, etc.
- Build/Buy files: moved into `BuildItem`
- Unknown metadata: moved into `PossiblyMerged`

How it works:

- Reads the DBPF index inside `.package` files.
- Detects CAS vs Build/Buy by resource types and markers.
- Attempts to detect CAS body type from CASP data, flag tables, or filename text.

Usage:

```bash
python organize_sims4_packages.py "C:\Path\To\Mods"
```

Dry run (no file moves):

```bash
python organize_sims4_packages.py "C:\Path\To\Mods" --dry-run
```

### `identify_merged_sims4_packages.py`

Scans a mods folder recursively and identifies merged `.package` files.

How it works:

- High confidence: detects package-manifest resource types commonly used by merge tools (`0x7FB6AD8A` and legacy `0x73E93EEB`).
- Medium confidence (optional): heuristic fallback for probable merged files using very high CASPART count/density patterns.

Usage (high-confidence only):

```bash
python identify_merged_sims4_packages.py --path "C:\Path\To\Mods"
```

Include probable heuristic matches:

```bash
python identify_merged_sims4_packages.py "C:\Path\To\Mods" --include-probable
```

Unmerge detected merged files:

```bash
python identify_merged_sims4_packages.py --path "C:\Path\To\Mods" --unmerge
```

When `--unmerge` is used:

- Script asks if original merged files should be kept or sent to trash.
- It writes extracted packages into a sibling folder named `<path>_unmerged`.
- Example: `C:\Tmp\Items` -> `C:\Tmp\Items_unmerged`
- For special merged files that only contain a manifest marker (no explicit manifest entry map),
  the script uses a fallback split-by-CASP-instance process and writes an additional `*_shared.package`
  with leftover shared resources.

JSON output:

```bash
python identify_merged_sims4_packages.py "C:\Path\To\Mods" --include-probable --json
```

### `find_duplicates.py`

Finds duplicate files by content and moves duplicates into a `Duplicated` folder (keeps the first copy found).

How it works:

- Groups by file size to reduce hashing.
- Hashes file contents with SHA-256 to confirm duplicates.
- Moves duplicates into `Duplicated`, with unique filenames when needed.

Usage:

```bash
python find_duplicates.py "C:\Path\To\Mods"
```

### `organize_files_by_author.py`

Groups files by common filename prefixes and moves them into subfolders (useful when creators prefix their files with a consistent tag).

How it works:

- Normalizes filenames (alphanumeric only, lowercased) for matching.
- Builds prefix frequency counts across files.
- Creates folders for prefixes that meet a minimum group size.
- Moves files into the most suitable prefix folder, or `Unknown` if no strong match.

Usage:

```bash
python organize_files_by_author.py "C:\Path\To\Mods"
```

Optional tuning:

```bash
python organize_files_by_author.py "C:\Path\To\Mods" --min-group-size 3 --min-prefix-length 5 --max-prefix-length 30
```

### `rename_non_latin_files.py`

Renames files containing non-ASCII characters to ASCII equivalents.

How it works:

- Uses `unidecode` when available for transliteration.
- Falls back to Unicode normalization.
- Uses numeric code points when no transliteration is possible.
- Ensures unique filenames to avoid collisions.

Usage:

```bash
python rename_non_latin_files.py "C:\Path\To\Mods"
```

## Notes and Safety

- These scripts move or rename files in place. Make a backup of your mods folder before running them.
- All scripts recurse into subfolders.
- If a move or rename fails (permissions, locked files), the script reports it and continues.

## Suggested Workflow

1. `rename_non_latin_files.py` (avoid filename issues)
2. `find_duplicates.py` (clean duplicates)
3. `organize_sims4_packages.py` (sort by CAS/Build/Buy)
4. `organize_files_by_author.py` (optional, for creator prefixes)

# Sims 4 Mod File Helper Scripts

A set of Python utilities for organizing Sims 4 `.package` mod files. These scripts operate directly on your folders — **make a backup before running them**.

## Requirements

- Python 3.9+
- Optional: `unidecode` for better transliteration in `rename_non_latin_files.py`

```bash
python -m pip install unidecode
```

---

## Scripts

### `organize_sims4_packages.py`

Scans a mods folder recursively, classifies `.package` files by content, and sorts them into categorized folders.

#### Classification & Output Folders

| Category | Output Folder | How Detected |
|---|---|---|
| Merged | `Merged/` | Contains a merge-tool manifest resource (`0x7FB6AD8A` or `0x73E93EEB`) |
| CAS | `<BodyType>/` or `UnknownBodyType/` | Contains CAS resource types (CASP, GEOM, RMAP, SkinTone, StyledLook) |
| Build/Buy | `BuildItem/` | Contains Build/Buy resource types (COBJ, OBJD, catalogs, walls, floors, etc.) |
| Tuning | `Tuning/` | Contains tuning resource types or tuning text markers |
| Preset | `Presets/` | Contains `CASPresetResource` (`0xEAA32ADD`) |
| Animation | `Animations/` | Contains `ClipResource` (`0x6B20C4F3`) or `Jazz Script` (`0xBC4A5044`) |
| Override | `Overrides/` | Filename contains "override" or "replacement" |
| Unknown | `Other/` | Fallback for unclassified files |

#### CAS Body Type Detection (4-layer cascade)

1. **Adaptive CASP parser** — Reads CASP version, then tries version-specific field layouts to extract the body type ID. Supports all known CASP versions (v27–v50+) via 6 empirically verified layouts.
2. **Flag table scan** — Scans for a valid CAS flag category table and reads body type from a fixed offset after the table.
3. **ID frequency scan** — Counts known body type integers across the entire resource as a last-resort heuristic.
4. **Filename fallback** — Matches over 90 filename tokens (e.g., "top", "hair", "shoes", "dress", "choker") to canonical body type names via `BODY_TYPE_ALIASES`.

Between layers 3 and 4, explicit text marker scans also run (`body type:` patterns in raw data).

#### Body Types (59 total, IDs 0x00–0x3A)

Hat, Hair, Head, Face, FullBody, Top, Bottom, Shoes, Accessories, Earrings, Glasses, Necklace, Gloves, Bracelets, Lip/Nose/Brow Rings, Finger Rings, FacialHair, Lipstick, Eyeshadow, Eyeliner, Blush, Facepaint, Eyebrows, Eyecolor, Socks, Eyelashes, ForeheadCrease, Freckles, Dimples, Tights, Moles, Tattoos (8 zones), MouthCrease, SkinOverlay.

#### Filename Aliases (90+ mappings)

Common variants are mapped to canonical names: `choker`→Necklace, `suit`/`dress`/`jumpsuit`/`romper`→FullBody, `lipliner`→Lipstick, `freckle`→Freckles, `cheek`→Blush, `facemask`/`nosemask`→FacePaint, `eyelid`→Eyeshadow, `beard`/`mustache`→FacialHair, `boot`/`slipper`→Shoes, `hoodie`/`sweater`/`jacket`→Top, and many more.

#### Usage

```bash
python organize_sims4_packages.py "C:\Path\To\Mods"
python organize_sims4_packages.py "C:\Path\To\Mods" --dry-run
```

Output goes to `<input_path>_Organized/`.

---

### `identify_merged_sims4_packages.py`

Scans a mods folder recursively to identify and optionally unmerge merged `.package` files.

#### Detection Methods

- **High confidence** — Detects merge-tool manifest resource types (`0x7FB6AD8A`, `0x73E93EEB`). Parses manifest entry count via multiple layout strategies.
- **Heuristic (optional)** — TSR filename patterns, high CASP count (>200), or secondary CASP count + density thresholds.

#### Unmerge Capability

Reconstructs individual `.package` files from a merged DBPF:

- Reads manifest entries (filenames + TGI resource lists).
- Maps resources by TGI key with swapped-instance fallback.
- Builds valid DBPF files for each extracted package.
- For empty-manifest merges: splits by CASP instance ID + writes a shared resources package.
- Interactive prompt to keep or trash original merged files.

#### Usage

```bash
# Scan only
python identify_merged_sims4_packages.py --path "C:\Path\To\Mods"

# Include heuristic matches
python identify_merged_sims4_packages.py "C:\Path\To\Mods" --include-probable

# Move merged files
python identify_merged_sims4_packages.py --path "C:\Path\To\Mods" --move "C:\Path\To\MergedArchive"

# Unmerge into individual packages
python identify_merged_sims4_packages.py --path "C:\Path\To\Mods" --unmerge

# JSON output
python identify_merged_sims4_packages.py "C:\Path\To\Mods" --json
```

---

### `merge_sims4_packages.py`

Merges individual `.package` files within subfolders into combined DBPF packages with a manifest.

#### Merge Rules

- **Max 300 files** per merged package.
- **Max 900 MB** per merged package.
- If both limits are satisfied in a single batch → one merged file.
- If limits are exceeded → multiple numbered merged files.

#### Output Naming

| Scenario | Output |
|---|---|
| Single batch | `FolderName_Merged.package` |
| Multiple batches | `FolderName_Merged_01.package`, `FolderName_Merged_02.package`, … |

#### How It Works

- Scans all immediate subfolders in the given path.
- Reads each `.package` file, extracts all DBPF resources (preserving original compression).
- Batches files by count and total size.
- Builds a merged DBPF with a manifest resource (`0x7FB6AD8A`) mapping each original filename to its resource TGIs.
- After merging, prompts to send original files to the recycle bin.

#### Usage

```bash
# Preview what would be merged
python merge_sims4_packages.py "C:\Path\To\Mods" --dry-run

# Merge packages
python merge_sims4_packages.py "C:\Path\To\Mods"
```

---

### `find_duplicates.py`

Finds duplicate files by content (SHA-256) and moves duplicates into a `Duplicated` folder.

- Groups files by size first to minimize hashing work.
- Keeps the first copy found, moves subsequent duplicates.
- Collision-safe filenames (`_1`, `_2`, etc.).

```bash
python find_duplicates.py "C:\Path\To\Mods"
```

---

### `organize_files_by_author.py`

Groups files by shared filename prefixes into subfolders. Useful when mod creators use consistent naming prefixes.

- Normalizes filenames (alphanumeric, lowercased) for matching.
- Scores prefixes by `(group_size × 1000) + length`.
- Windows-safe folder names (strips reserved characters and names).
- Unmatched files go to `Unknown/`.

```bash
python organize_files_by_author.py "C:\Path\To\Mods"
python organize_files_by_author.py "C:\Path\To\Mods" --min-group-size 3 --min-prefix-length 5 --max-prefix-length 30
```

---

### `rename_non_latin_files.py`

Renames files containing non-ASCII characters to ASCII equivalents.

- 3-tier transliteration: `unidecode` → Unicode NFKD decomposition → `ord()` code points.
- Collision-safe renaming.
- Works without `unidecode` installed (graceful fallback).

```bash
python rename_non_latin_files.py "C:\Path\To\Mods"
```

---

## Notes and Safety

- These scripts move or rename files. **Back up your mods folder first.**
- All scripts recurse into subfolders.
- Failed moves/renames are reported and skipped.

## Suggested Workflow

1. `rename_non_latin_files.py` — fix filename encoding issues
2. `find_duplicates.py` — remove duplicate content
3. `identify_merged_sims4_packages.py --unmerge` — split merged packages
4. `organize_sims4_packages.py` — sort by content type and body type
5. `organize_files_by_author.py` — (optional) group by creator prefix
6. `merge_sims4_packages.py` — (optional) re-merge organized folders for faster game loading

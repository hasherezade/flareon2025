#!/usr/bin/env python3
"""
Rename DLLs to their exported module name.

- Walks a directory (recursively) and checks each file.
- If it's a PE and a DLL, reads the module name from the export directory.
- Renames the file to <ExportName>.dll.
- If a file with the target name exists, appends _1, _2, ... to avoid clobbering.
"""

import argparse
import os
import re
import sys
from pathlib import Path

import pefile
from pefile import PEFormatError

IMAGE_FILE_DLL = 0x2000

INVALID_CHARS = r'<>:"/\\|?*'
INVALID_PATTERN = re.compile(r'[<>:"/\\|?*\x00-\x1F]')

def sanitize_filename(name: str) -> str:
    """Remove/replace characters that are invalid on Windows and normalize spaces."""
    # Replace invalid characters with underscores
    name = INVALID_PATTERN.sub('_', name)
    # Strip trailing spaces/dots (invalid as final chars on Windows)
    return name.strip().rstrip('.')

def is_pe(path: Path) -> bool:
    try:
        _ = pefile.PE(str(path), fast_load=True)
        return True
    except PEFormatError:
        return False
    except Exception:
        return False

def get_dll_export_name(path: Path) -> str | None:
    """
    If `path` is a PE DLL, return its export 'Name' from the export directory.
    Otherwise return None.
    """
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except PEFormatError:
        return None
    except Exception:
        return None

    try:
        # Check DLL characteristic
        if (pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL) == 0:
            return None

        # Load export directory
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
        )

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') or pe.DIRECTORY_ENTRY_EXPORT is None:
            return None

        raw_name = pe.DIRECTORY_ENTRY_EXPORT.name
        if not raw_name:
            return None

        # raw_name is bytes; decode safely
        name = raw_name.decode('utf-8', errors='replace')
        name = sanitize_filename(name)

        # Avoid empty result
        if not name:
            return None

        # Ensure it ends with .dll (case-insensitively)
        if not name.lower().endswith('.dll'):
            name = name + '.dll'

        return name
    except Exception:
        return None
    finally:
        try:
            pe.close()
        except Exception:
            pass

def unique_path(base_dir: Path, filename: str) -> Path:
    """
    Return a path that doesn't collide by appending _1, _2, ... if needed.
    """
    target = base_dir / filename
    if not target.exists():
        return target

    stem = Path(filename).stem
    suffix = Path(filename).suffix
    i = 1
    while True:
        candidate = base_dir / f"{stem}_{i}{suffix}"
        if not candidate.exists():
            return candidate
        i += 1

def process_directory(root: Path, dry_run: bool = False) -> None:
    for path in root.rglob('*'):
        if not path.is_file():
            continue

        # Quick skip: extremely small files are unlikely valid PEs, but we still try.
        export_name = get_dll_export_name(path)
        if not export_name:
            continue

        # Same-name check (case-insensitive on Windows)
        current_name_ci = path.name.lower()
        export_name_ci = export_name.lower()
        if current_name_ci == export_name_ci:
            # Already correctly named
            continue

        target_path = unique_path(path.parent, export_name)

        if dry_run:
            print(f"[DRY] Would rename: {path.name}  ->  {target_path.name}")
        else:
            try:
                path.rename(target_path)
                print(f"[OK]  Renamed: {path.name}  ->  {target_path.name}")
            except Exception as e:
                print(f"[ERR] Failed to rename {path} -> {target_path.name}: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="Walk a directory, and rename DLLs to their exported module name (using pefile)."
    )
    parser.add_argument("directory", help="Root directory to scan")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without renaming")
    args = parser.parse_args()

    root = Path(args.directory).resolve()
    if not root.exists() or not root.is_dir():
        print(f"[!] Not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    process_directory(root, dry_run=args.dry_run)

if __name__ == "__main__":
    main()


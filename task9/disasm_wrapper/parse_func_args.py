#!/usr/bin/python3

import argparse
import os
import re
from FuncTypes import *

import re

# Regex: dll, func, type, [ ...args... ]
_LINE_RE = re.compile(
    r'^\s*'                         # start/leading space
    r'([^,]+)\s*,\s*'               # dll
    r'([^,]+)\s*,\s*'               # func
    r'(-?\d+)\s*,\s*'               # type (int)
    r'\[\s*(.*?)\s*\]\s*$'          # [...] capture inner as group 4
)

def _parse_arg_token(tok: str) -> int:
    """Convert a token to int; supports hex like 0x..., or decimal."""
    tok = tok.strip()
    if not tok:
        raise ValueError("empty arg token")
    # Allow optional '+'/'-' and hex/decimal autodetect
    if tok.lower().startswith(('0x', '+0x', '-0x')):
        return int(tok, 16)
    return int(tok, 10)

def parse_line(line: str) -> FFuncWrapper | None:
    """
    Parse a single line into FFuncWrapper.
    Returns None for blank/comment lines.
    Raises ValueError on malformed content.
    """
    # Strip comments after '#'
    line = line.split('#', 1)[0].strip()
    if not line:
        return None

    m = _LINE_RE.match(line)
    if not m:
        raise ValueError(f"Malformed record: {line}")

    dll, func, type_str, args_blob = m.groups()
    ftype = int(type_str, 10)

    # Split args by commas and/or whitespace
    raw_tokens = re.split(r'[\s,]+', args_blob.strip())
    tokens = [t for t in raw_tokens if t]  # drop empties

    args = [_parse_arg_token(t) for t in tokens]
    return FFuncWrapper(dll, func, ftype, args)


def parse_file_to_map(path: str, mapping: dict[str, FFuncWrapper]) -> dict[str, FFuncWrapper]:
    
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if "]" not in line:
                print(f"Invalid record: {line}")
                continue
            try:
                rec = parse_line(line)
                if rec is None:
                    continue
                key = f"{rec.dll}.{rec.func}"
                mapping[key] = rec
                #print(f"Key = {key}")
                #print(rec)
            except Exception as e:
                raise ValueError(f"{path}:{lineno}: {e}") from e
    return mapping


def main():
    parser = argparse.ArgumentParser(description="Parse files containing DLL function records.")
    parser.add_argument('--inpath', dest="inpath", required=True,
                        help="Path to input file or directory")
    args = parser.parse_args()
    out_file = args.inpath + "dlls_args.pkl"

    print(f"The results will be saved to: {out_file}")
    
    mapping: dict[str, FFuncWrapper] = {}
    if not os.path.isdir(args.inpath):
        print(f"No such directory: {args.inpath}")
        return
    # Process all files in directory
    for root, dirs, files in os.walk(args.inpath):
        for fname in files:
            if not fname.endswith(".csv"):
                continue
            filepath = os.path.join(root, fname)
            print(f"Parsing {filepath}")
            parse_file_to_map(filepath, mapping)
                
    save_map_as_pickle(mapping, out_file)
    print(f"Saved: {out_file}")


if __name__ == "__main__":
    main()
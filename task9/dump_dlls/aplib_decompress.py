#!/usr/bin/env python3

import malduck
import sys
import argparse
import os

def decompress_file(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
        try:
            res = malduck.aplib(data)
            if res:
                outpath = filepath + '_aplib_decompressed.exe'
                with open(outpath, 'wb') as g:
                    g.write(res)
                print(f'[+] Decompressed: {filepath} -> {outpath}')
            else:
                print(f'[!] Malduck did not decompress: {filepath}')
        except Exception as e:
            print(f'[!] Error decompressing {filepath}: {e}')

def main():
    parser = argparse.ArgumentParser(description="Aplib unpacker for single file or directory")
    parser.add_argument('--inpath', dest="inpath", required=True,
                        help="Path to input file or directory")
    args = parser.parse_args()

    if os.path.isdir(args.inpath):
        # Process all files in directory
        for root, dirs, files in os.walk(args.inpath):
            for fname in files:
                filepath = os.path.join(root, fname)
                decompress_file(filepath)
    else:
        # Single file
        decompress_file(args.inpath)

if __name__ == "__main__":
    main()


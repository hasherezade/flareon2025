#!/usr/bin/env python3
import os
import argparse

def rename_real_dlls(directory):
    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.real.dll'):
                old_path = os.path.join(root, filename)
                new_filename = filename.replace('.real.dll', '.dll')
                new_path = os.path.join(root, new_filename)

                # Rename the file
                try:
                    os.rename(old_path, new_path)
                    print(f'Renamed: {old_path} -> {new_path}')
                except Exception as e:
                    print(f'Error renaming {old_path}: {e}')

def main():
    parser = argparse.ArgumentParser(description='Rename *.real.dll files to *.dll recursively in a directory.')
    parser.add_argument('directory', help='Path to the directory to process')

    args = parser.parse_args()
    directory = args.directory

    if os.path.isdir(directory):
        rename_real_dlls(directory)
    else:
        print(f'Error: "{directory}" is not a valid directory.')

if __name__ == "__main__":
    main()


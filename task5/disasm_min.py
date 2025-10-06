#!/usr/bin/env python3
"""
Disassemble the .text section of a 64-bit PE and write lines like:
0x140015d14;jmp 0x140c685ee
0x140015d19;rdtsc
0x140015d1b;shl rdx, 0x20
0x140015d1f;or rax, rdx

Usage:
  pip install pefile capstone
  python disasm_text_to_file.py path/to/binary.exe -o out.txt
"""

import argparse
import sys
import os

try:
    import pefile
except ImportError:
    sys.stderr.write("[-] Missing dependency: pefile (pip install pefile)\n")
    sys.exit(1)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    sys.stderr.write("[-] Missing dependency: capstone (pip install capstone)\n")
    sys.exit(1)


def find_section(pe, name=b".text"):
    """Return the IMAGE_SECTION_HEADER for the given name (case-insensitive)."""
    lname = name.lower()
    for s in pe.sections:
        if s.Name.rstrip(b"\x00").lower() == lname:
            return s
    return None


def is_pe64(pe):
    """True iff PE is PE32+ AMD64."""
    return (pe.FILE_HEADER.Machine == 0x8664 and pe.OPTIONAL_HEADER.Magic == 0x20B)


def disasm_text_to_file(pe_path: str, out_path: str, section_name: str = ".text"):
    pe = pefile.PE(pe_path, fast_load=False)
    if not is_pe64(pe):
        raise RuntimeError("File is not a 64-bit PE (PE32+ / AMD64).")

    sec = find_section(pe, name=section_name.encode("ascii"))
    if not sec:
        raise RuntimeError(f"Section '{section_name}' not found.")

    image_base = pe.OPTIONAL_HEADER.ImageBase
    start_va = image_base + sec.VirtualAddress
    code = pe.get_data(sec.VirtualAddress, sec.SizeOfRawData)
    if not code:
        raise RuntimeError(f"Failed to read raw bytes of {section_name}.")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False  # we only need mnemonic/op_str

    # Write out: 0x{VA};{mnemonic}[ {op_str}]
    with open(out_path, "w", encoding="utf-8") as f:
        for ins in md.disasm(code, start_va):
            if ins.op_str:
                line = f"0x{ins.address:016x};{ins.mnemonic} {ins.op_str}"
            else:
                line = f"0x{ins.address:016x};{ins.mnemonic}"
            f.write(line + "\n")


def main():
    ap = argparse.ArgumentParser(description="Disassemble the .text of a 64-bit PE to a simple VA;insn text file.")
    ap.add_argument("pe", help="Path to the PE file (64-bit).")
    ap.add_argument("-o", "--out", required=True, help="Output text file.")
    ap.add_argument("--section", default=".text", help="Section name to disassemble (default: .text).")
    args = ap.parse_args()

    if not os.path.isfile(args.pe):
        sys.stderr.write(f"[-] File not found: {args.pe}\n")
        sys.exit(1)

    try:
        disasm_text_to_file(args.pe, args.out, section_name=args.section)
    except Exception as e:
        sys.stderr.write(f"[-] Error: {e}\n")
        sys.exit(1)

    print(f"[+] Disassembly of '{args.section}' written to: {args.out}")


if __name__ == "__main__":
    main()
    

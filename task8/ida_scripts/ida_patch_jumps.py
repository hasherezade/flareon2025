# IDA 9+ script: patch JMP REG obfuscation regions across the WHOLE .text segment
# Requires comments inserted by your marker script:
#   mov ... ;OBFUC BEGIN
#   jmp ... ;OBFUSC END: <rva2_hex>
#
# Changes vs original:
#  - Scans the .text segment (not just the current function)
#  - Backward search for OBFUC BEGIN is limited to .text start
#  - Keeps the same safety checks (jmp must be JMP reg; rel32 must fit)
#
# Tip: run after your linear-sweep/code-making pass, so all bytes are decodable.

import idaapi
import ida_kernwin
import idc
import idautils
import ida_bytes
import ida_segment
import ida_ua
import struct
import re

def find_eol_comment(ea):
    return idc.get_cmt(ea, 0) or ""

def patch_region_with_reljmp(start_ea, end_ea, target_va):
    """
    Write 5-byte rel32 JMP at start_ea -> target_va, NOP-fill [start_ea+5, end_ea).
    Returns True on success.
    """
    jump_size = 5
    rel32 = target_va - (start_ea + jump_size)
    if not -2**31 <= rel32 < 2**31:
        print(f"[patch_jmp] rel32 0x{rel32 & 0xFFFFFFFF:X} out of 32-bit range "
              f"for start 0x{start_ea:X} -> target 0x{target_va:X}")
        return False

    jmp_bytes = b'\xE9' + struct.pack('<i', rel32)
    try:
        ida_bytes.patch_bytes(start_ea, jmp_bytes)
    except Exception as e:
        print(f"[patch_jmp] failed to write jmp at 0x{start_ea:X}: {e}")
        return False

    cur = start_ea + jump_size
    while cur < end_ea:
        ida_bytes.patch_byte(cur, 0x90)  # NOP
        cur += 1
    return True

def main():
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        ida_kernwin.warning("[patch_jmp] .text segment not found.")
        return

    start_text, end_text = seg.start_ea, seg.end_ea
    image_base = idaapi.get_imagebase()
    print(f"[patch_jmp] scanning .text 0x{start_text:X}..0x{end_text:X} (image_base=0x{image_base:X})")

    patched_count = 0
    skipped_count = 0

    # Iterate every head in .text
    for head in idautils.Heads(start_text, end_text):
        mnem = idc.print_insn_mnem(head).lower()
        if mnem != "jmp":
            continue

        # must be JMP reg (obfuscation pattern we're targeting)
        op0type = idc.get_operand_type(head, 0)
        if op0type != ida_ua.o_reg:
            continue

        comment = find_eol_comment(head)
        if "obfusc" not in comment.lower():
            continue

        # Extract hex after "OBFUSC END:"
        m = re.search(r'OBFUSC\s*END\s*:\s*([0-9A-Fa-fx]+)', comment, flags=re.IGNORECASE)
        if not m:
            # fallback: any hex in the comment
            m2 = re.search(r'([0-9A-Fa-f]{3,})', comment)
            if not m2:
                print(f"[patch_jmp] can't parse target hex in comment at 0x{head:X}: '{comment}'")
                skipped_count += 1
                continue
            rva2_hex = m2.group(1)
        else:
            rva2_hex = m.group(1)

        if rva2_hex.lower().startswith("0x"):
            rva2_hex = rva2_hex[2:]
        try:
            rva2 = int(rva2_hex, 16)
        except Exception as e:
            print(f"[patch_jmp] invalid hex '{rva2_hex}' at 0x{head:X}: {e}")
            skipped_count += 1
            continue

        target_va = image_base + rva2

        # Walk backward (bounded by .text start) to find the nearest "OBFUC BEGIN"
        begin_ea = None
        cur = head
        while True:
            cur = idc.prev_head(cur, start_text)
            if cur == idc.BADADDR or cur < start_text:
                break
            c = find_eol_comment(cur).lower()
            if "obfuc begin" in c or "obfucbegin" in c:
                begin_ea = cur
                break

        if begin_ea is None:
            print(f"[patch_jmp] OBFUC BEGIN not found for jmp at 0x{head:X} (target RVA 0x{rva2_hex}) - skipping")
            skipped_count += 1
            continue

        # Region end = end of the jmp instruction
        jmp_size = idc.get_item_size(head) or 0
        if jmp_size <= 0:
            print(f"[patch_jmp] cannot get size of jmp at 0x{head:X} - skipping")
            skipped_count += 1
            continue
        end_ea = head + jmp_size

        if patch_region_with_reljmp(begin_ea, end_ea, target_va):
            patched_count += 1
            print(f"[patch_jmp] patched 0x{begin_ea:X}-0x{end_ea:X} -> jmp 0x{target_va:X}")
            # Mark it as patched
            old = find_eol_comment(head)
            idc.set_cmt(head, (old + " ;PATCHED->direct_jmp") if old else "PATCHED->direct_jmp", 0)
        else:
            skipped_count += 1

    ida_kernwin.refresh_idaview_anyway()
    idaapi.msg(f"\n[patch_jmp] done: patched={patched_count}, skipped={skipped_count}\n")
    print(f"[patch_jmp] done: patched={patched_count}, skipped={skipped_count}")

if __name__ == "__main__":
    main()

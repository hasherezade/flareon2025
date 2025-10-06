# IDA 9+ script: patch simple "add REG; call REG" obfuscation regions to direct calls
# Runs across the WHOLE .text segment (linear scan)
# Based on the user's original ida_patch_calls.py. :contentReference[oaicite:1]{index=1}
#
# Behavior:
#  - find call instructions with OBFUSC END comment
#  - ensure previous instruction is "add" whose dest reg matches call reg
#  - find preceding OBFUC BEGIN comment (bounded by .text start)
#  - replace region [begin_ea .. call_end) with:
#       5-byte relative CALL (E8 rel32 to targetVA) + NOPs
#
# Make a backup of your IDB/binary before running.

import idaapi
import ida_kernwin
import idc
import idautils
import ida_bytes
import struct
import ida_ua
import ida_segment
import re

def find_eol_comment(ea):
    return idc.get_cmt(ea, 0) or ""

def get_operand_text(ea, opnum=0):
    return idc.print_operand(ea, opnum)

def patch_region_with_relcall(start_ea, end_ea, target_va):
    """
    Write a 5-byte relative CALL at start_ea to target_va, and NOP-fill the rest
    of the region up to end_ea (end_ea is exclusive).
    Returns True on success.
    """
    call_size = 5
    rel32 = target_va - (start_ea + call_size)
    if not -2**31 <= rel32 < 2**31:
        print(f"[patch_call] rel32 0x{rel32 & 0xffffffff:X} doesn't fit 32-bit for start 0x{start_ea:X} -> target 0x{target_va:X}")
        return False

    call_bytes = b'\xE8' + struct.pack('<i', rel32)
    try:
        ida_bytes.patch_bytes(start_ea, call_bytes)
    except Exception as e:
        print(f"[patch_call] failed to write call at 0x{start_ea:X}: {e}")
        return False

    # NOP the rest
    cur = start_ea + call_size
    while cur < end_ea:
        ida_bytes.patch_byte(cur, 0x90)
        cur += 1

    return True

def main():
    image_base = idaapi.get_imagebase()

    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        ida_kernwin.warning("[patch_call] .text segment not found.")
        return

    start_text = seg.start_ea
    end_text = seg.end_ea
    print(f"[patch_call] scanning .text 0x{start_text:X}..0x{end_text:X} (image_base=0x{image_base:X})")

    patched = 0
    skipped = 0

    # iterate every head in .text
    for head in idautils.Heads(start_text, end_text):
        mnem = idc.print_insn_mnem(head).lower()
        if mnem != "call":
            continue

        # require register operand
        op0type = idc.get_operand_type(head, 0)
        if op0type != ida_ua.o_reg:
            continue

        comment = find_eol_comment(head)
        if not comment or "obfusc" not in comment.lower():
            continue

        # extract rva hex from comment
        m = re.search(r'OBFUSC\s*END\s*:\s*([0-9A-Fa-fx]+)', comment, flags=re.IGNORECASE)
        if not m:
            # fallback: any hex token in comment
            m2 = re.search(r'([0-9A-Fa-f]{3,})', comment)
            if not m2:
                print(f"[patch_call] can't parse target hex in comment at 0x{head:X}: '{comment}'")
                skipped += 1
                continue
            rva2_hex = m2.group(1)
        else:
            rva2_hex = m.group(1)
        if rva2_hex.lower().startswith("0x"):
            rva2_hex = rva2_hex[2:]
        try:
            rva2 = int(rva2_hex, 16)
        except Exception as e:
            print(f"[patch_call] invalid hex '{rva2_hex}' at 0x{head:X}: {e}")
            skipped += 1
            continue

        target_va = image_base + rva2

        # Ensure immediate previous instruction exists and is "add DEST, ..."
        prev = idc.prev_head(head, start_text)
        if prev == idc.BADADDR or prev < start_text:
            print(f"[patch_call] no previous instruction for call at 0x{head:X} - skipping")
            skipped += 1
            continue
        prev_mnem = idc.print_insn_mnem(prev).lower()
        if prev_mnem != "add":
            print(f"[patch_call] previous instr at 0x{prev:X} is '{prev_mnem}' not 'add' - skipping (simple-case only)")
            skipped += 1
            continue

        # check dest reg of add matches call reg
        call_reg = get_operand_text(head, 0).split()[0].lower()
        add_dest = get_operand_text(prev, 0).split()[0].lower()
        if call_reg != add_dest:
            print(f"[patch_call] add dest '{add_dest}' != call reg '{call_reg}' at 0x{head:X} - skipping")
            skipped += 1
            continue

        # find preceding OBFUC BEGIN comment (bounded by .text start)
        begin_ea = None
        cur = prev  # start searching from the instruction before the call so that 'add' is inside the region
        while True:
            cur = idc.prev_head(cur, start_text)
            if cur == idc.BADADDR or cur < start_text:
                break
            c = find_eol_comment(cur)
            if "obfuc begin" in c.lower() or "obfucbegin" in c.lower():
                begin_ea = cur
                break
        if begin_ea is None:
            print(f"[patch_call] OBFUC BEGIN not found for call at 0x{head:X} - skipping")
            skipped += 1
            continue

        # compute end of call instruction
        call_size = idc.get_item_size(head)
        if not call_size:
            print(f"[patch_call] cannot get size of call at 0x{head:X} - skipping")
            skipped += 1
            continue
        end_ea = head + call_size

        # patch region
        ok = patch_region_with_relcall(begin_ea, end_ea, target_va)
        if ok:
            patched += 1
            # add patch comment to call instruction
            old = find_eol_comment(head)
            newc = (old + " ;PATCHED->direct_call") if old else "PATCHED->direct_call"
            idc.set_cmt(head, newc, 0)
            print(f"[patch_call] patched region 0x{begin_ea:X}-0x{end_ea:X} -> call 0x{target_va:X}")
        else:
            skipped += 1

    ida_kernwin.refresh_idaview_anyway()
    idaapi.msg(f"\n[patch_call] done: patched={patched}, skipped={skipped}\n")
    print(f"[patch_call] done: patched={patched}, skipped={skipped}")

if __name__ == "__main__":
    main()

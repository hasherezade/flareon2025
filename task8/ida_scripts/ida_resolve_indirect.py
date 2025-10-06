# IDA 9+ script: mark obfuscated call/jmp -> mov cs:off_... patterns across the whole .text segment
# Based on the user's original ida_resolve_indirect.py. Processes every head in .text
#
# Usage: run in IDA while any view is active. It will load TAGS_PATH and scan the .text segment.
# Adjust TAGS_PATH if needed.

import idaapi
import idc
import ida_kernwin
import ida_funcs
import idautils
import ida_ua
import ida_segment
import ida_nalt
import ida_loader
import re
import os

modulebase = idaapi.get_imagebase()

def load_rva_map(path):
    if not os.path.exists(path):
        ida_kernwin.warning(f"[mark_obfuc] tags file not found: {path}")
        return {}

    pattern = re.compile(
        r'^\s*([0-9A-Fa-f]+)\s*;\s*to:\s*([0-9A-Fa-fx]+)\s*\[.*\+\s*([0-9A-Fa-f]+)\s*\]',
        re.IGNORECASE
    )
    rva_map = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            m = pattern.match(ln.strip())
            if not m:
                continue
            rva1_hex = m.group(1)
            rva2_hex = m.group(3)
            try:
                r1 = int(rva1_hex, 16)
                r2 = int(rva2_hex, 16)
                rva_map[r1] = r2
            except Exception as e:
                print(f"[mark_obfuc] parse fail for line: {ln.strip()} -> {e}")
                continue
    print(f"[mark_obfuc] loaded {len(rva_map)} RVA entries from {path}")
    return rva_map

def is_reg_operand(ea):
    t = idc.get_operand_type(ea, 0)
    return t == ida_ua.o_reg

def get_operand_text(ea, opnum=0):
    return idc.print_operand(ea, opnum)

def try_mark_obfuc_for_range(start, end, rva_map, image_base):
    """
    Walk heads in [start, end) and mark occurrences.
    Returns list of (mov_ea, call_ea, rva2)
    """
    marked = []
    for ea in idautils.Heads(start, end):
        # compute RVA of this instruction
        rva = ea - image_base
        if rva < 0:
            continue
        if rva not in rva_map:
            continue

        mnem = idc.print_insn_mnem(ea).lower()
        if mnem not in ("call", "jmp"):
            continue

        if not is_reg_operand(ea):
            continue

        reg_text = get_operand_text(ea, 0).split()[0]

        # search backward for "mov REG, cs:..."
        mov_ea_found = None
        search_ea = ea
        # limit search to range start
        while True:
            prev = idc.prev_head(search_ea, start)
            if prev == idc.BADADDR or prev < start:
                break
            search_ea = prev
            smnem = idc.print_insn_mnem(search_ea).lower()
            if smnem != "mov":
                continue
            dest = get_operand_text(search_ea, 0)
            if not dest:
                continue
            if dest.split()[0].lower() != reg_text.lower():
                continue
            src_text = get_operand_text(search_ea, 1)
            # check printed operand or full disasm for 'cs:' segment override
            if src_text and ('cs:' in src_text.lower() or 'cs:' in idc.GetDisasm(search_ea).lower()):
                mov_ea_found = search_ea
                break

        if mov_ea_found:
            rva2 = rva_map[rva]
            rva2_hex = f"{rva2:x}"
            try:
                new_mov = " ;OBFUC BEGIN"
                idc.set_cmt(mov_ea_found, new_mov, 0)

                new_call = f"{(rva2+modulebase):x}; OBFUSC END: {rva2_hex}"
                idc.set_cmt(ea, new_call, 0)

                marked.append((mov_ea_found, ea, rva2))
                print(f"[mark_obfuc] marked mov at 0x{mov_ea_found:08X} and {mnem} at 0x{ea:08X} -> RVA2=0x{rva2_hex}")
            except Exception as e:
                print(f"[mark_obfuc] failed to set comments at {hex(mov_ea_found)} / {hex(ea)}: {e}")
        else:
            print(f"[mark_obfuc] no mov(cs:...) found for {mnem} at {hex(ea)} (RVA 0x{rva:x}) - skipped")

    return marked


def get_trimmed_path(full_path):
    # Normalize to lowercase for safety
    lower_path = full_path.lower()
    if ".exe" in lower_path:
        trimmed = full_path[: lower_path.index(".exe") + 4]  # include ".exe"
    elif ".dll" in lower_path:
        trimmed = full_path[: lower_path.index(".dll") + 4]  # include ".dll"
    else:
        trimmed = full_path  # fallback
    return trimmed
        
def main():
    image_base = idaapi.get_imagebase()
    path = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
    trimmed = get_trimmed_path(path)
    tags_path = trimmed + ".tag"   # change if needed
    print("Loading tags from: %s" % (tags_path))

    rva_map = load_rva_map(tags_path)
    if not rva_map:
        ida_kernwin.warning("[mark_obfuc] No tag entries found; quitting.")
        return

    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        ida_kernwin.warning("[mark_obfuc] .text segment not found.")
        return

    start = seg.start_ea
    end = seg.end_ea
    print(f"[mark_obfuc] Scanning .text: 0x{start:08X}..0x{end:08X} (image_base=0x{image_base:08X})")

    # Pause background analysis while we annotate
    try:
        ida_auto = __import__("ida_auto")
        ida_auto.set_ida_state(ida_auto.st_Work)
    except Exception:
        ida_kernwin.warning("[mark_obfuc] couldn't pause auto-analysis; continuing anyway.")

    marked = try_mark_obfuc_for_range(start, end, rva_map, image_base)
    ida_kernwin.refresh_idaview_anyway()
    print(f"[mark_obfuc] Done. Marked {len(marked)} regions.")
    idaapi.msg(f"\n[mark_obfuc] Done. Marked {len(marked)} regions.\n")

if __name__ == "__main__":
    main()

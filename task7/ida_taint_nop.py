# IDA 9+ — NOP-out all lines tagged as OBFUSC (skip END)
# - Scans the function at the cursor (or pass an EA).
# - NOPs every instruction whose comment contains "OBFUSC" (case-insensitive)
#   and does NOT contain "END".
# - Leaves "END ..." lines alone (those mark the end of an obfuscation block).
#
# Notes:
# - Uses 0x90 NOPs (x86/x64). If you're on a different arch, swap NOP_BYTE accordingly.
# - Set DRY_RUN = True to only print what would be patched.

import ida_funcs
import idautils
import ida_bytes
import ida_lines
import ida_kernwin
import idc

# ---------- Config ----------
DRY_RUN   = False          # True => print only, no patching
NOP_BYTE  = 0x90           # x86/x64 NOP
SKIP_FLOW = False          # If True, don't NOP control-flow insns (jmp/jcc/call/ret)
VERBOSE   = False
# ----------------------------

_FLOW_PREFIXES = ("j",)  # jmp, je, jne, jg, jl, etc.
_FLOW_EXACT    = {"call", "ret"}

def _is_code(ea):
    return ida_bytes.is_code(ida_bytes.get_full_flags(ea))

def _mnem(ea):
    return (idc.print_insn_mnem(ea) or "").lower()

def _is_control_flow(ea):
    m = _mnem(ea)
    if m in _FLOW_EXACT:
        return True
    if any(m.startswith(p) for p in _FLOW_PREFIXES):
        return True
    return False

def _disasm(ea):
    s = ida_lines.generate_disasm_line(ea, 0) or idc.GetDisasm(ea) or ""
    return ida_lines.tag_remove(s).strip()

def _get_any_comment(ea):
    # check both regular and repeatable comments
    c0 = idc.get_cmt(ea, 0) or ""
    c1 = idc.get_cmt(ea, 1) or ""
    return (c0 + " " + c1).strip()

def _is_obfusc_line(ea):
    c = _get_any_comment(ea).lower()
    if not c:
        return False
    if "end" in c:
        return False
    return "obfusc" in c

def _nop_bytes(size):
    return bytes([NOP_BYTE] * size)

def _nop_insn(ea):
    sz = idc.get_item_size(ea)
    if sz <= 0:
        return False
    ida_bytes.patch_bytes(ea, _nop_bytes(sz))
    # Optional: re-decoding not strictly needed; IDA will re-analyze later anyway.
    return True

def nop_obfusc_in_func(ea=None):
    if ea is None:
        ea = ida_kernwin.get_screen_ea()
    f = ida_funcs.get_func(ea)
    if not f:
        print(f"[!] No function found at 0x{ea:X}")
        return

    fname = ida_funcs.get_func_name(f.start_ea)
    print(f"[+] NOP scan in {fname} @ 0x{f.start_ea:X}..0x{f.end_ea:X}")
    to_patch = []

    for insn_ea in idautils.FuncItems(f.start_ea):
        if not _is_code(insn_ea):
            continue
        if not _is_obfusc_line(insn_ea):
            continue
        if SKIP_FLOW and _is_control_flow(insn_ea):
            continue
        to_patch.append(insn_ea)

    if not to_patch:
        print("[+] Nothing to NOP (no OBFUSC lines found).")
        return

    print(f"[+] Found {len(to_patch)} OBFUSC instruction(s) to NOP.")
    total_bytes = 0
    for i, ea_i in enumerate(to_patch, 1):
        sz = idc.get_item_size(ea_i)
        d  = _disasm(ea_i)
        if VERBOSE:
            print(f"  {i:>4}. 0x{ea_i:X}  size={sz:>2}  {d}")
        total_bytes += max(0, sz)
        if not DRY_RUN:
            _nop_insn(ea_i)

    if DRY_RUN:
        print(f"[DRY RUN] Would patch {len(to_patch)} insn(s), {total_bytes} byte(s).")
    else:
        print(f"[DONE] NOPed {len(to_patch)} insn(s), {total_bytes} byte(s).")

if __name__ == "__main__":
    nop_obfusc_in_func()

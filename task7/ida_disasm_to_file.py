# Save current function's disassembly to a file (IDA 9+)
import os
import ida_funcs
import ida_kernwin
import idautils
import ida_lines
import idc

OUTPUT_PATH = "C:\\dumps"

def save_func_disasm(ea=None, dir_path=OUTPUT_PATH, append=False):
    """
    Walks from the beginning to the end of the function containing `ea`
    (or the cursor if None) and saves disassembly lines for code items
    to the given file path.
    """
    if ea is None:
        ea = ida_kernwin.get_screen_ea()

    f = ida_funcs.get_func(ea)
    path = dir_path + "\\" + idc.get_func_name(ea) + ".disasm.asm"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "a" if append else "w"

    if not f:
        with open(path, mode, encoding="utf-8", newline="\n") as fp:
            fp.write(f"[!] No function found at 0x{ea:X}\n")
        return False

    name = ida_funcs.get_func_name(f.start_ea)
    with open(path, mode, encoding="utf-8", newline="\n") as fp:
        fp.write(f"[+] Function: {name} @ 0x{f.start_ea:X} .. 0x{f.end_ea:X}\n")
        for head in idautils.Heads(f.start_ea, f.end_ea):
            if idc.is_code(idc.get_full_flags(head)):
                line = ida_lines.generate_disasm_line(head, 0) or idc.GetDisasm(head)
                if not line:
                    continue
                line = ida_lines.tag_remove(line)
                if "nop" in line:
                    continue
                fp.write(f"{head:08X}: {line}\n")
    return True

if __name__ == "__main__":
    save_func_disasm()


# IDA 9+ (IDAPython 3)
import ida_segment, ida_bytes, ida_ua, ida_funcs, ida_auto

def linear_sweep_text(make_funcs=False):
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        raise RuntimeError("No .text segment found")
    start, end = seg.start_ea, seg.end_ea

    # 1) Undefine everything in .text so we start clean
    ida_bytes.del_items(start, ida_bytes.DELIT_SIMPLE, end - start)

    ea = start
    insn = ida_ua.insn_t()

    # 2) Optional: disable auto while we brute-force (keeps IDA from retyping under us)
    ida_auto.set_ida_state(ida_auto.st_Work)  # enter "work" state to pause background passes

    while ea < end:
        # Try to create an instruction at ea
        if ida_ua.create_insn(ea):
            # decode to get length, advance by instruction size
            n = ida_ua.decode_insn(insn, ea)
            if n and n > 0:
                # Optionally, create tiny 1-ea functions if asked
                if make_funcs and not ida_funcs.get_func(ea):
                    ida_funcs.add_func(ea)
                ea += n
                continue

        # If we couldn’t make an instruction, step one byte and try again
        ea += 1

    # 3) Let IDA finish any pending queues
    ida_auto.set_ida_state(ida_auto.st_Ready)
    ida_auto.auto_wait()

linear_sweep_text(make_funcs=False)  # set True if you want single-ea funcs
print("[+] Linear sweep over .text completed.")

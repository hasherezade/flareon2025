# IDA 9+ — obfuscation taint tracker (regs + locals) with:
# - START/END block prints
# - Kills: MOV-from-unrelated, LEA-from-clean-local, LEA reg,symbol/const, zeroing idioms (scalar+SIMD),
#          CALL return (rax + xmm0)
# - Propagation: regs + locals; g_Obfusc origins & uses
# - Pass 2: mark JCC that skip fully-OBF fallthrough blocks
# - Pass 3: retro-tag "mov reg, imm/symbol" as OBFUSC when the reg is used only by OBFUSC ops (incl. RMW & implicit)
#
# Notes:
# - "OBFUSC ..." lines are colored; "END ..." kills are NOT colored.
# - If Pass 1 wrote an END on a const load but Pass 3 proves it's for obfuscation only,
#   Pass 3 will overwrite the comment to "OBFUSC (const-for-obf)" and color it.

import re
import ida_kernwin
import ida_funcs
import idautils
import ida_lines
import ida_bytes
import idc

# ---------- Config ----------
COMMENT_OBFUSC = "OBFUSC"
COMMENT_END    = "END"
COMMENT_REPEATABLE = True

COLOR_MARK     = True
COLOR_OBFUSC   = 0xFFCCCC  # BGR

PRINT_BLOCK_EVENTS = False
PRINT_OTHER        = False

# Pass 3 options
P3_STOP_AT_CTRL_FLOW = True
P3_REQUIRE_AT_LEAST_ONE_USE = True
# ----------------------------

# --- Register alias groups (canonical -> aliases) ---
REG_ALIAS_GROUPS = {
    'rax': ['rax','eax','ax','al','ah'],
    'rbx': ['rbx','ebx','bx','bl','bh'],
    'rcx': ['rcx','ecx','cx','cl','ch'],
    'rdx': ['rdx','edx','dx','dl','dh'],
    'rsi': ['rsi','esi','si','sil'],
    'rdi': ['rdi','edi','di','dil'],
    'rbp': ['rbp','ebp','bp'],
    'rsp': ['rsp','esp','sp'],
    'r8' : ['r8','r8d','r8w','r8b'],
    'r9' : ['r9','r9d','r9w','r9b'],
    'r10': ['r10','r10d','r10w','r10b'],
    'r11': ['r11','r11d','r11w','r11b'],
    'r12': ['r12','r12d','r12w','r12b'],
    'r13': ['r13','r13d','r13w','r13b'],
    'r14': ['r14','r14d','r14w','r14b'],
    'r15': ['r15','r15d','r15w','r15b'],
}
# XMM/YMM/ZMM (canonical 'xmmN'; aliases include ymmN/zmmN)
for i in range(32):
    REG_ALIAS_GROUPS[f'xmm{i}'] = [f'xmm{i}', f'ymm{i}', f'zmm{i}']

ALL_REG_ALIASES = set()
ALIASTO_CANON = {}
for canon, aliases in REG_ALIAS_GROUPS.items():
    for a in aliases:
        a_l = a.lower()
        ALL_REG_ALIASES.add(a_l)
        ALIASTO_CANON[a_l] = canon

RE_G_OBFUSC = re.compile(r'\b(g_Obfusc\d+)\b', re.IGNORECASE)
RE_VAR      = re.compile(r'\b(var_[0-9A-Fa-f]+)\b', re.IGNORECASE)

# ---------- helpers: comments / color / tracking ----------
def add_comment(ea, text, tag=COMMENT_OBFUSC, color=True):
    """
    Force the comment to show by setting BOTH non-repeatable (0) and repeatable (1).
    This ensures retro-tagging (e.g., changing END -> OBFUSC) is visible.
    """
    c = f"{tag} {text}"
    try:
        idc.set_cmt(ea, c, 0)  # non-repeatable
        idc.set_cmt(ea, c, 1)  # repeatable
    except Exception:
        pass
    if color and COLOR_MARK and tag == COMMENT_OBFUSC:
        try:
            ida_kernwin.set_item_color(ea, COLOR_OBFUSC)
        except Exception:
            pass

# record all EAs marked as OBFUSC
obf_eas = set()
def obf_mark(ea, text):
    add_comment(ea, text, COMMENT_OBFUSC, color=True)
    obf_eas.add(ea)

def end_mark(ea, text):
    add_comment(ea, text, COMMENT_END, color=False)
#
def dline(ea):
    s = ida_lines.generate_disasm_line(ea, 0) or idc.GetDisasm(ea) or ""
    return ida_lines.tag_remove(s).strip()

def p(msg):
    if PRINT_OTHER:
        print(msg)

def block_start(kind, name, ea, reason):
    if PRINT_BLOCK_EVENTS:
        print(f"[BLOCK START] {kind} {name} @ 0x{ea:X} — {reason}")

def block_end(kind, name, ea, reason):
    if PRINT_BLOCK_EVENTS:
        print(f"[BLOCK END]   {kind} {name} @ 0x{ea:X} — {reason}")

# ---------- helpers: text / operand parsing ----------
def extract_operands_from_disasm(ea):
    line = dline(ea)
    if not line:
        return ("","","")
    parts = re.split(r'\s+', line, maxsplit=1)
    if len(parts) == 1:
        return ("","","")
    ops = parts[1].strip()
    op_parts = [p.strip() for p in ops.split(',')]
    while len(op_parts) < 3:
        op_parts.append("")
    return (op_parts[0], op_parts[1], op_parts[2])

def find_registers_in_text(op_text):
    found = set()
    if not op_text:
        return found
    t = op_text.lower()
    # If stack var access, don't count rbp/rsp from inside [...]
    if '[' in t and ']' in t and RE_VAR.search(t):
        before = t.split('[',1)[0]
        after  = t.split(']',1)[1] if ']' in t else ''
        combined = before + ' ' + after
        for alias, canon in ALIASTO_CANON.items():
            if re.search(r'\b' + re.escape(alias) + r'\b', combined):
                found.add(canon)
        return found
    for alias, canon in ALIASTO_CANON.items():
        if re.search(r'\b' + re.escape(alias) + r'\b', t):
            found.add(canon)
    return found

def extract_variable_from_operand(op_text):
    if not op_text:
        return None
    t = op_text.lower()
    if '[' not in t or ']' not in t:
        return None
    m = RE_VAR.search(t)
    return m.group(1).lower() if m else None

def get_first_gobf_text(*ops):
    for o in ops:
        if not o: 
            continue
        m = RE_G_OBFUSC.search(o)
        if m:
            return m.group(1)
    return None

def is_plain_register_operand(op_text):
    return bool(op_text) and (op_text.lower() in ALL_REG_ALIASES)

def is_mov_like(mnem): return mnem.startswith('mov')          # mov, movsx, movzx, movabs...
def is_call(mnem):     return mnem == 'call'
def is_jmp(mnem):      return mnem == 'jmp'
def is_cond_jcc(m):    return (m.startswith('j') and not is_jmp(m))  # jz, jne, jle, ...

def operand_has_gobf(op_text):
    return bool(op_text and RE_G_OBFUSC.search(op_text.lower()))

def is_zeroing_idiom(mnem, op0, op1, op2):
    m = mnem.lower()
    op0l, op1l, op2l = (op0 or "").lower(), (op1 or "").lower(), (op2 or "").lower()
    if m in ('xor','sub','pxor','xorps','xorpd'):
        return is_plain_register_operand(op0l) and is_plain_register_operand(op1l) and (op0l == op1l)
    if m in ('vpxor','vxorps','vxorpd','vpxord','vpxorq'):
        return all(is_plain_register_operand(x) for x in (op0l, op1l, op2l)) and (op0l == op1l == op2l)
    return False

def is_symbol_or_const_no_mem(op_text):
    if not op_text:
        return False
    t = op_text.lower().strip()
    if '[' in t or ']' in t:
        return False
    if is_plain_register_operand(t):
        return False
    if operand_has_gobf(t):
        return False
    # immediates
    if re.fullmatch(r'(?:0x[0-9a-f]+|[0-9a-f]+h|\d+)', t):
        return True
    if t.startswith('offset '):
        return True
    # label-ish
    if re.fullmatch(r'(?:[a-z_$.@?][\w$.@?]*)(?::[a-z_$.@?][\w$.@?]*)?', t):
        return True
    return any(prefix in t for prefix in ('off_', 'byte_', 'word_', 'dword_', 'qword_', 'stru_', 'cs:','ds:','a'))

def resolve_branch_target(ea, op0_text):
    try:
        v = idc.get_operand_value(ea, 0)
        if v not in (idc.BADADDR, 0):
            return v
    except Exception:
        pass
    t = op0_text.strip()
    t = re.sub(r'^(?:short|near|far)\s+', '', t, flags=re.I)
    ea2 = idc.get_name_ea_simple(t)
    if ea2 not in (idc.BADADDR, None):
        return ea2
    m = re.search(r'loc_([0-9A-Fa-f]+)', t)
    if m:
        return int(m.group(1), 16)
    m = re.search(r'0x([0-9A-Fa-f]+)', t) or re.search(r'([0-9A-Fa-f]+)h', t)
    if m:
        s = m.group(1)
        return int(s, 16) if 'h' not in t else int(s[:-1], 16)
    return idc.BADADDR

def is_control_flow_mnem(m):
    return is_call(m) or is_jmp(m) or (m == 'ret') or is_cond_jcc(m)

# --- RMW ops read the destination too (e.g., sub ecx, eax) ---
def rmw_reads_dest(mnem: str) -> bool:
    m = (mnem or "").lower()
    return m in {
        'add','sub','adc','sbb',
        'and','or','xor',
        'imul',  # 2- & 3-op forms read dest; 1-op handled via implicit reads
        'shl','sal','shr','sar','rol','ror','rcl','rcr',
        'inc','dec','neg','not',
        'xadd','bts','btr','btc',
        'cmpxchg','cmpxchg8b','cmpxchg16b'
    }

def next_is_obf_use_of_reg(ea, canon_reg, func_end_ea):
    """
    Quick lookahead: if the very next instruction uses 'canon_reg' (explicitly in sources
    or as RMW dest) AND that next instruction is already in obf_eas, return True.
    """
    nxt = idc.next_head(ea, func_end_ea)
    if nxt in (idc.BADADDR, None):
        return False
    m = (idc.print_insn_mnem(nxt) or "").lower()
    op0, op1, op2 = extract_operands_from_disasm(nxt)
    # explicit source use?
    srcs = find_registers_in_text((op1 or "").lower()) | find_registers_in_text((op2 or "").lower())
    if canon_reg in srcs and (nxt in obf_eas):
        return True
    # RMW on dest?
    dests = find_registers_in_text((op0 or "").lower())
    if (canon_reg in dests) and rmw_reads_dest(m) and (nxt in obf_eas):
        return True
    # implicit read (e.g., 1-op IMUL reading RAX)?
    r_impl, _ = implicit_reads_writes(m, op0, op1, op2)
    if (canon_reg in r_impl) and (nxt in obf_eas):
        return True
    return False
# --- Some mnemonics that DO NOT write op0 (avoid false "overwrite"): ---
NON_WRITING_DEST = {'cmp','test','bt','cmps','scas'}

# --- Implicit register reads/writes for tricky mnemonics ---
def implicit_reads_writes(mnem: str, op0: str, op1: str, op2: str):
    """
    Return (reads, writes) sets of canonical regs implicitly touched.
    Handle:
      - 1-op imul/mul:   reads RAX, writes RDX:RAX
      - idiv/div:        reads RDX:RAX, writes RDX:RAX
      - cpuid:           reads RAX, writes RAX,RBX,RCX,RDX
    """
    m = (mnem or "").lower()
    reads, writes = set(), set()

    opcnt = int(bool((op0 or '').strip())) + int(bool((op1 or '').strip())) + int(bool((op2 or '').strip()))
    if m in ('imul', 'mul'):
        if opcnt == 1:
            reads.add('rax')
            writes.update(('rax','rdx'))
    elif m in ('idiv','div'):
        reads.update(('rax','rdx'))
        writes.update(('rax','rdx'))
    elif m == 'cpuid':
        reads.add('rax')
        writes.update(('rax','rbx','rcx','rdx'))

    return reads, writes

# ---------- PASS 1: taint-based marking ----------
def pass1_taint_mark(f):
    tainted_regs = set()
    tainted_vars = set()
    open_block_reg = {}
    open_block_var = {}

    for ea in idautils.FuncItems(f.start_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        op0, op1, op2 = extract_operands_from_disasm(ea)
        op0_l, op1_l, op2_l = (op0 or "").lower(), (op1 or "").lower(), (op2 or "").lower()
        var0 = extract_variable_from_operand(op0_l)
        var1 = extract_variable_from_operand(op1_l)
        var2 = extract_variable_from_operand(op2_l)
        src_regs = find_registers_in_text(op1_l) | find_registers_in_text(op2_l)
        dest_regs = find_registers_in_text(op0_l)

        # CALL: kill rax & xmm0
        if is_call(mnem):
            for ret_reg in ('rax','xmm0'):
                if ret_reg in tainted_regs:
                    tainted_regs.remove(ret_reg)
                    end_mark(ea, f"(kill reg {ret_reg} by call return)")
                    if ret_reg in open_block_reg:
                        block_end("reg", ret_reg, ea, "call return")
                        del open_block_reg[ret_reg]
            continue

        # Origins: direct g_Obfusc loads
        if operand_has_gobf(op1_l) or operand_has_gobf(op0_l):
            gtxt = get_first_gobf_text(op0_l, op1_l)
            if is_plain_register_operand(op0_l):
                for d in dest_regs:
                    if d not in tainted_regs:
                        tainted_regs.add(d)
                        if d not in open_block_reg:
                            open_block_reg[d] = (ea, f"origin {gtxt or 'g_Obfusc'}")
                            block_start("reg", d, ea, open_block_reg[d][1])
                obf_mark(ea, "(obf-origin)")
            elif var0:
                if var0 not in tainted_vars:
                    tainted_vars.add(var0)
                    if var0 not in open_block_var:
                        open_block_var[var0] = (ea, f"origin {gtxt or 'g_Obfusc'}")
                        block_start("var", var0, ea, open_block_var[var0][1])
                obf_mark(ea, f"(obf-origin -> {var0})")
            else:
                obf_mark(ea, "(obf-origin, mem/complex)")
            continue

        # Uses tainted VARS -> propagate
        used_vars = [v for v in (var1, var2) if v and v in tainted_vars]
        if used_vars:
            obf_mark(ea, "(uses-vars)")
            for d in dest_regs:
                if d not in tainted_regs:
                    tainted_regs.add(d)
                    if d not in open_block_reg:
                        open_block_reg[d] = (ea, f"prop from var(s) {','.join(sorted(set(used_vars)))}")
                        block_start("reg", d, ea, open_block_reg[d][1])
                    obf_mark(ea, f"(taint-propagate->{d} from var)")
            if var0 and var0 not in tainted_vars:
                tainted_vars.add(var0)
                if var0 not in open_block_var:
                    open_block_var[var0] = (ea, f"prop from var(s) {','.join(sorted(set(used_vars)))}")
                    block_start("var", var0, ea, open_block_var[var0][1])
                obf_mark(ea, f"(taint-propagate->var {var0})")
            continue

        # Uses tainted REGS -> propagate
        used_regs = sorted(r for r in src_regs if r in tainted_regs)
        if used_regs:
            obf_mark(ea, f"(uses-regs: {','.join(used_regs)})")
            for d in dest_regs:
                if d not in tainted_regs:
                    tainted_regs.add(d)
                    if d not in open_block_reg:
                        open_block_reg[d] = (ea, f"prop from reg(s) {','.join(used_regs)}")
                        block_start("reg", d, ea, open_block_reg[d][1])
                    obf_mark(ea, f"(taint-propagate->{d})")
            if var0 and var0 not in tainted_vars:
                tainted_vars.add(var0)
                if var0 not in open_block_var:
                    open_block_var[var0] = (ea, f"prop from reg(s) {','.join(used_regs)}")
                    block_start("var", var0, ea, open_block_var[var0][1])
                obf_mark(ea, f"(taint-propagate->var {var0})")
            continue

        # Uses g_Obfusc in source -> propagate
        if operand_has_gobf(op1_l) or operand_has_gobf(op2_l):
            gtxt = get_first_gobf_text(op1_l, op2_l)
            obf_mark(ea, "(uses g_Obfusc)")
            for d in dest_regs:
                if d not in tainted_regs:
                    tainted_regs.add(d)
                    if d not in open_block_reg:
                        open_block_reg[d] = (ea, f"from {gtxt or 'g_Obfusc'}")
                        block_start("reg", d, ea, open_block_reg[d][1])
                obf_mark(ea, f"(taint-propagate->{d})")
            if var0 and var0 not in tainted_vars:
                tainted_vars.add(var0)
                if var0 not in open_block_var:
                    open_block_var[var0] = (ea, f"from {gtxt or 'g_Obfusc'}")
                    block_start("var", var0, ea, open_block_var[var0][1])
                obf_mark(ea, f"(taint-propagate->var {var0})")
            continue

        # LEA A: lea REG, [rbp+...+var_X]
        if mnem == 'lea' and is_plain_register_operand(op0_l):
            var1x = extract_variable_from_operand(op1_l)
            if var1x:
                if var1x in tainted_vars:
                    for d in dest_regs:
                        if d not in tainted_regs:
                            tainted_regs.add(d)
                            if d not in open_block_reg:
                                open_block_reg[d] = (ea, f"lea from tainted {var1x}")
                                block_start("reg", d, ea, open_block_reg[d][1])
                        obf_mark(ea, f"(lea propagate->{d} from tainted {var1x})")
                else:
                    for d in dest_regs:
                        if d in tainted_regs:
                            tainted_regs.remove(d)
                            end_mark(ea, f"(kill {d} by lea from clean {var1x})")
                            if d in open_block_reg:
                                block_end("reg", d, ea, f"lea from clean {var1x}")
                                del open_block_reg[d]
                continue

        # LEA B: lea REG, <symbol/const>
        if mnem == 'lea' and is_plain_register_operand(op0_l) and is_symbol_or_const_no_mem(op1_l):
            for d in dest_regs:
                if d in tainted_regs:
                    tainted_regs.remove(d)
                    end_mark(ea, f"(kill {d} by lea from symbol/const)")
                    if d in open_block_reg:
                        block_end("reg", d, ea, "lea from symbol/const")
                        del open_block_reg[d]
            continue

        # ZEROING idioms -> kill
        if is_zeroing_idiom(mnem, op0_l, op1_l, op2_l):
            for d in dest_regs:
                if d in tainted_regs:
                    tainted_regs.remove(d)
                    end_mark(ea, f"(kill reg {d} by zeroing {mnem})")
                    if d in open_block_reg:
                        block_end("reg", d, ea, f"zeroing {mnem}")
                        del open_block_reg[d]
            continue

        # MOV-like: kills if src unrelated; else propagate
        if dest_regs or var0:
            if is_mov_like(mnem):
                src_tainted = any(r in tainted_regs for r in src_regs) or (var1 in tainted_vars) or (var2 in tainted_vars)
                if not src_tainted and not (operand_has_gobf(op1_l) or operand_has_gobf(op2_l)):
                    for d in list(dest_regs):
                        if d in tainted_regs:
                            tainted_regs.remove(d)
                            end_mark(ea, f"(kill reg {d} by mov)")
                            if d in open_block_reg:
                                block_end("reg", d, ea, "mov from unrelated")
                                del open_block_reg[d]
                    if var0 and var0 in tainted_vars:
                        tainted_vars.remove(var0)
                        end_mark(ea, f"(kill var {var0} by mov)")
                        if var0 in open_block_var:
                            block_end("var", var0, ea, "mov from unrelated")
                            del open_block_var[var0]
                else:
                    for d in dest_regs:
                        if d not in tainted_regs:
                            tainted_regs.add(d)
                            if d not in open_block_reg:
                                open_block_reg[d] = (ea, "mov from tainted")
                                block_start("reg", d, ea, open_block_reg[d][1])
                        obf_mark(ea, f"(taint-propagate->{d} by mov)")
                    if var0 and var0 not in tainted_vars:
                        tainted_vars.add(var0)
                        if var0 not in open_block_var:
                            open_block_var[var0] = (ea, "mov from tainted")
                            block_start("var", var0, ea, open_block_var[var0][1])
                        obf_mark(ea, f"(taint-propagate->var {var0} by mov)")
            else:
                kept = []
                for d in dest_regs:
                    if d in tainted_regs:
                        kept.append(d)
                if var0 and var0 in tainted_vars:
                    kept.append(var0)
                if kept:
                    obf_mark(ea, f"(write-nonmov keeps: {','.join(sorted(kept))})")

    # Informative block ends at function end
    # (we don't clear taints to let Pass 3 see OBF marks)
    for r in list(open_block_reg.keys()):
        block_end("reg", r, f.end_ea, "function end")
    for v in list(open_block_var.keys()):
        block_end("var", v, f.end_ea, "function end")

# ---------- PASS 3: retro-tag constants used only by OBF ----------
def pass3_const_for_obf(f):
    newly_marked = 0

    def explicit_writes_reg(ea, canon_reg):
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        if mnem in NON_WRITING_DEST:
            return False
        op0, _, _ = extract_operands_from_disasm(ea)
        dests = find_registers_in_text((op0 or "").lower())
        return canon_reg in dests

    def explicit_uses_reg_in_sources(ea, canon_reg):
        _, op1, op2 = extract_operands_from_disasm(ea)
        srcs = find_registers_in_text((op1 or "").lower()) | find_registers_in_text((op2 or "").lower())
        return canon_reg in srcs

    def implicit_use_or_write(ea, canon_reg):
        m = (idc.print_insn_mnem(ea) or "").lower()
        op0, op1, op2 = extract_operands_from_disasm(ea)
        r, w = implicit_reads_writes(m, op0, op1, op2)
        return (canon_reg in r, canon_reg in w)

    for ea in idautils.FuncItems(f.start_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        if ea in obf_eas:  # already OBFUSC
            continue

        mnem = (idc.print_insn_mnem(ea) or "").lower()
        op0, op1, _ = extract_operands_from_disasm(ea)
        op0_l, op1_l = (op0 or "").lower(), (op1 or "").lower()

        # Candidate: mov-like  reg, imm/symbol (no memory)
        if not is_mov_like(mnem) or not is_plain_register_operand(op0_l) or not is_symbol_or_const_no_mem(op1_l):
            continue

        dest_regs = find_registers_in_text(op0_l)
        if not dest_regs:
            continue
        canon = next(iter(dest_regs))  # the destination register

        # --- FAST PATH: immediate next insn is an OBFUSC use of this reg?
        if next_is_obf_use_of_reg(ea, canon, f.end_ea):
            obf_mark(ea, "(const-for-obf)")
            newly_marked += 1
            continue

        # --- FULL SCAN: linear lifetime
        saw_use = False
        only_obf_uses = True
        cur = idc.next_head(ea, f.end_ea)
        while cur not in (idc.BADADDR, None) and cur < f.end_ea:
            m = (idc.print_insn_mnem(cur) or "").lower()
            if P3_STOP_AT_CTRL_FLOW and is_control_flow_mnem(m):
                break

            cur_is_obf = (cur in obf_eas)

            # Overwrite? (lifetime end). If RMW, it also counts as a use.
            if explicit_writes_reg(cur, canon):
                if rmw_reads_dest(m):
                    saw_use = True
                    if not cur_is_obf:
                        only_obf_uses = False
                break

            # Explicit source use
            if explicit_uses_reg_in_sources(cur, canon):
                saw_use = True
                if not cur_is_obf:
                    only_obf_uses = False
                    break

            # Implicit uses/writes (e.g., imul 1-op, div/idiv, cpuid)
            imp_reads, imp_writes = implicit_use_or_write(cur, canon)
            if imp_reads:
                saw_use = True
                if not cur_is_obf:
                    only_obf_uses = False
                    break
            if imp_writes:
                break  # end of lifetime

            cur = idc.next_head(cur, f.end_ea)

        if (not P3_REQUIRE_AT_LEAST_ONE_USE or saw_use) and only_obf_uses:
            obf_mark(ea, "(const-for-obf)")
            newly_marked += 1

    return newly_marked


# ---------- PASS 2: mark JCC that skip fully-OBF fall-through ----------
def pass2_mark_jcc_over_obf(f):
    jcc_marked = 0
    for j_ea in idautils.FuncItems(f.start_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(j_ea)):
            continue
        m = (idc.print_insn_mnem(j_ea) or "").lower()
        if not is_cond_jcc(m):
            continue
        op0, _, _ = extract_operands_from_disasm(j_ea)
        tgt = resolve_branch_target(j_ea, op0)
        if tgt in (idc.BADADDR, None) or not (f.start_ea <= tgt <= f.end_ea) or tgt <= j_ea:
            continue

        cur = idc.next_head(j_ea, f.end_ea)
        if cur in (idc.BADADDR, None) or cur >= tgt:
            continue

        all_obf = True
        walk = cur
        while walk not in (idc.BADADDR, None) and walk < tgt:
            if not ida_bytes.is_code(ida_bytes.get_full_flags(walk)) or (walk not in obf_eas):
                all_obf = False
                break
            walk = idc.next_head(walk, f.end_ea)

        if all_obf and walk == tgt:
            obf_mark(j_ea, f"(jcc-skips obf-block → {op0.strip()})")
            jcc_marked += 1
    return jcc_marked

# ---------- Orchestrator ----------
def mark_obfusc_in_func(ea=None):
    global obf_eas
    obf_eas = set()

    if ea is None:
        ea = ida_kernwin.get_screen_ea()
    f = ida_funcs.get_func(ea)
    if not f:
        print(f"[!] No function at 0x{ea:X}")
        return
    fname = ida_funcs.get_func_name(f.start_ea)
    print(f"[+] Scanning function {fname} @ 0x{f.start_ea:X}-0x{f.end_ea:X}")

    # Pass 1: taint-based marking
    pass1_taint_mark(f)

    # Pass 3: constants used only in obfuscation (retro-tag, overrides END)
    n_const = pass3_const_for_obf(f)
    print(f"[+] Const-for-OBF newly marked: {n_const}")

    # Pass 2: JCC that skip fully-OBF fall-through (run after pass 3)
    n_jcc = pass2_mark_jcc_over_obf(f)
    print(f"[+] JCC-over-OBF blocks marked: {n_jcc}")

    print("[+] Done.")

if __name__ == "__main__":
    mark_obfusc_in_func()

#!/usr/bin/python3
from disasm_wrapper import *
from MatrixMod4x4 import *

MATRIX_DIM = 4

def extract_values(lines):
    values = []
    for addr, line in lines:
        if not "movabs" in line:
            continue
            # take the last token after splitting by spaces or comma
        value = line.split()[-1]
        values.append(value)
    return values

def get_args_type(lines):
    for addr, line in lines:
        if "movabs" in line:
            print(hex(addr), line)
            
def get_func_type(lines):
    count = len(lines)
    if count == 172 or count == 173:
        return 1
    elif count == 98 or count == 99:
        return 2
    elif count == 56 or count == 57:
        return 3
    return None

class FFuncWrapper:
    def __init__(self, _dll, _func, _type, _values):
        self.dll = _dll
        self.func = _func
        self.args = _values# []
        self.type = _type # int
        
    def __str__(self):
        return f"FFuncWrapper(dll={self.dll}, type={self.type}, args={self.args})"
      
class CheckFuncWrapper:
    def __init__(self, _dll, _values):
        self.dll = _dll
        self.p = int(_values[0], 16)
        self.e = int(_values[1], 16)
        self.xor = []
        self.m0 = []
        self.m1 = []
        self.m2 = []

        for i in range(16):
            self.xor.append(int(_values[2 + i], 16))
        pos = 2 + 16 
        for i in range(pos, len(_values)):
            self.m2.append(int(_values[i], 16))
        
    def __str__(self):
        xor_hex = [f"0x{v:x}" for v in self.xor]
        m0_hex = [f"0x{v:x}" for v in self.m0]
        m1_hex = [f"0x{v:x}" for v in self.m1]
        m2_hex = [f"0x{v:x}" for v in self.m2]
        return (f"CheckFuncWrapper(dll={self.dll}, "
                f"p=0x{self.p:x}, "
                f"e=0x{self.e:x}, "
                f"xor={xor_hex}, "
                f"m0={m0_hex}, "
                f"m1={m1_hex}, "
                f"m2={m2_hex})")
        #return f"CheckFuncWrapper(dll={self.dll}, p={self.p}, e={self.e}, xor={self.xor}, m2={self.m2})"
    
    def matrixConstruct(self, buf):
        return [buf[i:i+MATRIX_DIM] for i in range(0, len(buf), MATRIX_DIM)]

    def is_dexor_valid(self, xored_m):
        for i in range(MATRIX_DIM):
            for j in range(MATRIX_DIM):
                if xored_m[i] != xored_m[i + MATRIX_DIM *j]:
                    return False
        return True
                
    def dexor_m(self):
        xored_m = []
        for i in range(len(self.m1)):
            xored_m.append(self.m1[i] ^ self.xor[i])
        if self.is_dexor_valid(xored_m):
            for i in range(MATRIX_DIM):
                self.m0.append(xored_m[i])

    def solve(self):
        R = self.matrixConstruct(self.m2)
        M_root = inverse_exponentiation(R, self.e, self.p)
        #print("\n".join(mat_to_hex(M_root)))
        self.m1 = [val for row in M_root for val in row]
        self.dexor_m()

def extract_dll_and_func(lines):
    results = []
    for _, line in lines:
        if not " ; " in line:
            continue
        comment = line.split(";", 1)[1].strip()  # take everything after ;
        if "." not in comment:
            continue
        dll, func = comment.split(".dll.", 1)   # split into dll and function
        results.append((dll, func))
    return results
    
def print_all(lines):
    for addr, line in lines:
        print(hex(addr), line)
        
def dump_func(dll_name, func_name): #0000.dll
    wrapper = DisasmCLIWrapper("./disasm-cli")  # or just "disasm-cli" if on PATH
    lines = wrapper.disasm("./../resources/dlls/" + dll_name, func_name)
    ff = FFuncWrapper(dll_name, func_name, get_func_type(lines), extract_values(lines))
    print(ff)
    if ff.type == None:
        print("WARNING: %s : %d" % (func_name, len(lines)))

def dump_check(dll_name): #0000.dll
    func_name = "_Z5checkPh"
    wrapper = DisasmCLIWrapper("./disasm-cli")  # or just "disasm-cli" if on PATH
    lines = wrapper.disasm("./../resources/dlls/" + dll_name, func_name)
    #print_all(lines)
    print("### %s.%s" % (dll_name, func_name))
    funcs = extract_dll_and_func(lines)
    for dll,func in funcs:
        dump_func(dll + ".dll", func)
    values = extract_values(lines)
    cfunc = CheckFuncWrapper(dll_name, values)
    cfunc.solve()
    print(cfunc)
    m0_hex = [f"0x{v:x}" for v in cfunc.m0]
    print(f"Precalculated: {m0_hex}")

dump_check("0293.dll")
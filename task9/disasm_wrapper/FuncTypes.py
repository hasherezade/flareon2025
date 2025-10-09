#!/usr/bin/python3
import pickle
from MatrixMod4x4 import *

MATRIX_DIM = 4

class FFuncWrapper:
    def __init__(self, _dll, _func, _type, _values):
        self.dll = _dll
        self.func = _func
        self.args = _values# []
        self.type = _type # int
        
    def __str__(self):
        args_hex = [hex(a) for a in self.args]
        return f"FFuncWrapper(dll={self.dll}, type={self.type}, args={args_hex})"


class CheckFuncWrapper:
    def __init__(self, _dll, _values):
        self.dll = _dll
        self.p = int(_values[0], 16)
        self.e = int(_values[1], 16)
        self.xor = []
        self.m0 = []
        self.m1 = []
        self.m2 = []
        self.funcs_list = [] #FFuncWrapper[]

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
        # Convert each FFuncWrapper to string
        funcs_str = [str(f) for f in self.funcs_list]
        
        return (f"CheckFuncWrapper(dll={self.dll}, "
                f"p=0x{self.p:x}, "
                f"e=0x{self.e:x}, "
                f"xor={xor_hex}, "
                f"m0={m0_hex}, "
                f"m1={m1_hex}, "
                f"m2={m2_hex}),"
                f"funcs_list={funcs_str}")
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
  
###

def save_map_as_pickle(mapping: dict[str, FFuncWrapper], outfile: str) -> None:
    with open(outfile, "wb") as f:
        pickle.dump(mapping, f, protocol=pickle.HIGHEST_PROTOCOL)

def load_map_from_pickle(infile: str) -> dict[str, FFuncWrapper]:
    with open(infile, "rb") as f:
        return pickle.load(f)

###

def save_cfunc_as_pickle(cfunc: CheckFuncWrapper, pkl_file: str):
    with open(pkl_file, "wb") as f:
        pickle.dump(cfunc, f)
        
def load_cfunc_from_pickle(pkl_file: str):
    with open(pkl_file, "rb") as f:
        return pickle.load(f)
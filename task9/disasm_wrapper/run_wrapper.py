#!/usr/bin/python3
import argparse
import os
import pickle

from disasm_wrapper import *
from MatrixMod4x4 import *
from FuncTypes import *

DISASM_PATH = "./disasm-cli"
DLLS_PATH = "./../resources/dlls/"

def extract_values(lines):
    values = []
    for addr, line in lines:
        if not "movabs" in line:
            continue
            # take the last token after splitting by spaces or comma
        value = line.split()[-1]
        values.append(value)
    return values

def extract_int_values(lines):
    values = []
    for addr, line in lines:
        if not "movabs" in line:
            continue
            # take the last token after splitting by spaces or comma
        value = line.split()[-1]
        values.append(int(value,16))
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

def extract_dll_and_func(lines):
    results = []
    for _, line in lines:
        if not " ; " in line:
            continue
        comment = line.split(";", 1)[1].strip()  # take everything after ;
        if "." not in comment:
            continue
        results.append(comment.strip())
    return results
    
def print_all(lines):
    for addr, line in lines:
        print(hex(addr), line)
        
def dump_func(dll_name, func_name, funcs_list): #0000.dll
    wrapper = DisasmCLIWrapper(DISASM_PATH)  # or just "disasm-cli" if on PATH
    lines = wrapper.disasm(DLLS_PATH + dll_name, func_name)
    ff = FFuncWrapper(dll_name, func_name, get_func_type(lines), extract_int_values(lines))
    funcs_list.append(ff)
    print(ff)
    if ff.type == None:
        print("WARNING: %s : %d" % (func_name, len(lines)))

def dump_check(dll_name, fmapping, out_dir): #0000.dll
    func_name = "_Z5checkPh"
    wrapper = DisasmCLIWrapper(DISASM_PATH)  # or just "disasm-cli" if on PATH
    lines = wrapper.disasm(DLLS_PATH + dll_name, func_name)
    #print_all(lines)
    #print("### %s.%s" % (dll_name, func_name))

    values = extract_values(lines)
    cfunc = CheckFuncWrapper(dll_name, values)
    cfunc.solve()
    
    raw_func_list = extract_dll_and_func(lines)
    for dll_func in raw_func_list:
        if not dll_func in fmapping.keys():
            print(f"Function not found: {dll_func})")
            dll, func = dll_func.split(".dll.", 1)
            dump_func(dll + ".dll", func, cfunc.funcs_list)
            continue
        rec = fmapping[dll_func]
        #print(rec)
        cfunc.funcs_list.append(rec)
    #    dump_func(dll + ".dll", func, cfunc.funcs_list)

    out_file = out_dir + "//" + dll_name + ".resolved.txt"
    pkl_file = out_dir + "//" + dll_name + ".pkl"
    save_cfunc_as_pickle(cfunc, pkl_file)
    
    with open(out_file, "w", encoding="utf-8") as f:
        m0_hex = [f"0x{v:x}" for v in cfunc.m0]
        f.write(f"Precalculated: {m0_hex}\n")
        #f.write(f"{cfunc}\n")
        for func in cfunc.funcs_list:
            f.write(f"{func}\n")
    print(f"{dll_name} -> {m0_hex}")


def main():
    parser = argparse.ArgumentParser(description="Run disasm wrapper to extract arguments")
    parser.add_argument('--fmap', dest="fmap", required=True,
                        help="Pickle with func args mapping")
    parser.add_argument('--inpath', dest="inpath", required=True,
                        help="Path to input file or directory")
    parser.add_argument('--outpath', dest="outpath", required=True,
                        help="Path to the output directory")
    args = parser.parse_args()
    
    print("Load pickled functions mapping")
    #mapping: dict[str, FFuncWrapper] = {}
    mapping = load_map_from_pickle(args.fmap)
    print(f"Map loaded, size: {len(mapping)}")

    if os.path.isdir(args.inpath):
        # Process all files in directory
        for root, dirs, files in os.walk(args.inpath):
            DLLS_PATH = root
            for fname in files:
                if not fname.endswith(".dll"):
                    continue
                filepath = os.path.join(root, fname)
                dump_check(fname, mapping, args.outpath)
    else:
        # Single file
        dump_check(args.inpath)

if __name__ == "__main__":
    main()

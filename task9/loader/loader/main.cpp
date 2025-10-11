#include <windows.h>
#include <iostream>
#include <peconv.h> // include libPeConv header

#include "util.h"
#include "verif.h"

#define CHUNK_SIZE 32


BYTE g_EmptyBuf[0x9C40] = { 0 };
BYTE* g_BufPtr = g_VerifBuf;

size_t g_PESize = 0;
BYTE *g_PEBuf = NULL;


//---
// Functions prototypes:

BOOL __fastcall check(WORD* buf);

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved);  // reserved

//---


int run_pe_entrypoint(BYTE* my_pe, BYTE* buff, DWORD reason)
{
    //calculate the Entry Point of the manually loaded module
    DWORD ep_rva = peconv::get_entry_point_rva(my_pe);
    if (!ep_rva) {
        return -2;
    }
    ULONG_PTR ep_va = ep_rva + (ULONG_PTR)my_pe;
    //assuming that the payload is an EXE file (not DLL) this will be the simplest prototype of the main:
    auto _dll_main = reinterpret_cast<decltype(&DllMain)>(ep_va);
    if (!_dll_main) {
        std::cout << "Can't retrieve the Start function!\n";
        return (-1);
    }
    return _dll_main((HMODULE)buff, reason, 0);
}


BYTE* load_main_dll(const LPCSTR pe_path)
{
    // manually load the PE file using libPeConv:
    size_t v_size = 0;
    //if the PE is dropped on the disk, you can load it from the file:
    BYTE* my_pe = (BYTE*)LoadLibraryA(pe_path);
    if (!my_pe) {
        return NULL;
    } 
    // set the loaded PE in the global variables:
    g_PESize = v_size;
    g_PEBuf = my_pe;

    return g_PEBuf;
}

int make_check(WORD* bufw)
{
    FARPROC proc = peconv::get_exported_func(g_PEBuf, "_Z5checkPh");
    if (!proc) {
        std::cout << "Can't find the check function!\n";
        return (-1);
    }
    printf("Buffer before:\n");
    hexdump((BYTE*)bufw, 32);
    printf("\n");

    auto _check = reinterpret_cast<decltype(&check)>(proc);
    printf("Running...\n");
    if (_check((WORD*)bufw)) {
        printf("Check passed!\n");
    }
    else {
        printf("Check failed!\n");
    }

    printf("Buffer after:\n");
    hexdump((BYTE*)bufw, 32);
    printf("\n");
    return 0;
}


size_t register_modules()
{
    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return false;
    }
    size_t count = 0;
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(hSnap, &me)) {
        int index = 0;
        do {
            if (!isNumericDLLW(std::wstring(me.szExePath))) {
                continue;
            }
            count++;
#ifdef _DEBUG
            //wprintf(L"%02d: %s  Base=0x%p  Size=%u\n", index++, me.szExePath, me.modBaseAddr, me.modBaseSize);
#endif
            if (!run_pe_entrypoint(me.modBaseAddr, g_BufPtr, DLL_PROCESS_ATTACH)) {
                return NULL;
            }
        } while (Module32NextW(hSnap, &me));
    }
    else {
        printf("Module32First failed: %lu\n", GetLastError());
    }

    CloseHandle(hSnap);
    return count;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        std::cout << "Usage: <input_file> <dll_to_chek> <mode*>\n";
        std::cout << "*mode: 0 - use 0 buffer; 1 - use verification buffer\n";
        return 0;
    }
    char* input_file = argv[1];
    char* dll_file = argv[2];
    char mode = argv[3][0];
    bool isNull = (mode == '0') ? true : false;

    if (isNull) {
        std::cout << "Using Empty Buffer\n";
        g_BufPtr = g_EmptyBuf;
    }
    else {
        std::cout << "Using Verification Buffer\n";
        g_BufPtr = g_VerifBuf;
    }

    size_t input_size = 0;
    BYTE* input = read_from_file(input_file, CHUNK_SIZE, input_size);
    if (!input_size) {
        std::cerr << "Failed to read file: " << input_file << "\n";
        return 0;
    }
    std::cout << "Chunk file loaded\n";

    if (!load_main_dll(dll_file)) {
        std::cout << "[-] Loading the PE: "<< dll_file << " failed!\n";
        return -1;
    }
    register_modules();
    make_check((WORD*)input);
    return 0;
}

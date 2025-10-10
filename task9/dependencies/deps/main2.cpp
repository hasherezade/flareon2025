#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <peconv.h> // include libPeConv header

#include "util.h"

HMODULE g_mainMod = NULL;


size_t list_loaded_modules(std::wofstream &ous)
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
    bool isFirst = true;

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
            if (!isFirst) {
                ous <<  ",";
            }
            std::wstring dllName = get_base_filename(me.szExePath);
            ous << dllName;
            isFirst = false;
        } while (Module32NextW(hSnap, &me));
    }
    else {
        printf("Module32First failed: %lu\n", GetLastError());
    }
    CloseHandle(hSnap);
    ous << "\n" << std::endl;
    return count;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        std::cout << "Usage: <listing_dir> <out_file>\n";
        return 0;
    }
    std::string input_dir = argv[1];
    std::string out_file = argv[2];

    std::wofstream oFile(out_file);  // open file for reading
    if (!oFile.is_open()) {
        std::cerr << "Error: could not open file.\n";
        return 0;
    }

    const size_t chunks_max = 10000;

    for (WORD id = 0; id < chunks_max; id++) {
        std::stringstream ss;
        ss << input_dir << "\\"
            << std::setw(4) << std::setfill('0') << id
            << ".dll";

        //std::cout << "Chunk id: " << std::dec << id << std::endl;
        std::string input_file = ss.str();
        g_mainMod = LoadLibraryA(input_file.c_str());
        if (!g_mainMod) {
            std::cout << "Failed to load: " << input_file <<"\n";
            continue;
        }
        list_loaded_modules(oFile);
        FreeLibrary(g_mainMod);
    }
    oFile.close();

    return 0;
}

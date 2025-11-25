#include <windows.h>
#include <iostream>
#include <string>

#define FUNC_OFFSET 0x81760

__int64 __fastcall get_translated (void*, __int64);

int main(int argc, char* argv[])
{
    const char* dll_name = "FlareAuthenticator.dll";
    HMODULE mod = LoadLibraryA(dll_name);
    if (!mod) {
        std::cout << "Failed to load the DLL: " << dll_name << std::endl;
        return 1;
    }

    ULONG_PTR func_ptr = (ULONG_PTR)mod + FUNC_OFFSET;
    auto _get_translated = reinterpret_cast<decltype(&get_translated)>(func_ptr);
    for (size_t dig = 0; dig < 10; dig++) {
        std::cout << "#Digit: " << dig << std::endl;
        std::cout << "[" << std::endl;
        for (size_t pos = 1; pos <= 25; pos++) {
            char inp = dig + '0';
            WORD arg = inp | (0x100 * pos);
            uint64_t val0 = _get_translated(nullptr, pos);
            uint64_t val1 = _get_translated(nullptr, arg);
            std::cout << std::hex << val0 * val1;
            if (pos != 25) std::cout << ", ";
            if ((pos % 5) == 0) std::cout << "\n";
        }
        std::cout << "]" << std::endl;
    }
    
    return 0;
}
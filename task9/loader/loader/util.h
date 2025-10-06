#pragma once
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#define PAGE_SIZE 0x1000

void hexdump(BYTE* buf, size_t buf_size)
{
    for (size_t i = 0; i < buf_size; i++) {
        if ((i % 32) == 0) printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}


bool isNumericDLLW(const std::wstring& fullPath)
{
    std::wstring dllName = fullPath;
    size_t pos1 = fullPath.find_last_of(L"\\/");
    if (pos1 != std::string::npos)
        dllName = fullPath.substr(pos1 + 1); // skip the slash
    size_t pos2 = dllName.find_last_of(L".");
    dllName = dllName.substr(0, pos2); // skip the slash
    for (size_t i = 0; i < dllName.length(); ++i) {
        if (dllName[i] < '0' || dllName[i] > '9') {
            return false;
        }
    }
    return true;
}



BYTE* read_from_file(IN LPCTSTR in_path, IN size_t max_size, IN OUT size_t& read_size)
{
    HANDLE file = CreateFile(in_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Cannot open the file for reading!" << std::endl;
#endif
        return nullptr;
    }
    DWORD r_size = GetFileSize(file, 0) + 1;
    if (max_size < r_size) {
        r_size = max_size;
    }
    BYTE* buffer = (BYTE*)::calloc(r_size, 1);
    if (!buffer) {
        return nullptr;
    }
    DWORD out_size = 0;
    if (!ReadFile(file, buffer, r_size, &out_size, nullptr)) {
        ::free(buffer);
        buffer = nullptr;
        read_size = 0;
    }
    else {
        read_size = r_size;
    }
    CloseHandle(file);
    return buffer;
}


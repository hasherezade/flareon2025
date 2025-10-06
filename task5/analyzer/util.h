#pragma once
#include <windows.h>
#include <iostream>
#include <string>

#include <vector>
#include <fstream>

bool create_new_process(IN const char* cmdline, OUT PROCESS_INFORMATION& pi, DWORD timeout_ms = 1000)
{
    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessA(
        NULL,
        (LPSTR)cmdline,
        NULL, //lpProcessAttributes
        NULL, //lpThreadAttributes
        FALSE, //bInheritHandles
        CREATE_NEW_CONSOLE, //dwCreationFlags
        NULL, //lpEnvironment 
        NULL, //lpCurrentDirectory
        &si, //lpStartupInfo
        &pi //lpProcessInformation
    ))
    {
        printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
        return false;
    }
    return true;
}

BYTE* read_from_file(IN LPCTSTR in_path, IN OUT size_t& read_size)
{
    HANDLE file = CreateFile(in_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Cannot open the file for reading!" << std::endl;
#endif
        return nullptr;
    }
    DWORD r_size = GetFileSize(file, 0);
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

bool write_to_file(IN LPCTSTR in_path, IN BYTE* buf, IN size_t& buf_size)
{
    HANDLE file = CreateFile(in_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    bool is_ok = false;
    DWORD out_size = 0;
    if (WriteFile(file, buf, buf_size, &out_size, nullptr)) {
        if (out_size == buf_size) {
            is_ok = true;
        }
    }
    CloseHandle(file);
    return is_ok;
}

///----

inline bool manual_map(BYTE* image, size_t imgSize, BYTE* rawPE, size_t rawSize, PIMAGE_NT_HEADERS nt)
{
    if (imgSize < nt->OptionalHeader.SizeOfHeaders || rawSize < nt->OptionalHeader.SizeOfHeaders) {
        return false;
    }
    ::memcpy(image, rawPE, nt->OptionalHeader.SizeOfHeaders);
    // map sections
    PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        BYTE* vPtr = (BYTE*)(image)+section[i].VirtualAddress;
        BYTE* rPtr = (BYTE*)(rawPE)+section[i].PointerToRawData;
        const size_t secSize = section[i].SizeOfRawData;
        ::memcpy(vPtr, rPtr, secSize);
    }
    return true;
}

size_t loadPE(std::vector<char>& buffer, std::vector<char>& mapped)
{
    BYTE* raw = (BYTE*)&buffer[0];
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(raw);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    size_t imgSize = nt->OptionalHeader.SizeOfImage;
    mapped.resize(imgSize);
    BYTE* image = (BYTE*)&mapped[0];
    if (!manual_map(image, mapped.size(), raw, buffer.size(), nt)) {
        return 0;
    }
    return imgSize;
}

BYTE* load_image(const std::string imagePath, std::vector<char> &mapped)
{
    std::ifstream file(imagePath, std::ios::binary | std::ios::in);
    if (!file.is_open()) return nullptr;

    file.seekg(0, std::ios::end);

    const std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(fileSize);
    
    file.read(&buffer[0], fileSize);
    file.close();

    if (!loadPE(buffer, mapped)) return nullptr;

    BYTE* mem = (BYTE*)&mapped[0];
    return mem;
}
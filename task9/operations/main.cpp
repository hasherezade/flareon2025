#include <windows.h>
#include <iostream>
#include <string>

#include "util.h"
#include "verif.h"

#include "ffuncs.h"
#include "inverse.h"

#define CHUNK_SIZE 32

BYTE* g_Buffer1 = g_VerifBuf;

void hexdump_print(BYTE *buf, const char *label, size_t size = CHUNK_SIZE)
{
    printf("%s:\n", label);
    hexdump(buf, size);
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "Usage: <input_file>\n";
        return 0;
    }
    char* input_file = argv[1];
    size_t input_size = 0;
    BYTE *input = read_from_file(input_file, input_size);
    if (!input_size) {
        std::cerr << "Failed to read file: " << input_file << "\n";
        return 0;
    }
    std::cout << "Chunk file loaded\n";

    WORD* bufw = (WORD*)input;

    hexdump_print((BYTE*)bufw, "Buffer before");

    printf("Transform1...\n");
    uint64_t kQargs_1[4] = { 0x22F130E6FAFE934BLL, 0x777FD23EB0B83B25LL, 0xF605C9124BC28C77LL, 0x59263089104BC46BLL };
    f_type1(input, kQargs_1);
    hexdump_print((BYTE*)bufw, "Buffer after");


    uint64_t kQargs_2[4] = { 0x2759439DC26540DFLL, 0x90D15DB9CF959B34LL, 0xD5CA662B8655DC90LL, 0x198E45265B4D53D1LL };
    f_type1(input, kQargs_2);

    hexdump_print((BYTE*)bufw, "Buffer after");

    uint64_t v5[33];
    v5[0] = 0x48D4B4B214423E5ALL;
    v5[1] = 0xC32B82DA6624C1E3LL;
    v5[2] = 0xABEEBC9246E4E87BLL;
    v5[3] = 0x90213DF4DB612840LL;
    v5[4] = 0x13D2C4E92A0F1516LL;
    v5[5] = 0x3AA9274973D7688DLL;
    v5[6] = 0x4FF5019836A6CF22LL;
    v5[7] = 0x5862F24A0069C952LL;
    v5[8] = 0x178AD0838C347C8BLL;
    v5[9] = 0x93C032C8875C20DLL;
    v5[10] = 0x71564B774E729E08LL;
    v5[11] = 0x7ACB35530BA7381BLL;
    v5[12] = 0x60D8540A5CD6EB44LL;
    v5[13] = 0x11A5F34CFDCA6339LL;
    v5[14] = 0x6F899A6CB732E76DLL;
    v5[15] = 0x10EFB8AFA82904F6LL;
    v5[16] = 0x9F70F79C125076FFLL;
    v5[17] = 0xE3165F9E2A34DFBLL;
    v5[18] = 0x2F1806E1DF99AD91LL;
    v5[19] = 0x29B7993C5B3BB20LL;
    v5[20] = 0xD5AE55F8DC6B1CEALL;
    v5[21] = 0x1959CEFC3B9447C7LL;
    v5[22] = 0x1F301E25C6DEC06ELL;
    v5[23] = 0x7F3395A1861D6A26LL;
    v5[24] = 0x435774BFE5B0D9B5LL;
    v5[25] = 0xECBE84FA5EBA7E5FLL;
    v5[26] = 0x5D80C87864A2B9A0LL;
    v5[27] = 0x6707BDD37D23512DLL;
    v5[28] = 0x59D2ECC0CFEB15BLL;
    v5[29] = 0x37F1B6AAEDF0AC87LL;
    v5[30] = 0x97411AA4E6D18E85LL;
    v5[31] = 0x8FDD96E04581CD3FLL;

    f_type2(input, v5);
    hexdump_print(input, "Buffer after");

    uint64_t v6[5];
    v6[0] = 0x1E07141A020D0F00LL;
    v6[1] = 0x6041B171D19010CLL;
    v6[2] = 0x1F100E0913111503LL;
    v6[3] = 0xA12050816181C0BLL;
    f_type3(input, v6);
    hexdump_print(input, "Buffer after");
    
    return 0;
}
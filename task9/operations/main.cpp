#include <windows.h>
#include <iostream>
#include <string>

#include "util.h"
#include "verif.h"

#include "ffuncs.h"
#include "inverse.h"
#ifdef TEST_MATRIX
#include "matrix_exp.h"
#endif //TEST_MATRIX

#include "parse_records.h"

#define CHUNK_SIZE 32

unsigned char g_NullBuf[40080] = { 0 };

BYTE* g_Buffer1 = g_NullBuf;// g_VerifBuf;


void hexdump_print(BYTE *buf, const char *label, size_t size = CHUNK_SIZE)
{
    printf("%s:\n", label);
    hexdump(buf, size);
    printf("\n");
}

void test_0000_dll(BYTE *input)
{
    WORD* bufw = (WORD*)input;
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
}
#ifdef TEST_MATRIX
void matrix_tests(BYTE* input)
{
    std::cout << "Extracted QWORDs:\n";

    uint64_t* qbuf = (uint64_t*)input;
    for (size_t i = 0; i < 4; i++) {
        std::cout << "[" << i << "] = " << std::hex << qbuf[i] << std::endl;
    }

    uint64_t base_matrix[] = {
        0xce9f85f8f81d13ff,
        0xec9d2f85565d15f6,
        0x7b5537223badaa1b,
        0xc62d73650ec319a5,

        0xc3543bfb857ed549,
        0x16a2b87f21558fea,
        0x12034078017cacaf,
        0xb6927d3fbdb449dd,

        0xbcf1b1e55f84ed9b,
        0x3d3000ea560ecbc4,
        0x23f312a8a19ebd32,
        0x9cbf0a850e0a5177,

        0x770e28a6163f095,
        0xacd30a8362f21c4c,
        0x5813d448a6407267,
        0xbe6aec23dde852b3
    };

    for (size_t i = 0; i < _countof(base_matrix); i++) {
        std::cout << std::hex << base_matrix[i] << " XOR " << qbuf[i % 4] << " = " << (base_matrix[i] ^ qbuf[i % 4]) << "\n";
        base_matrix[i] ^= qbuf[i % 4];
    }
    // Example matrix M and exponent e
    uint64_t M[MATRIX_SIZE][MATRIX_SIZE] = { 0 };
    matrixConstruct(base_matrix, M);
    matrixPrint(M, "M");

    static uint64_t R[MATRIX_SIZE][MATRIX_SIZE];

    const uint64_t p = 0xcfa801af34882c6dULL;
    const uint64_t e = 0x0aaf4d006d2bd73fULL;

    matrixExpotentiate(M, e, p, R);
    std::cout << "\n";
    std::cout << "Result of matrix exponentiation: " << std::endl;
    matrixPrint(R, "result");
    matrixPrint(M, "M");
}
#endif// TEST_MATRIX

void apply_functions(BYTE buf[CHUNK_SIZE], std::vector<FFuncWrapperC*> &wrappers)
{
    for (auto itr = wrappers.begin(); itr != wrappers.end(); ++itr) {
        const FFuncWrapperC* wr = *itr;
        std::cout << wr->dll << " : " << wr->type << std::endl;
        if (wr->type == 1) {
            f_type1(buf, wr->args.data());
        }
        else if (wr->type == 2) {
            f_type2(buf, wr->args.data());
        }
        else if (wr->type == 3) {
            f_type3(buf, wr->args.data());
        }
        hexdump(buf, CHUNK_SIZE);
    }
    std::cout << std::endl;
}

void apply_functions_inv(BYTE buf[CHUNK_SIZE], std::vector<FFuncWrapperC*>& wrappers)
{
    for (auto itr = wrappers.rbegin(); itr != wrappers.rend(); ++itr) {
        const FFuncWrapperC* wr = *itr;
        if (wr->type == 1) {
            f_type1_inv(buf, wr->args.data());
        }
        else if (wr->type == 2) {
            f_type2_inv(buf, wr->args.data());
        }
        else if (wr->type == 3) {
            f_type3_inv(buf, wr->args.data());
        }
    }
    std::cout << "After Inv:";
    hexdump(buf, CHUNK_SIZE);
    std::cout << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "Usage: <listing_file>\n";
        return 0;
    }
    char* input_file = argv[1];
    size_t input_size = 0;
    std::vector<FFuncWrapperC*> wrappers;
    Precalculated* prec = nullptr;
    read_resolved(input_file, &prec, wrappers);

    BYTE buf[CHUNK_SIZE] = { 0 };
    if (prec) {
        for (size_t i = 0; i < MATRIX_SIZE; i++) {
            ::memcpy(&buf[i * sizeof(uint64_t)], &prec->values[i], sizeof(uint64_t));
        }
    }
    apply_functions_inv(buf, wrappers);
    std::string outFile = get_base_filename(input_file) + "_chunk.bin";
    if (write_to_file(outFile.c_str(), buf, CHUNK_SIZE)) {
        std::cout << "Chunk saved to: " << outFile << "\n";
    }
    return 0;
}

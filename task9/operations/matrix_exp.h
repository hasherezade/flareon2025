#pragma once
#include <cstdint>
#include <cstring>
#include <iostream>

#define MATRIX_SIZE 4


void matrixPrint(uint64_t M[MATRIX_SIZE][MATRIX_SIZE], const char* label)
{
    std::cout << "\nMatrix ";
    if (label) std::cout << label;
    std::cout << "  \n";
    for (int i = 0; i < MATRIX_SIZE; ++i) {
        for (int j = 0; j < MATRIX_SIZE; ++j) {
            std::cout << M[i][j] << " ";
        }
        std::cout << "\n";
    }
    std::cout << std::endl;
}

// Function to construct 4x4 matrix from a 1D array
void matrixConstruct(uint64_t base_matrix[], uint64_t M[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; ++i) {
        for (int j = 0; j < MATRIX_SIZE; ++j) {
            M[i][j] = base_matrix[i * MATRIX_SIZE + j];
        }
    }
}
// ----- overflow-free helpers -----
static inline uint64_t addmod(uint64_t a, uint64_t b, uint64_t mod) {
    // assumes a,b < mod
    return (a >= mod - b) ? (a - (mod - b)) : (a + b);
}

static inline uint64_t doublemod(uint64_t a, uint64_t mod) {
    // compute (2*a) % mod without overflow
    return (a >= mod - a) ? (a - (mod - a)) : (a + a);
}

// (a * b) % mod without __uint128_t
static uint64_t mulmod(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t r = 0;
    a %= mod; b %= mod;
    while (b) {
        if (b & 1) r = addmod(r, a, mod);
        b >>= 1;
        if (b) a = doublemod(a, mod);
    }
    return r;
}

// C = (A * B) % mod
static void matrixMuliplyModulo(const uint64_t A[MATRIX_SIZE][MATRIX_SIZE],
    const uint64_t B[MATRIX_SIZE][MATRIX_SIZE],
    uint64_t mod,
    uint64_t C[MATRIX_SIZE][MATRIX_SIZE])
{
    for (size_t i = 0; i < MATRIX_SIZE; ++i) {
        for (size_t j = 0; j < MATRIX_SIZE; ++j) {
            uint64_t sum = 0;
            for (size_t k = 0; k < MATRIX_SIZE; ++k) {
                sum = addmod(sum, mulmod(A[i][k], B[k][j], mod), mod);
            }
            C[i][j] = sum;
        }
    }
}

static void matrixCopy(uint64_t D[MATRIX_SIZE][MATRIX_SIZE],
    const uint64_t S[MATRIX_SIZE][MATRIX_SIZE])
{
    for (size_t i = 0; i < MATRIX_SIZE; ++i)
        for (size_t j = 0; j < MATRIX_SIZE; ++j)
            D[i][j] = S[i][j];
}

static void matrixMakeIdentity(uint64_t I[MATRIX_SIZE][MATRIX_SIZE], uint64_t mod)
{
    for (size_t i = 0; i < MATRIX_SIZE; ++i)
        for (size_t j = 0; j < MATRIX_SIZE; ++j)
            I[i][j] = (i == j) ? (uint64_t)(1 % mod) : 0;
}

void matrixExpotentiate(const uint64_t M_in[MATRIX_SIZE][MATRIX_SIZE],
    uint64_t e,
    uint64_t p,
    uint64_t Result[MATRIX_SIZE][MATRIX_SIZE])
{
    uint64_t Base[MATRIX_SIZE][MATRIX_SIZE];
    uint64_t Tmp[MATRIX_SIZE][MATRIX_SIZE];

    for (size_t i = 0; i < MATRIX_SIZE; ++i)
        for (size_t j = 0; j < MATRIX_SIZE; ++j)
            Base[i][j] = M_in[i][j] % p;

    matrixMakeIdentity(Result, p);

    for (unsigned bit = 0; bit < 64; ++bit) {
        if ((e >> bit) & 1ULL) {
            matrixMuliplyModulo(Result, Base, p, Tmp);
            matrixCopy(Result, Tmp);
        }
        matrixMuliplyModulo(Base, Base, p, Tmp);
        matrixCopy(Base, Tmp);
    }
}
